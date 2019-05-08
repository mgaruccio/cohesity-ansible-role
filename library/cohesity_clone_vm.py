
#!/usr/bin/python
# Copyright (c) 2018 Cohesity Inc
# Apache License Version 2.0

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import open_url, urllib_error

try:
    # => When unit testing, we need to look in the correct location however, when run via ansible,
    # => the expectation is that the modules will live under ansible.
    from module_utils.storage.cohesity.cohesity_auth import get__cohesity_auth__token
    from module_utils.storage.cohesity.cohesity_utilities import cohesity_common_argument_spec, raise__cohesity_exception__handler
    from module_utils.storage.cohesity.cohesity_hints import get__prot_source_id__by_endpoint, \
        get__protection_jobs__by_environment, get__vmware_snapshot_information__by_vmname, \
        get__prot_source_root_id__by_environment, get__restore_job__by_type
except:
    from ansible.module_utils.storage.cohesity.cohesity_auth import get__cohesity_auth__token
    from ansible.module_utils.storage.cohesity.cohesity_utilities import cohesity_common_argument_spec, raise__cohesity_exception__handler
    from ansible.module_utils.storage.cohesity.cohesity_hints import get__prot_source_id__by_endpoint, \
        get__protection_jobs__by_environment, get__vmware_snapshot_information__by_vmname, \
        get__prot_source_root_id__by_environment, get__restore_job__by_type

ANSIBLE_METADATA = {
    'metadata_version': '1.0',
    'supported_by': 'community',
    'status': ['preview']
}

DOCUMENTATION = '''
module: cohesity_clone
short_description: Clone Data from Cohesity Protection Jobs
description:
    - This module will create clones from Cohesity Clusters for the selected Protection Jobs.
version_added: '2.6.5'
author:
  - Jeremy Goodrum (github.com/exospheredata)
  - Cohesity, Inc

extends_documentation_fragment:
    - cohesity
requirements: []

'''

EXAMPLES = '''
'''

RETURN = '''
'''

class ParameterViolation(Exception):
    pass

def check__protection_clone__exists(module, self):
    # => TODO: Fix this query
    payload = self.copy()
    payload['restore_type'] = "kCloneVMs"

    restore_tasks = get__restore_job__by_type(module, payload)

    if restore_tasks:
        task_list = [task for task in restore_tasks if task['name'] == self['task_name'] ]
        for task in task_list:
            return True
    return False

def get_clone_task_by_id(module, self):
    payload = self.copy()
    payload['restore_type'] = "kCloneVMs"

    restore_tasks = get__restore_job__by_type(module, payload)
    if restore_tasks:
        for task in restore_tasks:
            if task['name'] == self['task_name']:
                return task
    return False

# => Return the Protection Job information based on the Environment and Job Name
def get__job_information__for_clone(module, self):
    # => Gather the Protection Jobs by Environment to allow us
    # => to verify that the Job exists and feed that into the
    # => snapshot collection.
    job_output = get__protection_jobs__by_environment(module, self)

    # => There will be a lot of potential jobs.  Return only the
    # => one that matches our job_name
    job_data = [job for job in job_output if job['name'] == self['job_name']]

    if not job_data:
        failure=dict(
            changed=False,
            job_name = self['job_name'],
            environment=self['environment'],
            msg="Failed to find chosen Job name for the selected Environment Type."
        )
        module.fail_json(**failure)
    else:
        # => Since we are filtering out any job that matches our name
        # => we will need to properly just grab the first element as
        # => it is returned as an array.
        return job_data[0]

def get__snapshot_information__for_vmname(module, self):
    clone_objects = []
    # => Return the Protection Job information based on the Environment and Job Name
    job_data = get__job_information__for_clone(module, self)

    # => Create a clone object for each Virtual Machine
    for vmname in self['vm_names']:
      # => Build the Clone Dictionary Object
      clone_details = dict(
          jobRunId="",
          jobUid=dict(
            clusterId=job_data['uid']['clusterId'],
            clusterIncarnationId=job_data['uid']['clusterIncarnationId'],
            id=job_data['uid']['id']
          ),
          startedTimeUsecs=""
      )
      self['restore_obj'] = clone_details.copy()
      self['restore_obj']['vmname'] = vmname
      output = get__vmware_snapshot_information__by_vmname(module, self)

      if not output or output['totalCount'] == 0:
        failure=dict(
            changed=False,
            job_name = self['job_name'],
            vmname=vmname,
            environment=self['environment'],
            msg="Failed to find a snapshot for the VM in the chosen Job name."
        )
        module.fail_json(**failure)

      # => TODO: Add support for selecting a previous backup.
      # => For now, let's just grab the most recent snapshot.
      success = False
      for snapshot_info in output['objectSnapshotInfo']:
            if snapshot_info['objectName'] == vmname:
                snapshot_detail = snapshot_info['versions'][0]
                clone_details['protectionSourceId'] = snapshot_info['snapshottedSource']['id']
                clone_details['jobRunId'] = snapshot_detail['jobRunId']
                clone_details['startedTimeUsecs'] = snapshot_detail['startedTimeUsecs']
                success = True
      if not success:
            module.fail_json(msg="No Snapshot Found for the VM: " + vmname)

      clone_objects.append(clone_details)

    return clone_objects

# => Perform the Clone of a Virtual Machine to the selected ProtectionSource Target
def start_clone__vms(module, self):
    payload = self.copy()
    payload.pop('vm_names', None)
    return start_clone(module, "/irisservices/api/v1/public/restore/clone", payload)

def start_clone(module, uri, self):
    server = module.params.get('cluster')
    validate_certs = module.params.get('validate_certs')
    token = self['token']
    try:
        uri = "https://" + server + uri
        headers = {"Accept": "application/json",
                   "Authorization": "Bearer " + token}
        payload = self.copy()

        # => Remove the Authorization Token from the Payload
        payload.pop('token', None)

        data = json.dumps(payload)

        response = open_url(url=uri, data=data, headers=headers,
                            validate_certs=validate_certs)

        response = json.loads(response.read())

        # => Remove the Job name as it will be duplicated back to our process.
        response.pop('name')

        return response
    except urllib_error.URLError as e:
        # => Capture and report any error messages.
        raise__cohesity_exception__handler(e.read(), module)
    except Exception as error:
        raise__cohesity_exception__handler(error, module)

def wait_clone_complete(module, self):
    server = module.params.get('cluster')
    validate_certs = module.params.get('validate_certs')
    token = self['token']
    wait_counter = int(module.params.get('wait_minutes')) * 2

    wait_results = dict(
        changed=False,
        status="Failed",
        attempts=list(),
        error=list()
    )
    try:
        import time

        uri = "https://" + server + "/irisservices/api/v1/public/restore/tasks/" + str(self['id'])
        headers = {"Accept": "application/json", "Authorization": "Bearer " + token}
        attempts = 0
        # => Wait for the restore based on a predetermined number of minutes with checks every 30 seconds.
        while attempts < wait_counter:

            response = open_url(url=uri, headers=headers, validate_certs=validate_certs)
            response = json.loads(response.read())

            # => If the status is Finished then break out and check for errors.
            if response['status'] == "kFinished":
                wait_results['changed'] = True
                wait_results['status'] = "Finished"
                break
            # => Otherwise, pause and try again.
            else:
                attempt_tracker = dict(
                    attempt=attempts,
                    status=response['status']
                )
                wait_results['attempts'].append(attempt_tracker)
                attempts += 1
                time.sleep(30)

                if attempts >= wait_counter:
                    wait_results['changed'] = False
                    wait_results['status'] = response['status']
                    wait_results['error'] = "Failed to wait for the clone to complete after " + module.params.get('wait_minutes') + " minutes."
                    if wait_results['status'] == "kInProgress":
                        wait_results['error'] = wait_results['error'] + " The clone is still in progress and the timeout might be too short."
        # => If the error key exists in the response, then something happened during the clone
        if 'error' in response:
            wait_results['status'] = "Failed"
            wait_results['changed'] = False
            if self['environment'] == "VMware":
                wait_results['error'] = [elem['error']['message'] for elem in response['restoreObjectState']]
            else:
                wait_results['error'] = response['error']['message']

        output = self.copy()
        output.update(**wait_results)

        return output
    except urllib_error.URLError as e:
        # => Capture and report any error messages.
        raise__cohesity_exception__handler(e.read(), module)
    except Exception as error:
        raise__cohesity_exception__handler(error, module)


# => Destroy an existing Cohesity Clone.
def destroy_clone(module, self):
    server = module.params.get('cluster')
    validate_certs = module.params.get('validate_certs')
    token=get__cohesity_auth__token(module)
    try:
        uri = "https://" + server + \
            "/irisservices/api/v1/destroyclone/" + str(self['id'])
        headers = {"Accept": "application/json",
                   "Authorization": "Bearer " + token}

        response = open_url(url=uri, method='POST', headers=headers,
                            validate_certs=validate_certs)

        return response
    except urllib_error.URLError as e:
        # => Capture and report any error messages.
        raise__cohesity_exception__handler(e.read(), module)
    except Exception as error:
        raise__cohesity_exception__handler(error, module)

def main():
    # => Load the default arguments including those specific to the Cohesity Protection Jobs.
    argument_spec = cohesity_common_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type='str', required=True),
            state=dict(choices=['present', 'absent',
                                'started', 'stopped'], default='present'),
            job_name=dict(type='str'),
            view_name=dict(type='str', required=True),
            backup_id=dict(type='str'),
            backup_timestamp=dict(type='str'),
            # => Currently, the only supported environments types are list in the choices
            # => For future enhancements, the below list should be consulted.
            # => 'SQL', 'View', 'Puppeteer', 'Pure', 'Netapp', 'HyperV', 'Acropolis', 'Azure'
            environment=dict(
                choices=['VMware'],
                default='VMware'
            ),
            vm_names=dict(type='list'),
            wait_for_job=dict(type='bool', default=True),
            vm_name_prefix=dict(type='str', default=""),
            power_state=dict(type='bool', default=True),
            network_connected=dict(type='bool', default=False),
            wait_minutes=dict(type='str', default=5)

        )
    )

    # => Create a new module object
    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True)
    results = dict(
        changed=False,
        msg="Attempting to manage Cohesity Clone",
        state=module.params.get('state')
    )

    job_details = dict(
        token=get__cohesity_auth__token(module),
        job_name=module.params.get('job_name'),
        environment=module.params.get('environment')
    )

    if module.params.get('backup_id'):
        job_details['jobRunId'] = module.params.get('backup_id')

    if module.params.get('backup_timestamp'):
        job_details['backup_timestamp'] = module.params.get('backup_timestamp')

    clone_task_details = dict(
        token=get__cohesity_auth__token(module),
        task_name=module.params.get('name')
    )
    clone_exists = check__protection_clone__exists(module, clone_task_details)

    if module.check_mode:
        check_mode_results = dict(
            changed=False,
            msg="Check Mode: Cohesity Clone is not currently present",
            id=""
        )
        if module.params.get('state') == "present":
            if clone_exists:
                check_mode_results[
                    'msg'] = "Check Mode: Cohesity Clone is currently present. No changes"
            else:
                check_mode_results[
                    'msg'] = "Check Mode: Cohesity Clone is not currently present. This action would create the Cohesity Clone."
                check_mode_results['id'] = clone_exists
        else:
            if clone_exists:
                check_mode_results[
                    'msg'] = "Check Mode: Cohesity Clone is currently present. This action would tear down the Cohesity Clone."
                check_mode_results['id'] = clone_exists
            else:
                check_mode_results[
                    'msg'] = "Check Mode: Cohesity Clone is not currently present. No changes."
        module.exit_json(**check_mode_results)

    elif module.params.get('state') == "present":

        if clone_exists:
            results = dict(
                changed=False,
                msg="The Clone with specified name is already present",
                id=clone_exists,
                name=module.params.get('name')
            )
        else:
            # check__mandatory__params(module)
            environment = module.params.get('environment')
            response =[]

            if environment == "VMware":
                job_details['vm_names']  = module.params.get('vm_names')
                source_object_info = get__snapshot_information__for_vmname(module, job_details)

                clone_data=dict(
                    name=module.params.get('name'),
                    vm_names=module.params.get('vm_names'),
                    objects=source_object_info,
                    token=job_details['token'],
                    type="kCloneVMs",
                    targetViewName=module.params.get('view_name'),
                    vmwareParameters=dict(
                        prefix=module.params.get('vm_name_prefix'),
                        poweredOn=module.params.get('power_state'),
                        disableNetwork=module.params.get('network_connected'),
                        resourcePoolId=80
                    )
                )
                job_start = start_clone__vms(module, clone_data)
                job_start['vm_names']=job_details['vm_names']
                response.append(job_start)

            else:
                # => This error should never happen based on the set assigned to the parameter.
                # => However, in case, we should raise an appropriate error.
                module.fail_json(msg="Invalid Environment Type selected: {0}".format(
                    module.params.get('environment')), changed=False)

            task = dict(
                changed=False
            )
            for jobCheck in response:
                clone_data['id'] = jobCheck['id']
                clone_data['environment'] = environment
                if module.params.get('wait_for_job'):
                    task = wait_clone_complete(module, clone_data)
                    jobCheck['status'] = task['status']

            results = dict(
                changed=True,
                msg="Cohesity Clone created",
                name=module.params.get('name'),
                restore_jobs=response
            )

            if not task['changed'] and module.params.get('wait_for_job'):
                # => If the task failed to complete, then the key 'changed' will be False and
                # => we need to fail the module.
                results['changed'] = False
                results.pop('msg')
                errorCode = ""
                # => Set the errorCode to match the task['error'] if the key exists
                if 'error' in task:
                    errorCode = task['error']
                module.fail_json(msg="Cohesity Clone failed to complete",error=errorCode, **results)

    elif module.params.get('state') == "absent":

        if clone_exists:
            clone_task = get_clone_task_by_id(module, clone_task_details)
            response = destroy_clone(module, clone_task)

            results = dict(
                changed=True,
                msg="Cohesity Clone destroyed",
                id=clone_task['id'],
                task_name=module.params.get('name')
            )
        else:
            results = dict(
                changed=False,
                msg="Cohesity Clone does not exist",
                task_name=module.params.get('name')
            )
    else:
        # => This error should never happen based on the set assigned to the parameter.
        # => However, in case, we should raise an appropriate error.
        module.fail_json(msg="Invalid State selected: {}".format(
            module.params.get('state')), changed=False)

    module.exit_json(**results)


if __name__ == '__main__':
    main()
