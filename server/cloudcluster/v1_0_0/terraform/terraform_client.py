import json
import logging
import os
import pathlib
import re
import tempfile

from ..services import run_shell

logger = logging.getLogger(__name__)

FILE_BASE_DIR = str(pathlib.Path(__file__).parent.absolute().parent)

TF_DIR = FILE_BASE_DIR + '/terraform/'

class TerraformClient:
    '''Terraform client for terraform_CLI library'''

    tfstate = {}
    tfvars = {}
    tf_filepath = ''
    code = ''

    def apply(self, user_id, environment_id, environment_name):
        '''Creates cluster, before using set needed providers and vars, if tfstate is set it will use it'''
        if not isinstance(self.tfstate, dict):
            raise AttributeError('tfstate is not a dictionary')

        with tempfile.TemporaryDirectory(dir=TF_DIR) as workdir:
            self.__write_code_to_temp_dir(workdir)

            self.__init(workdir, user_id=user_id, environment_id=environment_id, environment_name=environment_name)

            if self.tfstate != {}:
                self.__write_tfstate_to_temp_dir(workdir)
            self.__apply(workdir, user_id=user_id, environment_id=environment_id, environment_name=environment_name)

    def get_used_resources(self, user_id, cluster_id):
        if not isinstance(self.tfstate, dict):
            raise AttributeError('tfstate is not a dictionary')

        with tempfile.TemporaryDirectory(dir=TF_DIR) as workdir:
            self.__write_code_to_temp_dir(workdir)

            self.__init(workdir, user_id=user_id)

            cmd = ['terraform', 'plan', '-out=plan.out', '-no-color']

            for var in self.tfvars:
                cmd.append('-var')
                cmd.append(var + '=' + str(self.tfvars[var]))

            log_data = {'user_id': user_id}
            run_shell.run_shell_with_subprocess_popen(cmd, workdir=workdir, return_stdout=True, log_data=log_data)

            cmd = ['terraform', 'show', '-json', 'plan.out', '-no-color']

            log_data = {'user_id': user_id}
            output = run_shell.run_shell_with_subprocess_popen(cmd, workdir=workdir, return_stdout=True, log_data=log_data)

            return output['stdout']

    def plan(self, user_id):
        '''Plan cluster, before using set needed providers and vars'''
        if not isinstance(self.tfstate, dict):
            raise AttributeError('tfstate is not a dictionary')

        with tempfile.TemporaryDirectory(dir=TF_DIR) as workdir:
            self.__write_code_to_temp_dir(workdir)

            self.__init(workdir, user_id=user_id)

            cmd = ['terraform', 'plan', '-out=plan.out', '-no-color']

            for var in self.tfvars:
                cmd.append('-var')
                cmd.append(var + '=' + str(self.tfvars[var]))

            log_data = {'user_id': user_id}
            run_shell.run_shell_with_subprocess_popen(cmd, log_output=False, workdir=workdir, return_stdout=True, log_data=log_data)

            cmd = ['terraform', 'show', '-json', 'plan.out', '-no-color']

            log_data = {'user_id': user_id}
            output = run_shell.run_shell_with_subprocess_popen(cmd, log_output=False, workdir=workdir, return_stdout=True, log_data=log_data)

            return json.loads(output['stdout'][0])

    def get_plan(self, user_id):
        '''Plan cluster, before using set needed providers and vars'''
        if not isinstance(self.tfstate, dict):
            raise AttributeError('tfstate is not a dictionary')

        with tempfile.TemporaryDirectory(dir=TF_DIR) as workdir:
            self.__write_code_to_temp_dir(workdir)

            self.__init(workdir, user_id=user_id)

            if self.tfstate != {}:
                self.__write_tfstate_to_temp_dir(workdir)

            cmd = ['terraform', 'plan', '-out=plan.out', '-no-color', '-state=./terraform.tfstate']

            for var in self.tfvars:
                cmd.append('-var')
                cmd.append(var + '=' + str(self.tfvars[var]))

            log_data = {'user_id': user_id}
            output = run_shell.run_shell_with_subprocess_popen(cmd, log_output=False, workdir=workdir, return_stdout=True, log_data=log_data)

            cmd = ['terraform', 'show', '-json', 'plan.out', '-no-color']

            log_data = {'user_id': user_id}
            output = run_shell.run_shell_with_subprocess_popen(cmd, log_output=False, workdir=workdir, return_stdout=True, log_data=log_data)

            return json.loads(output['stdout'][0])

    def destroy(self, user_id, environment_id, environment_name):
        '''Destroys cluster, tfstate needs to be set'''

        if not isinstance(self.tfstate, dict):
            raise Exception('tfstate is not a dictionary')

        if self.tfstate == {}:
            raise Exception('tfstate is empty')

        with tempfile.TemporaryDirectory(dir=TF_DIR) as workdir:
            self.__write_code_and_tfstate_to_temp_dir(workdir)

            self.__init(workdir, user_id=user_id, environment_id=environment_id, environment_name=environment_name)

            tfstate_filepath = workdir + '/terraform.tfstate'

            cmd = ["terraform", "destroy", "-auto-approve", "-refresh=true", "-state", './terraform.tfstate', '-no-color']

            for var in self.tfvars:
                cmd.append('-var')
                cmd.append(var + '=' + str(self.tfvars[var]))

            state_file_path = workdir + '/terraform.tfstate'

            log_data = {'user_id': user_id, 'environment_id': environment_id, 'environment_name': environment_name}

            try:
                run_shell.run_shell_with_subprocess_popen(
                    cmd,
                    workdir=workdir,
                    log_data=log_data
                )
            except Exception as e:
                if os.path.isfile(state_file_path):
                    with open(state_file_path, 'r') as tfstate_file:
                        self.tfstate = json.loads(tfstate_file.read())
                raise e

        if os.path.isfile(tfstate_filepath):
            with open(tfstate_filepath, 'r') as tfstate_file:
                self.tfstate = json.loads(tfstate_file.read())

    def __apply(self, workdir, user_id, environment_id='', environment_name='', return_stdout=False):
        cmd = ['terraform',
               'apply',
               '-no-color',
               '-auto-approve',
               '-state=./terraform.tfstate']

        for var in self.tfvars:
            cmd.append('-var')
            cmd.append(var + '=' + str(self.tfvars[var]))

        tfstate_filepath = workdir + '/terraform.tfstate'

        output = ""

        log_data = {'user_id': user_id}

        if environment_id:
            log_data['environment_id'] = environment_id
        if environment_name:
            log_data['environment_name'] = environment_name

        try:
            if return_stdout:
                output = run_shell.run_shell_with_subprocess_popen(
                    cmd,
                    workdir=workdir,
                    return_stdout=return_stdout,
                    log_data=log_data
                )['stdout']

            else:
                run_shell.run_shell_with_subprocess_popen(
                    cmd,
                    workdir=workdir,
                    return_stdout=return_stdout,
                    log_data=log_data
                )
        except Exception as e:
            if os.path.isfile(tfstate_filepath):
                with open(tfstate_filepath, 'r') as tfstate_file:
                    self.tfstate = json.loads(tfstate_file.read())
            # if 'The specified instanceType or zone is not available or not authorized.' in str(e) and 'alicloud' in str(e):
            #     raise Exception('Please refresh Alicloud provider options.\nGo to "Cloud Profile" settings of your profile and click on "Refresh provider options" in Alicloud Cloud tab.')
            # else:

            print("Terraform process output: ", str(e))
            error_msg = ''
            error_instance_type = ''

            error_msg_split = str(e).split('\n')

            for line in error_msg_split:
                if re.search('.*Machine type with name \'.*\' does not exist in zone.*', line):
                    error_instance_type = line.split('Machine type with name \'')[1].split('\' does not exist in zone')[0]
                if 'on terraform.tf line ' not in line and ': resource "' not in line:
                    if 'Error: ' in line:
                        line = line.replace('Error:', '')
                    error_msg += line + '\n'

            if error_instance_type == '':
                raise Exception(error_msg)
            else:
                exception = {
                    'error_msg': error_msg,
                    'error_instance_type': error_instance_type
                }
                raise Exception(json.dumps(exception))

        if os.path.isfile(tfstate_filepath):
            with open(tfstate_filepath, 'r') as tfstate_file:
                self.tfstate = json.loads(tfstate_file.read())
        else:
            raise Exception('tfstate file does not exist')

        return output

    def __init(self, workdir, user_id='', environment_id='', environment_name=''):
        log_data = {'user_id': user_id}

        if environment_id:
            log_data['environment_id'] = environment_id
        if environment_name:
            log_data['environment_name'] = environment_name

        run_shell.run_shell_with_subprocess_popen(['terraform', 'init', '-no-color'], workdir=workdir, return_stdout=True, log_data=log_data)

    def __write_code_to_temp_dir(self, tf_tempdir):
    
        tf_file_path = tf_tempdir + '/terraform.tf'

        with open(tf_file_path, 'a') as tf_file:
            tf_file.write(self.code)

    def __write_tfstate_to_temp_dir(self, tf_tempdir):
        tfstate_file_path = tf_tempdir + '/terraform.tfstate'

        with open(tfstate_file_path, 'a') as tfstate_file:
            tfstate_file.write(json.dumps(self.tfstate))

    def __write_code_and_tfstate_to_temp_dir(self, tf_tempdir):
        self.__write_code_to_temp_dir(tf_tempdir)
        self.__write_tfstate_to_temp_dir(tf_tempdir)
