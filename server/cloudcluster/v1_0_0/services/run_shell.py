import json
import subprocess
import logging
import re
import sys

logger = logging.getLogger(__name__)


# Returns only return code

def run_shell_with_subprocess_call(cmd, workdir='./'):
    x = subprocess.call(cmd, cwd=workdir)
    if x != 0:
        raise Exception('Run shell command returned status different from 0')

# Returns output and return code


def run_shell_with_subprocess_popen(cmd, log_output=True, raise_on_error=True, workdir='./', return_stdout=False, log_data={}, shell=False):
    result = {'return_code': '', 'output': ''}
    stdout = []
    stderr = []

    process = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=workdir, shell=shell
    )

    while True:
        output_stdout = process.stdout.readline()
        if output_stdout == b'' and process.poll() is not None:
            break
        if output_stdout != '':
            line = output_stdout.decode("utf-8")
            if return_stdout:
                stdout.append(line)
            if log_output:
                log_msg = {'level': 'DEBUG'}
                if 'environment_name' in log_data:
                    log_msg['environment_name'] = log_data['environment_name']
                if 'environment_id' in log_data:
                    log_msg['environment_id'] = log_data['environment_id']
                if 'user_id' in log_data:
                    log_msg['user_id'] = log_data['user_id']
                logger.debug(line, extra=log_msg)

    while True:
        output_stderr = process.stderr.readline()
        if output_stderr == b'' and process.poll() is not None:
            break
        if output_stderr != '':
            line = output_stderr.decode("utf-8")
            stderr.append(line)
            if log_output:
                log_msg = {'level': 'ERROR'}
                if 'environment_name' in log_data:
                    log_msg['environment_name'] = log_data['environment_name']
                if 'environment_id' in log_data:
                    log_msg['environment_id'] = log_data['environment_id']
                if 'user_id' in log_data:
                    log_msg['user_id'] = log_data['user_id']
                logger.error(line, extra=log_msg)

    rc = process.poll()
    result['return_code'] = rc
    if return_stdout:
        result['stdout'] = stdout
    result['stderr'] = stderr

    if rc!=0 and raise_on_error:
        errorMsg = ''
        for line in stderr:
            errorMsg += line + '\n'

        raise AttributeError(errorMsg)
    return result
