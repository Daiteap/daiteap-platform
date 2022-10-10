import tempfile
import sys

from cloudcluster.v1_0_0.services.run_shell import run_shell_with_subprocess_call, run_shell_with_subprocess_popen

aws = True
azure = True
google = True

def __write_code_to_temp_dir(tf_tempdir):
    code = __generate_tf_code()

    tf_file_path = tf_tempdir + '/terraform.tf'

    with open(tf_file_path, 'a') as tf_file:
        tf_file.write(code)

def init(pathToConfiguration):
    run_shell_with_subprocess_call(['terraform', 'init', pathToConfiguration + '/'])

def __generate_tf_code():
    code = ''
    providers_count = __count_providers()

    if providers_count == 0:
        raise EnvironmentError('No providers selected')

    if aws:
        with open(TF_DIR + '../../../environment_providers/aws/terraform/config.tf', 'r') as tf_file:
            code += tf_file.read()

    if azure:
        with open(TF_DIR + '../../../environment_providers/azure/terraform/config.tf', 'r') as tf_file:
            code += tf_file.read()

    if google:
        with open(TF_DIR + '../../../environment_providers/google/terraform/config.tf', 'r') as tf_file:
            code += tf_file.read()

    if aws and providers_count > 0:
        with open(TF_DIR + '../../../environment_providers/terraform/vpn/vpn_aws.tf', 'r') as tf_file:
            code += tf_file.read()

    if azure and providers_count > 0:
        with open(TF_DIR + '../../../environment_providers/terraform/vpn/vpn_azure.tf', 'r') as tf_file:
            code += tf_file.read()

    if google and aws:
        with open(TF_DIR + '../../../environment_providers/terraform/vpn/vpn_aws_google.tf', 'r') as tf_file:
            code += tf_file.read()

    if google and azure:
        with open(TF_DIR + '../../../environment_providers/terraform/vpn/vpn_google_azure.tf', 'r') as tf_file:
            code += tf_file.read()

    if aws and azure:
        with open(TF_DIR + '../../../environment_providers/terraform/vpn/vpn_aws_azure.tf', 'r') as tf_file:
            code += tf_file.read()
    return code

def __count_providers():
    providers_count = 0

    if aws:
        providers_count += 1

    if azure:
        providers_count += 1

    if google:
        providers_count += 1

    return providers_count

TF_DIR = './cloudcluster/v1_0_0/terraform/'

with tempfile.TemporaryDirectory(dir=TF_DIR) as tf_tempdir:
    __write_code_to_temp_dir(tf_tempdir)

    run_shell_with_subprocess_popen(['terraform', 'init'], workdir=tf_tempdir, return_stdout=True)

    cmd = ['terraform', 'validate']

    try:
        run_shell_with_subprocess_popen(cmd, workdir=tf_tempdir, return_stdout=True)
    except:
        sys.exit(-1)