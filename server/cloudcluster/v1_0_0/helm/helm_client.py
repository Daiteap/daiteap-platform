import json
import pathlib
import tempfile

from ..services import run_shell
import os
import ast

FILE_BASE_DIR = str(pathlib.Path(__file__).parent.absolute().parent)

class HelmClient:
    '''Helm client for helm binary'''

    Helm_DIR = FILE_BASE_DIR + '/helm/charts/'
    name = ''
    chart_name = ''
    namespace = ''
    kubeconfig_path = ''

    def install(self, values_path):
        '''Installs helm chart.'''

        chart_path = self.Helm_DIR + self.chart_name

        cmd = ['helm', 'install', '-f']
        cmd.append(values_path)
        cmd.append(self.name)
        cmd.append(chart_path)
        cmd.append('--namespace')
        cmd.append(self.namespace)
        cmd.append('--create-namespace')
        cmd.append('--kubeconfig')
        cmd.append(self.kubeconfig_path)

        output = run_shell.run_shell_with_subprocess_popen(cmd, workdir='./', return_stdout=True)

        return output

    def uninstall(self, delete_pvc=False, pvc_name=None):
        '''Uninstalls helm deployment.'''

        cmd = ['helm', 'uninstall']
        cmd.append('--namespace')
        cmd.append(self.namespace)
        cmd.append('--kubeconfig')
        cmd.append(self.kubeconfig_path)
        cmd.append(self.name)

        output = run_shell.run_shell_with_subprocess_popen(cmd, workdir='./', return_stdout=True)

        if delete_pvc and pvc_name:
            cmd = ['kubectl', 'delete', '--namespace', self.namespace, '--kubeconfig', self.kubeconfig_path, 'pvc', pvc_name]
            run_shell.run_shell_with_subprocess_popen(cmd, workdir='./', return_stdout=True)

        return
