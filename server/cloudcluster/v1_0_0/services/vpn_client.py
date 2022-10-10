import tempfile

from cloudcluster.v1_0_0.services.run_shell import run_shell_with_subprocess_popen

def connect(wireguard_config, cluster_id):
    cluster_id = str(cluster_id).replace('-', '')[:10]
    # create tmp directory
    with tempfile.TemporaryDirectory() as wg_config_path:
        # write config to tmp directory
        with open(wg_config_path + '/wg-%s.conf' % cluster_id, 'w') as wg_config_file:
            wg_config_file.write(wireguard_config)

        command = 'wg-quick down %s/wg-%s.conf' % (wg_config_path, cluster_id)
        run_shell_with_subprocess_popen(command, workdir='./', shell=True, raise_on_error=False)

        command = 'wg-quick up %s/wg-%s.conf' % (wg_config_path, cluster_id)
        run_shell_with_subprocess_popen(command, workdir='./', shell=True)

def disconnect(wireguard_config, cluster_id):
    cluster_id = str(cluster_id).replace('-', '')[:10]
    # create tmp directory
    with tempfile.TemporaryDirectory() as wg_config_path:
        # write config to tmp directory
        with open(wg_config_path + '/wg-%s.conf' % cluster_id, 'w') as wg_config_file:
            wg_config_file.write(wireguard_config)

        command = 'wg-quick down %s/wg-%s.conf' % (wg_config_path, cluster_id)
        run_shell_with_subprocess_popen(command, workdir='./', shell=True, raise_on_error=False)