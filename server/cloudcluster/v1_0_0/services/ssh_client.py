import time
import traceback
import paramiko
import logging

logger = logging.getLogger(__name__)

def transfer_file(node_address, local_path, remote_path):
    user = 'clouduser'
    ssh = paramiko.SSHClient()
    key = paramiko.RSAKey.from_private_key_file('/var/.ssh/id_rsa')
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Connect to the node
    ssh_retry_attempts = 10
    for ssh_retry_attempt in range(ssh_retry_attempts):
        try:
            ssh.connect(node_address, username=user, pkey=key)
            logger.debug('*** Connected to %s' % node_address)
            break
        except Exception as e:
            if ssh_retry_attempt == ssh_retry_attempts - 1:
                logger.error('Failed to connect to node {}'.format(node_address))
                raise e
            else:
                logger.warning('Failed to connect to node {}. Retrying...'.format(node_address))
                time.sleep(10)
                continue

    retry_attempts = 10

    for retry_attempt in range(retry_attempts):
        try:
            sftp = ssh.open_sftp()
            sftp.put(local_path, remote_path)
            sftp.close()
            logger.debug('File transfer successful')
            break
        except Exception as e:
            if retry_attempt == retry_attempts - 1:
                logger.error('File transfer failed')
                raise e
            else:
                logger.warning('File transfer failed. Retrying...')
                time.sleep(10)
                continue

def exec_commands_on_node(node_address, commands, return_output=False, skip_errors=False, gateway_address='', command_retry_attempts=10):
    ssh_retry_attempts = 10
    user = 'clouduser'
    key = paramiko.RSAKey.from_private_key_file('/var/.ssh/id_rsa')

    if gateway_address != '':
        gateway = paramiko.SSHClient()
        gateway.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Connect to the gateway
        for ssh_retry_attempt in range(ssh_retry_attempts):
            try:
                gateway.connect(gateway_address, username=user, pkey=key)
                logger.debug('*** Connected to %s' % gateway_address)
                break
            except Exception as e:
                if ssh_retry_attempt == ssh_retry_attempts - 1:
                    logger.error('Failed to connect to node {}'.format(gateway_address))
                    raise e
                else:
                    logger.warning('Failed to connect to node {}. Retrying...'.format(gateway_address))
                    time.sleep(10)
                    continue

        gateway_transport = gateway.get_transport()
        dest_addr = (node_address, 22)
        local_addr = (gateway_address, 22)
        # Connect to the gateway
        for ssh_retry_attempt in range(ssh_retry_attempts):
            try:
                gateway_channel = gateway_transport.open_channel("direct-tcpip", dest_addr, local_addr)
                logger.debug('*** Connected to %s' % gateway_address)
                break
            except Exception as e:
                if ssh_retry_attempt == ssh_retry_attempts - 1:
                    logger.error('Failed to connect to node {}'.format(gateway_address))
                    raise e
                else:
                    logger.warning('Failed to connect to node {}. Retrying...'.format(gateway_address))
                    time.sleep(10)
                    continue

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    output = []

    # Connect to the node
    for ssh_retry_attempt in range(ssh_retry_attempts):
        try:
            if gateway_address != '':
                ssh.connect(node_address, username=user, pkey=key, sock=gateway_channel)
            else:
                ssh.connect(node_address, username=user, pkey=key)
            logger.debug('*** Connected to %s' % node_address)
            break
        except Exception as e:
            if ssh_retry_attempt == ssh_retry_attempts - 1:
                logger.error('Failed to connect to node {}'.format(node_address))
                raise e
            else:
                logger.warning('Failed to connect to node {}. Retrying...'.format(node_address))
                time.sleep(10)
                continue

    # Execute commands
    for command in commands:
        for retry in range(command_retry_attempts):

            logger.debug('Executing command: ' + command)
            stdin, stdout, stderr = ssh.exec_command(command)

            exit_status = stdout.channel.recv_exit_status()

            if exit_status != 0 and not skip_errors:
                stderr_text = stderr.read().decode('utf-8')
                logger.debug('Command execution failed. Error: ' + stderr_text)
                if retry < command_retry_attempts - 1:
                    time.sleep(10)
                    logger.debug('Retrying({}) command execution on node {}'.format(retry, node_address))
                    continue
                else:
                    logger.debug('*** Closed connection to %s' % node_address)
                    ssh.close()
                    error_msg = 'Command execution on node {} failed'.format(node_address)
                    logger.error(str(traceback.format_exc()) + '\n' + error_msg)
                    raise Exception('Command execution on node {} failed'.format(node_address) + '\n' + 'Command: ' + command + '\n' + 'Error: ' + stderr_text)
            else:
                stdout_text = stdout.read().decode('utf-8')
                if return_output:
                    output.append(stdout_text)
                logger.debug('Command execution successful')
                logger.debug('Command output: ' + stdout_text)
                break

    # Close connection
    logger.debug('*** Closed connection to %s' % node_address)
    ssh.close()
    return output