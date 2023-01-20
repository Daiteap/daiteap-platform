import base64
import subprocess

def encrypt(username, password):
    command = ["openssl", "passwd", "-stdin", "-apr1"]
    p = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    p.stdin.write(password.encode("utf-8"))
    p.stdin.close()
    p.wait()

    return base64.b64encode(username + ":" + p.stdout.read())