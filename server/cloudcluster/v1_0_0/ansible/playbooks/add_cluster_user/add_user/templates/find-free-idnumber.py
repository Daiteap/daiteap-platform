for x in range(2002, 6000):
    if str(x) not in open('/var/tmp/ansible/ldap_idNumbers').read():
        break