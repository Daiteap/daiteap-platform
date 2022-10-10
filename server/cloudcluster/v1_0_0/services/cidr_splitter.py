import math
import ipaddress

def power_log(x):
    return 2**(math.ceil(math.log(x, 2)))

def split_cidr(original_cidr, count):
    pair = ipaddress.ip_network(original_cidr, strict=False)
    subnet_diff = int(math.sqrt(power_log(float(count))))
    subnets = list(pair.subnets(prefixlen_diff=subnet_diff))

    return [str(subnet) for subnet in subnets]