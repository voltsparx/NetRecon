import ipaddress

def parse_ports(port_str):
    ports = set()
    for part in port_str.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    return sorted(ports)

def expand_targets(target):
    """Expand CIDR into list of hosts"""
    try:
        if "/" in target:
            return [str(ip) for ip in ipaddress.ip_network(target, strict=False).hosts()]
        return [target]
    except:
        return [target]
