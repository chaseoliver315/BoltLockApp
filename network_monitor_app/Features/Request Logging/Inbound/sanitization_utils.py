def mask_ip(ip_address):
    if ':' in ip_address:
        # IPv6 address masking
        parts = ip_address.split(':')
        if len(parts) >= 2:
            parts[-1] = '0000'
            parts[-2] = '0000'
            return ':'.join(parts)
        else:
            return ip_address
    else:
        # IPv4 address masking
        parts = ip_address.split('.')
        if len(parts) == 4:
            parts[-1] = '0'
            return '.'.join(parts)
        else:
            return ip_address

def sanitize_dns_name(dns_name):
    if dns_name:
        parts = dns_name.split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])  # Keep only the domain and TLD
        else:
            return dns_name
    else:
        return 'N/A'
