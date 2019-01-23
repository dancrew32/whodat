import collections
import ipwhois
import pprint
import re
import socket
import sys
import warnings

warnings.filterwarnings(action='ignore')

MOST_COMMON = 20
ALLOWED_COUNTRIES = ('US',)


def scan(path):
    with open(path, 'r') as f:
        data = f.read()
    IP_MATCH = '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'
    return re.findall(IP_MATCH, data, flags=re.MULTILINE)


def lookup(ip):
    try:
        socket.gethostbyaddr(ip)
    except socket.herror:
        return None
    obj = ipwhois.IPWhois(ip)
    return obj.lookup_whois()


def scan_ips(ips):
    c = collections.Counter(ips)
    top = c.most_common(MOST_COMMON)

    for ip, freq in top:
        print(f'{ip} has {freq} entries.')
        data = lookup(ip)
        if not data:
            continue
        code = data['asn_country_code']
        if code in ALLOWED_COUNTRIES:
            continue
        print(f'# Ban: {code}')
        print(f'iptables -A INPUT -s {ip} -j DROP')


if __name__ == '__main__':
    ips = scan(sys.argv[1])
    scan_ips(ips)
