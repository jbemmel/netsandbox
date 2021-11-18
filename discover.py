#!/usr/bin/env python3

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

GNMI_PORT=57400

def gnmi_scan(ip_range,port=GNMI_PORT):
    """
    @param ip_range a range of IP (ex : 172.20.20.1/30).
    """
    try:
        syn = IP(dst=ip_range) / TCP(dport=port, flags="S")
    except socket.gaierror:
        raise ValueError('Hostname {} could not be resolved.'.format(ip))

    ans, unans = sr(syn, inter=0.1, timeout=0.1, retry=0)
    result = []

    for sent, received in ans:
        if received[TCP].flags == "SA":
            result.append(received[IP].src)

    return result

# gnmic -a 172.20.20.2 -u admin -p admin -e json_ietf --skip-verify get --path /system/lldp
def ListLLDPNeighbors(node):
    """
    Uses a gNMI connection to list LLDP neighbors for the given node

    Note the hardcoded admin/admin credentials
    """
    from pygnmi.client import gNMIclient

    with gNMIclient(target=(node,GNMI_PORT),
                    username="admin",password="admin",
                    insecure=False, debug=False) as c:
        path = "/system/lldp" # /interface/neighbor
        data = c.get(path=[path],encoding='json_ietf')
        print( data )
        res = data['notification'][0]['update'][0]['val']

        def shorten(i):
            return i.replace("ethernet-","e").replace('/','-')

        release = re.match( "^SRLinux-v(\d+[.]\d+[.]\d+).*$", res['system-description'] )
        ver = release.groups()[0] if release else 'latest'
        return [ (res['system-name'], ver, shorten(intf['name']), n['system-name'], shorten(n['port-id']))
                 for intf in res['interface']
                 for n in [ intf['neighbor'][0] ] ]

def CreateTopology(neighbors):
    from jinja2 import Template
    nodes = set( [ (lldp[0][0],lldp[0][1]) for lldp in neighbors.values() ] )
    TOPOLOGY = """name: Auto-discovered sandbox
topology:
  kinds:
    srl:
      image: ghcr.io/nokia/srlinux:latest # Overriden at node level
  nodes:
  {% for n,v in nodes %}
    {{ n }}:
      kind: srl
      image: ghcr.io/nokia/srlinux:{{ v }}
      startup-config: todo-download.json
  {% endfor %}
  links:
  {% for n in neighbors -%}
  {% for (n1,v,i1,n2,i2) in neighbors[n] -%}
  {% if n1<n2 and i1!="mgmt0" -%}
  - endpoints: [ "{{ n1 }}:{{ i1 }}", "{{ n2 }}:{{ i2 }}" ]
  {% endif -%}
  {% endfor -%}
  {% endfor %}
"""

    Template(TOPOLOGY).stream(nodes=nodes,neighbors=neighbors).dump('sandbox.yml')

if __name__ == "__main__":
    nodes = gnmi_scan(ip_range="172.20.20.1/30")
    print( nodes )

    neighbors = {}
    for n in nodes:
        neighbors[n] = ListLLDPNeighbors(n)
    print( neighbors )

    CreateTopology(neighbors)
