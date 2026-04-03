from scapy.arch.windows import get_windows_if_list
ifaces = get_windows_if_list()
print(f'Found {len(ifaces)} interfaces:\n')
for i in ifaces:
    name    = i.get('name', '')
    desc    = i.get('description', '')
    netname = i.get('network_name', '')
    ips     = i.get('ips', [])
    print(f'  network_name : {netname}')
    print(f'  description  : {desc}')
    print(f'  ips          : {ips}')
    print(f'  name(guid)   : {name[:60]}')
    print()
