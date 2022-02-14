#!/usr/bin/env python3

import subprocess
import sys
import time


def extract_flow_from_logline(line: str) -> str:
    """Extract flow from debug log.

    The string is also massaged into something that can be compared to the
    output from ovs-ofctl.

    Example input:
    '2022-02-11T08:25:46.572Z|2419719|ofctrl|DBG|ofctrl_add_flow flow: '
    'cookie=33d9a01c, table_id=20, priority=100, '
    'reg0=0xac10005b,reg15=0x3,metadata=0x144, '
    'actions=set_field:fa:16:3e:5b:d3:19->eth_dst,resubmit(,21)'
    
    Example output:
    'cookie=0x33d9a01c,table=20,priority=100,reg0=0xac10005b,reg15=0x3,'
    'metadata=0x144,actions=set_field:fa:16:3e:5b:d3:19->eth_dst,resubmit(,21)'
    """
    flow_out = line.rstrip().split('flow:')[1]
    for replacement in (
            (' ', '',),
            ('table_id=', 'table='),
            ('cookie=', 'cookie=0x')):
        flow_out = flow_out.replace(replacement[0], replacement[1])
    return flow_out


def extract_flow_from_ofctl(line: str) -> str:
    """Extract flow from ovs-ofctl output.

    Removes any variable runtime data which is not suitable for further
    comparison.

    Example input:
    'cookie=0x33d9a01c, duration=2962.254s, table=20, n_packets=0, n_bytes=0, '
    'idle_age=2962, priority=100,reg0=0xac10005b,reg15=0x3,metadata=0x144 '
    'actions=set_field:fa:16:3e:5b:d3:19->eth_dst,resubmit(,21)'

    Example output:
    'cookie=0x33d9a01c,table=20,priority=100,reg0=0xac10005b,reg15=0x3,'
    'metadata=0x144,actions=set_field:fa:16:3e:5b:d3:19->eth_dst,'
    'resubmit(,21)'
    """
    kv_pairs = [
        kv_pair
        for kv_pair in line.rstrip().replace(' ', ',').split(',')
        if kv_pair and ('duration' not in kv_pair
            and 'n_packets' not in kv_pair
            and 'n_bytes' not in kv_pair
            and 'idle_age' not in kv_pair)
    ]
    return ','.join(kv_pairs)


def check_ofctl(expected_flows: set):
    cp = subprocess.run(
        ('ovs-ofctl', '-O', 'OpenFlow15', 'dump-flows', 'br-int', 'table=20'),
        capture_output=True, check=True, universal_newlines=True)

    ofctl_flows = set()
    for line in cp.stdout.splitlines():
        ofctl_flows.add(extract_flow_from_ofctl(line))
    missing_flows = expected_flows.difference(ofctl_flows)
    if missing_flows:
        print('MISSING FLOWS: {}'.format(missing_flows))
    else:
        print('All flows installed!')


with open('/var/log/ovn/ovn-controller.log') as logf:
    # Seek to EOF
    logf.seek(0, 2)
    expected_flows = set()
    while True:
        line = logf.readline()
        if not line or not line.endswith('\n'):
            time.sleep(0.025)
            print('expected_flows: {}'.format(len(expected_flows)))
            continue
        if 'ofctrl_put not needed' in line and len(expected_flows):
            check_ofctl(expected_flows)
        if 'ofctrl_add_flow' in line and 'table_id=20' in line:
            expected_flows.add(extract_flow_from_logline(line))
        if 'removing installed flow' in line and 'table_id=20' in line:
            expected_flows.remove(extract_flow_from_logline(line))

