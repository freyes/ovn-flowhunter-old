#!/usr/bin/env python3

import io
import subprocess
import sys
import time


VLOG_DESTINATION = {
    'console': 0,
    'syslog': 1,
    'file': 2
}


class MissingFlows(Exception):
    pass


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


def extract_flow_from_ovs_logline(line:str):
    """Extract flow from ovs-vswitchd.log.

    Example input:
    '2022-02-14T21:50:28.287Z|00356|vconn|DBG|unix#3: received: OFPT_FLOW_MOD '
    '(OF1.3) (xid=0x36c): ADD table:20 priority=100,reg0=0xc0a815dd,reg15=0x3,'
    'metadata=0x2 cookie:0x507e59f3 '
    'actions=set_field:fa:16:3e:fb:18:f3->eth_dst,resubmit(,21)'

    Example output:
    'cookie=0x507e59f3,table=20,priority=100,reg0=0xc0a815dd,reg15=0x3,'
    'metadata=0x2,actions=set_field:fa:16:3e:fb:18:f3->eth_dst,resubmit(,21)'
    """
    flow_line = line.split(' ADD ', maxsplit=1)[1]
    tokens = flow_line.split(' ')
    table = tokens[0].replace(':', '=')
    cookie = tokens[2].replace(':', '=')

    return ','.join([cookie, table, tokens[1], tokens[3]])


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
        raise MissingFlows(missing_flows)
    else:
        print('All flows installed!')


def vlog_get(module: str, destination: str='file',
             daemon: str='ovn-controller') -> str:
    stdout = subprocess.check_output(['sudo', 'ovn-appctl', '-t', daemon,
                                      'vlog/list'], universal_newlines=True)
    for line in stdout.split('\n'):
        if line.startswith(module):
            tokens = line.split()
            return tokens[VLOG_DESTINATION[destination]]


def vlog_set(module: str, level: str, destination: str='file',
             daemon: str='ovn-controller') -> str:
    subprocess.check_call(['sudo', 'ovn-appctl', '-t', daemon,
                           'vlog/set', f'{module}:{destination}:{level}'])


def loop(ovn_logf: io.TextIOBase, ovs_logf: io.TextIOBase):
    # Seek to EOF
    ovn_logf.seek(0, 2)
    ovs_logf.seek(0, 2)
    expected_flows = set()
    while True:
        ovn_line = ovn_logf.readline()
        if not ovn_line or not ovn_line.endswith('\n'):
            time.sleep(0.025)
            print('expected_flows: {}'.format(len(expected_flows)))
            continue
        if 'ofctrl_put not needed' in ovn_line and len(expected_flows):
            try:
                check_ofctl(expected_flows)
            except MissingFlows as ex:
                # TODO(freyes): look for the missing flows in OVS logs.
                pass
        if 'ofctrl_add_flow' in ovn_line and 'table_id=20' in ovn_line:
            expected_flows.add(extract_flow_from_logline(ovn_line))
        if 'removing installed flow' in ovn_line and 'table_id=20' in ovn_line:
            expected_flows.remove(extract_flow_from_logline(ovn_line))

def main():
    ovn_logf = open('/var/log/ovn/ovn-controller.log')
    ovs_logf = open('/var/log/openvswitch/ovs-vswitchd.log')
    try:
        loop(ovn_logf, ovs_logf)
    finally:
        ovn_logf.close()
        ovs_logf.close()


if __name__ == '__main__':
    current_vlog_level = vlog_get('ofctrl')
    try:
        vlog_set('ofctrl', 'dbg')
        main()
    finally:
        vlog_set('ofctrl', current_vlog_level)
