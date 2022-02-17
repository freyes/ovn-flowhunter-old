#!/usr/bin/env python3

import argparse
import collections
import functools
import json
import os
import re
import subprocess
import sys
import uuid


__doc__ = 'Detect and delete duplicated logical flows.'

RE_LRP = re.compile('^[ ]+table=\d+\(lr_in_arp_resolve  \), priority=\d+  , '
                    'match=\(outport == "lrp-.*')
RE_PORT_UUID = re.compile('.*\(outport == "lrp-(.*)" ')
RE_IP_ADDR = re.compile('.* reg0 == (.*)\), action=\(eth.dst = ([a-f0-9:]{17});')


class PortNotFound(Exception):
    pass


class ManyPortsFound(Exception):
    pass


def setup_options() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--datapath', dest='datapath', metavar='NAME',
                        required=True,
                        help='Datapath')
    parser.add_argument('--delete', dest='delete', action='store_true',
                        help='Delete duplicates found')
    parser.add_argument('--dry-run', dest='dry_run', action='store_true',
                        help=("Don't perform the operation, just print what "
                              "deletions would have been made."))
    return parser.parse_args()


def get_ovn_ips(name: str) -> str:
    """Get ONV NB or SB IP addresses to connect to."""
    assert name in ["ovnnb", "ovnsb"]

    with open('/etc/ovn/ovn-northd-db-params.conf', 'r') as f:
        for line in f.readlines():
            if name in line:
                return line.split('=')[1].strip()
    raise ValueError(f'{name} not found')


def run_sbctl(cmd: list[str]) -> subprocess.CompletedProcess:
    """Run ovn-sbctl.

    :param cmd: list of arguments to pass to ovn-sbctl.
    """
    return run_ctl('ovn-sbctl', cmd)


def run_nbctl(cmd: list[str]) -> subprocess.CompletedProcess:
    return run_ctl('ovn-nbctl', cmd)


def run_ctl(progname: str, cmd: list[str]) -> subprocess.CompletedProcess:
    ips = get_ovn_ips('ovnsb')
    crt_file = None
    for crt in ['/etc/ovn/ovn-chassis.crt', '/etc/ovn/ovn-central.crt']:
        if os.path.isfile(crt):
            crt_file = crt
            break

    assert crt_file != None, 'crt file not found'
    command = [progname,
               '-p', '/etc/ovn/key_host',
               '-C', crt_file,
               '-c', '/etc/ovn/cert_host',
               '--db', ips,
               '--leader-only'] + cmd
    p = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       universal_newlines=True)
    return p


def find_lflow_dups(datapath: str) -> dict:
    """Find logical flows duplicated in Southbound DB.

    :param datapath: A datapath that lflow-list can undestand, this is
                     typically an OpenStack router.
    :returns: A dictionary where each key is a flow with more than 1 ocurrences
              and the value is the list of flows that matched.
    """
    cmd = ['lflow-list', datapath]

    p = run_sbctl(cmd)

    assert p.returncode == 0, p.stderr

    stdout_lines = p.stdout.split('\n')
    header = stdout_lines[0]  # Datapath: "neutron-..."
    flows = collections.defaultdict(list)
    for line in stdout_lines[1:]:
        result = RE_LRP.match(line)
        if not result:
            continue

        flow = ','.join(line.split(',')[0:3]).lstrip()
        flows[flow] += [line.strip()]

    duplicates = dict(filter(lambda elem: len(elem[1]) > 1, flows.items()))
    return duplicates


def parse_port(lines: list) -> dict:
    """Parse a list of strings to build a dictionary that represents a port."""
    port = {}
    for line in lines:
        if line.startswith("_uuid"):
            port['_uuid'] = uuid.UUID(line.split(':', maxsplit=1)[1].strip())
        elif line.startswith("addresses"):
            port['addresses'] = line.split(':', maxsplit=1)[1].strip()
        elif line.startswith('up'):
            value = line.split(':', maxsplit=1)[1].strip()
            port['up'] = True if value == 'true' else False

    return port


@functools.lru_cache(maxsize=None)  # unlimited caching
def get_list_logical_switch_port() -> list:
    """Get the list of logical Switch Port."""

    p = run_nbctl(['list', 'logical-switch-port'])
    assert p.returncode == 0, f"{p.stderr}"

    ports = []
    buffer_ = []
    for line in p.stdout.split('\n'):
        if line == '':
            ports.append(parse_port(buffer_))
            buffer_ = []
        else:
            buffer_.append(line)

    return ports


def get_port_uuid(flow: str) -> dict:
    """Get the port UUID from a flow."""

    result = RE_IP_ADDR.match(flow)
    assert result, f"IP address not found: {flow}"
    ip_addr = result.group(1)
    mac_addr = result.group(2)

    ports = get_list_logical_switch_port()

    ports_found = list(
        filter(lambda p: mac_addr in p['addresses'] and ip_addr in p['addresses'], ports))

    if len(ports_found) == 1:
        return ports_found[0]
    elif len(ports_found) == 0:
        raise PortNotFound(flow, ip_addr)
    else:
        # more than one ports found, is this correct?
        raise ManyPortsFound(flow, ip_addr, ports_found)


def delete_port(port_uuid: uuid.UUID,
                dry_run: bool=False) -> subprocess.CompletedProcess:
    """Delete port by UUID.

    :param uuid: port's uuid.
    :returns: returns the CompletedProcess object to let the caller examine the
              error (if any).
    """
    cmd = ['ovn-nbctl', 'lsp-del', str(port_uuid)]
    if not dry_run:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           universal_newlines=True)
        return p
    else:
        print('CMD: %s' % ' '.join(cmd))


def delete_duplicates(duplicates: dict, dry_run: bool=False) -> list:
    failures = []
    for k, flows in duplicates.items():
        for flow in flows:
            try:
                port = get_port_uuid(flow)

                # delete the port only if it is not up.
                if not port['up']:
                    r = delete_port(port_uuid, dry_run)
                    if dry_run:
                        pass
                    elif r.returncode == 0:
                        # a poor's man progress bar.
                        print('.', end='')
                    else:
                        failures.append((port_uuid, r))
                        print('F', end='')
            except PortNotFound as ex:
                print('E', end='')
    return failures


def print_report(duplicates: dict):
    for k, flows in duplicates.items():
        print(len(flows), k)


def main() -> int:
    opts = setup_options()
    duplicates = find_lflow_dups(opts.datapath)

    print_report(duplicates)

    if duplicates and opts.delete:
        failures = delete_duplicates(duplicates, dry_run=opts.dry_run)
        if failures:
            print("\nPorts that couldn't be deleted:")
            for (port_uuid, p) in failures:
                print(f"{port_uuid}: {p.stderr} (exit: {p.returncode})")

            return 1

if __name__ == '__main__':
    sys.exit(main())
