#!/usr/bin/env python3

import subprocess
import unittest
import uuid

from unittest import mock

import find_duplicates

DUPLICATES = {
    'table=12(lr_in_arp_resolve  ), priority=100  , match=(outport == "lrp-f85096df-74b7-4c75-917c-cb6726319bfb" && reg0 == 172.16.0.141)':
    ['table=12(lr_in_arp_resolve  ), priority=100  , match=(outport == "lrp-f85096df-74b7-4c75-917c-cb6726319bfb" && reg0 == 172.16.0.141), action=(eth.dst = fa:16:3e:a1:27:b3; next;)',
     'table=12(lr_in_arp_resolve  ), priority=100  , match=(outport == "lrp-f85096df-74b7-4c75-917c-cb6726319bfb" && reg0 == 172.16.0.141), action=(eth.dst = fa:16:3e:69:92:0f; next;)'],
    'table=12(lr_in_arp_resolve  ), priority=100  , match=(outport == "lrp-f85096df-74b7-4c75-917c-cb6726319bfb" && reg0 == 172.16.0.182)':
    ['table=12(lr_in_arp_resolve  ), priority=100  , match=(outport == "lrp-f85096df-74b7-4c75-917c-cb6726319bfb" && reg0 == 172.16.0.182), action=(eth.dst = fa:16:3e:73:7f:0b; next;)',
     'table=12(lr_in_arp_resolve  ), priority=100  , match=(outport == "lrp-f85096df-74b7-4c75-917c-cb6726319bfb" && reg0 == 172.16.0.182), action=(eth.dst = fa:16:3e:f5:a7:95; next;)']
}


class FakeCompletedProcess:
    def __init__(self):
        self.returncode = 0
        self.stdout = None
        self.stderr = None


class TestFindDuplicates(unittest.TestCase):

    @mock.patch.object(find_duplicates, 'run_sbctl')
    def test_find_lflow_dups(self, run_sbctl):
        fake_p = FakeCompletedProcess()
        with open('fixtures/lflow-list.zuul-tests_router.txt', 'r') as f:
            fake_p.stdout = f.read()

        run_sbctl.return_value = fake_p
        self.maxDiff = None
        duplicates = find_duplicates.find_lflow_dups('zuul-tests_admin_net')
        self.assertDictEqual(duplicates, DUPLICATES)

    @mock.patch.object(find_duplicates, 'run_nbctl')
    def test_get_port_uuid(self, run_nbctl):
        flow = 'table=12(lr_in_arp_resolve  ), priority=100  , match=(outport == "lrp-f85096df-74b7-4c75-917c-cb6726319bfb" && reg0 == 192.168.21.230), action=(eth.dst = fa:16:3e:1b:ae:20; next;)'
        fake_p = FakeCompletedProcess()
        fake_p.returncode = 0
        with open('fixtures/list-logical-switch-port.txt', 'r') as f:
            fake_p.stdout = f.read()

        run_nbctl.return_value = fake_p

        port = find_duplicates.get_port_uuid(flow)
        self.assertEqual(str(port['_uuid']),
                         'de23da0c-b496-4588-bb4a-266bef2a8d27')

    @mock.patch('subprocess.run')
    def test_delete_port(self, run):
        port = '4ada0187-3b77-4bc9-a829-392d0301ce0f'
        port_uuid = uuid.UUID(port)
        r = find_duplicates.delete_port(port_uuid)
        run.assert_called_with(['ovn-nbctl', 'lsp-del', port],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               universal_newlines=True)

    @mock.patch.object(find_duplicates, 'run_nbctl')
    def test_get_list_logical_switch_port(self, run_nbctl):
        fake_p = FakeCompletedProcess()
        fake_p.returncode = 0
        with open('fixtures/list-logical-switch-port.txt', 'r') as f:
            fake_p.stdout = f.read()

        run_nbctl.return_value = fake_p

        ports = find_duplicates.get_list_logical_switch_port()
        self.assertEqual(len(ports), 4)
        self.assertEqual(len(list(filter(lambda p: p['up'], ports))), 2)
