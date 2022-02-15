#!/usr/bin/env python3

import unittest

import missingflowhunter

class TestOVSLogParsing(unittest.TestCase):
    def test_extract_flow_from_ovs_logline(self):
        f_input = open('fixtures/ovs-vswitch.log.add-table.in', 'r')
        f_output = open('fixtures/ovs-vswitch.log.add-table.out', 'r')
        while True:
            in_line = f_input.readline().strip('\n')
            out_line = f_output.readline().strip('\n')

            if not in_line:
                return

            self.assertEqual(
                missingflowhunter.extract_flow_from_ovs_logline(in_line),
                out_line)


if __name__ == '__main__':
    unittest.main()
