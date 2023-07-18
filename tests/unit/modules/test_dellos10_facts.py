#!/usr/bin/env python3
# -*- coding: utf-8 -*-
__metaclass__ = type

import json

from unittest.mock import patch
from ansible_collections.sense.dellos10.tests.unit.modules.dellos10_module import TestDellOS10Module, load_fixture
from ansible_collections.sense.dellos10.tests.unit.modules.dellos10_module import set_module_args
from ansible_collections.sense.dellos10.plugins.modules import dellos10_facts


class TestDellOS10Facts(TestDellOS10Module):

    module = dellos10_facts

    def setUp(self):
        super(TestDellOS10Facts, self).setUp()

        self.mock_run_command = patch(
            'ansible_collections.sense.dellos10.plugins.modules.dellos10_facts.run_commands')
        self.run_commands = self.mock_run_command.start()

    def tearDown(self):
        super(TestDellOS10Facts, self).tearDown()

        self.mock_run_command.stop()

    def load_fixtures(self, commands=None):

        def load_from_file(*args, **kwargs):
            module, commands = args
            output = list()

            for item in commands:
                try:
                    obj = json.loads(item)
                    command = obj['command']
                except ValueError:
                    command = item
                if '|' in command:
                    command = str(command).replace('|', '')
                filename = str(command).replace(' ', '_')
                filename = filename.replace('/', '7')
                output.append(load_fixture(filename))
            return output

        self.run_commands.side_effect = load_from_file

    def test_dellos10_facts_gather_subset_default(self):
        set_module_args({'gather_subset': 'default'})
        result = self.execute_module()
        ansible_facts = result['ansible_facts']

        self.assertIn('ansible_net_interfaces', ansible_facts)
        test_data = {'Port-channel 104': {'bandwidth': 200000,
                                          'channel-member': ['hundredGigE '
                                                             '1/17',
                                                             'hundredGigE '
                                                             '1/19'],
                                          'description': 'PortChannel '
                                                         'to Arista-R02',
                                          'lineprotocol': 'up',
                                          'macaddress': '4c:76:25:e8:44:c2',
                                          'mtu': 9416,
                                          'operstatus': 'up'},
                     'TenGigabitEthernet 1/33': {'bandwidth': 10000,
                                                 'lineprotocol': 'up',
                                                 'macaddress': '4c:76:25:e8:44:c2',
                                                 'mediatype': '10GBASE-SR',
                                                 'mtu': 9416,
                                                 'operstatus': 'up',
                                                 'type': 'DellEMCEth'},
                     'Vlan 101': {'bandwidth': 40000,
                                  'description': 'Kubernetes Multus for '
                                                 'SENSE-Rucio XRootD '
                                                 'fff1 IPv6 Range',
                                  'ipv6': [{'address': '2605:d9c0:2:fff1::1',
                                            'masklen': 64}],
                                  'lineprotocol': 'up',
                                  'macaddress': '4c:76:25:e8:44:c2',
                                  'mtu': 9416,
                                  'operstatus': 'up',
                                  'tagged': ['fortyGigE 1/29',
                                             'hundredGigE 1/10',
                                             'hundredGigE 1/11',
                                             'hundredGigE 1/12',
                                             'hundredGigE 1/23',
                                             'hundredGigE 1/25',
                                             'hundredGigE 1/27',
                                             'Port-channel 102']}}
        for key, vals in test_data.items():
            self.assertIn(key, ansible_facts['ansible_net_interfaces'])
            for subkey, subval in vals.items():
                self.assertEquals(subval, ansible_facts['ansible_net_interfaces'][key][subkey])

    def test_dellos10_facts_gather_subset_routing(self):
        set_module_args({'gather_subset': 'routing'})
        result = self.execute_module()
        ansible_facts = result['ansible_facts']
        test_data = { 'ansible_net_ipv4': [{'from': '192.84.86.238',
                                            'to': '0.0.0.0/0',
                                            'vrf': 'lhcone'}],
                      'ansible_net_ipv6': [{'from': '2605:d9c0:0:ff02::',
                                            'to': '::/0',
                                            'vrf': 'lhcone'},
                                           {'intf': 'NULL 0',
                                            'to': '2605:d9c0:2::/48',
                                            'vrf': 'lhcone'}]}
        self.assertIn('ansible_net_ipv4', ansible_facts)
        self.assertEquals(test_data['ansible_net_ipv4'], ansible_facts['ansible_net_ipv4'])
        self.assertIn('ansible_net_ipv6', ansible_facts)
        self.assertEquals(test_data['ansible_net_ipv6'], ansible_facts['ansible_net_ipv6'])

    def test_dellos10_facts_gather_subset_lldp(self):
        set_module_args({'gather_subset': 'lldp'})
        result = self.execute_module()
        ansible_facts = result['ansible_facts']

        self.assertIn('ansible_net_lldp', ansible_facts)
        test_data = {'ManagementEthernet 1/1': {'local_port_id': 'ManagementEthernet '
                                                                  '1/1',
                                                 'remote_chassis_id': '00:01:e8:96:1c:19',
                                                 'remote_port_id': 'GigabitEthernet '
                                                                   '0/33',
                                                 'remote_system_name': 'LRT-R02-DELL-S60'},
                      'TenGigabitEthernet 1/33': {'local_port_id': 'TenGigabitEthernet '
                                                                   '1/33',
                                                  'remote_chassis_id': '00:01:e8:96:1c:19',
                                                  'remote_port_id': 'TenGigabitEthernet '
                                                                    '0/51',
                                                  'remote_system_name': 'LRT-R02-DELL-S60'},
                      'TenGigabitEthernet 1/34': {'local_port_id': 'TenGigabitEthernet '
                                                                   '1/34',
                                                  'remote_chassis_id': '00:01:e8:96:13:4f',
                                                  'remote_port_id': 'TenGigabitEthernet '
                                                                    '0/51',
                                                  'remote_system_name': 'LRT-R01-DELL-S60'},
                      'fortyGigE 1/26/1': {'local_port_id': 'fortyGigE 1/26/1',
                                           'remote_chassis_id': '00:01:e8:d7:72:f9',
                                           'remote_port_id': 'fortyGigE 0/48',
                                           'remote_system_name': 'lrt-sdn-r02-dell-s4810'}}
        for key, vals in test_data.items():
            self.assertIn(key, ansible_facts['ansible_net_lldp'])
            for subkey, subval in vals.items():
                self.assertEquals(subval, ansible_facts['ansible_net_lldp'][key][subkey])