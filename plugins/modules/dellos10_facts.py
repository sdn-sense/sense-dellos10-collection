#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright: Contributors to the Ansible project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

import re
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.six import iteritems
from ansible.utils.display import Display
from ansible_collections.sense.dellos10.plugins.module_utils.network.dellos10 import run_commands, normalizedip, normalizeIntfName
from ansible_collections.sense.dellos10.plugins.module_utils.network.dellos10 import dellos10_argument_spec, check_args

display = Display()


class FactsBase:
    """Base class for Facts"""

    COMMANDS = []

    def __init__(self, module):
        self.module = module
        self.facts = {}
        self.responses = None

    def populate(self):
        """Populate responses"""
        self.responses = run_commands(self.module, self.COMMANDS, check_rc=False)

    def run(self, cmd):
        """Run commands"""
        return run_commands(self.module, cmd, check_rc=False)


class Routing(FactsBase):

    COMMANDS = [
        'show running-config',
    ]

    def populate(self):
        super(Routing, self).populate()
        data = self.responses[0].split('\n')
        self.facts['ipv6'] = []
        self.getIPv6Routing(data)
        self.facts['ipv4'] = []
        self.getIPv4Routing(data)

    def getIPv4Routing(self, data):
        """Get IPv4 Routing from running config"""

        for inline in data:
            inline = inline.strip()  # Remove all white spaces
            # Rule 0: Parses route like: ip route 0.0.0.0/0 192.168.255.254
            match = re.match(r'ip route (\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}/\d{1,2}) (\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})$', inline)
            if match:
                self.facts['ipv4'].append({'to': match.groups()[0], 'from': match.groups()[1]})
                continue
            # Rule 1: Parses route like: ip route vrf lhcone 0.0.0.0/0 192.84.86.242
            match = re.match(r'ip route vrf (\w+) (\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}/\d{1,2}) (\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})$', inline)
            if match:
                self.facts['ipv4'].append({'vrf': match.groups()[0], 'to': match.groups()[1], 'from': match.groups()[2]})
                continue
            # Rule 2: Parses route like: ip route vrf lhcone 192.84.86.0/24 NULL 0
            match = re.match(r'ip route vrf (\w+) (\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}/\d{1,2}) (\w+) (\w+)$', inline)
            if match:
                self.facts['ipv4'].append({'vrf': match.groups()[0], 'to': match.groups()[1],
                                           'intf': f"{match.groups()[2]} {match.groups()[3]}"})
                continue
            # Rule 3: Parses route like: ip route vrf lhcone 192.84.86.0/24 NULL 0 1.2.3.1
            match = re.match(r'ip route vrf (\w+) (\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}/\d{1,2}) (\w+) (\w+) (\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})$', inline)
            if match:
                self.facts['ipv4'].append({'vrf': match.groups()[0], 'to': match.groups()[1],
                                           'intf': f"{match.groups()[2]} {match.groups()[3]}",
                                           'from': match.groups()[4]})

    def getIPv6Routing(self, data):
        """Get IPv6 Routing from running config"""
        for inline in data:
            inline = inline.strip()  # Remove all white spaces
            # Rule 0: Matches ipv6 route 2605:d9c0:2:11::/64 fd00::3600:1
            match = re.match(r'ipv6 route ([abcdef0-9:]+/\d{1,3}) ([abcdef0-9:]+)$', inline)
            if match:
                self.facts['ipv6'].append({'to': normalizedip(match.groups()[0]), 'from': normalizedip(match.groups()[1])})
                continue
            # Rule 1: Matches ipv6 route vrf lhcone ::/0 2605:d9c0:0:1::2
            match = re.match(r'ipv6 route vrf (\w+) ([abcdef0-9:]+/\d{1,3}) ([abcdef0-9:]+)$', inline)
            if match:
                self.facts['ipv6'].append({'vrf': match.groups()[0], 'to': normalizedip(match.groups()[1]),
                                           'from': normalizedip(match.groups()[2])})
                continue
            # Rule 2: Matches ipv6 route vrf lhcone 2605:d9c0::/32 NULL 0
            match = re.match(r'ipv6 route vrf (\w+) ([abcdef0-9:]+/\d{1,3}) (\w+) (\w+)$', inline)
            if match:
                self.facts['ipv6'].append({'vrf': match.groups()[0],
                                           'to': normalizedip(match.groups()[1]),
                                           'intf': f"{match.groups()[2]} {match.groups()[3]}"})
                continue
            # Rule 3: Matches ipv6 route vrf lhcone 2605:d9c0::2/128 NULL 0 2605:d9c0:0:1::2
            match = re.match(r'ipv6 route vrf (\w+) ([abcdef0-9:]+/\d{1,3}) (\w+) (\w+) ([abcdef0-9:]+)$', inline)
            if match:
                self.facts['ipv6'].append({'vrf': match.groups()[0],
                                           'to': normalizedip(match.groups()[1]),
                                           'intf': f"{match.groups()[2]} {match.groups()[3]}",
                                           'from': normalizedip(match.groups()[4])})


class LLDPInfo(FactsBase):
    """LLDP Information and link mapping"""
    COMMANDS = ['show lldp neighbors detail']

    def populate(self):
        super(LLDPInfo, self).populate()
        data = self.responses[0]
        self.facts['lldp'] = {}
        self.getlldpneighbors(data)

    def getlldpneighbors(self, data):
        """
        Get all lldp neighbors. Each entry will contain:
         Local Interface Hu 1/1 has 1 neighbor
          Total Frames Out: 98232
          Total Frames In: 98349
          Total Neighbor information Age outs: 0
          Total Multiple Neighbors Detected: 0
          Total Frames Discarded: 0
          Total In Error Frames: 0
          Total Unrecognized TLVs: 0
          Total TLVs Discarded: 0
          Next packet will be sent after 7 seconds
          The neighbors are given below:
          -----------------------------------------------------------------------
            Remote Chassis ID Subtype: Mac address (4)
            Remote Chassis ID:  34:17:eb:4c:1e:80
            Remote Port Subtype:  Interface name (5)
            Remote Port ID:  hundredGigE 1/32
            Local Port ID: hundredGigE 1/1
            Locally assigned remote Neighbor Index: 2
            Remote TTL:  120
            Information valid for next 113 seconds
            Time since last information change of this neighbor:  2w2d16h
           ---------------------------------------------------------------------------
        """
        regexs = {'local_port_id': r'Local Port ID:\s*(.+)',
                  'remote_system_name': r'Remote System Name:\s*(.+)',
                  'remote_port_id': r'Remote Port ID:\s*(.+)',
                  'remote_chassis_id': r'Remote Chassis ID:\s*(.+)'}
        for entry in data.split('-'*75):
            entryOut = {}
            for regName, regex in regexs.items():
                match = re.search(regex, entry, re.M)
                if match:
                    intfName = match.group(1)
                    if regName == 'local_port_id':
                        intfName = normalizeIntfName(intfName)
                    entryOut[regName] = intfName
            if 'local_port_id' in entryOut:
                self.facts['lldp'][entryOut['local_port_id']] = entryOut


class Default(FactsBase):
    """All Interfaces Class"""
    COMMANDS = ['show interface',
                'show running-config',
                'show system']

    def populate(self):
        super(Default, self).populate()

        self.facts.setdefault('info', {'macs': []})
        self.facts.setdefault('interfaces', {})
        calls = {'description': self.parse_description,
                 'macaddress': self.parse_macaddress,
                 'ipv4': self.parse_ipv4,
                 'ipv6': self.parse_ipv6,
                 'mtu': self.parse_mtu,
                 'bandwidth': self.parse_bandwidth,
                 'mediatype': self.parse_mediatype,
                 'lineprotocol': self.parse_lineprotocol,
                 'operstatus': self.parse_operstatus,
                 'type': self.parse_type,
                 'channel-member': self.parse_members}
        interfaceData = self.parseInterfaces(self.responses[0])
        for intfName, intfDict in interfaceData.items():
            intf = {}
            for key in calls:
                tmpOut = calls.get(key)(intfDict)
                if tmpOut:
                    intf[key] = tmpOut
            self.facts['interfaces'][intfName] = intf
            self.storeMacs(intf)
        # Use running config to identify all tagged, untagged vlans and mapping
        self.parseRunningConfig(self.responses[1])
        # Also write running config to output
        self.facts['config'] = self.responses[1]

        systemMac = self.parse_stack_mac(self.responses[2])
        if systemMac:
            self.facts['info']['macs'].append(systemMac)

    @staticmethod
    def parse_stack_mac(data):
        """Parse version"""
        match = re.search(r'^Stack MAC\s*:\s*(.+)', data)
        if match:
            return match.group(1)
        return ""

    def parseRunningConfig(self, data):
        """General Parser to parse ansible config"""
        interfaceSt = False
        key = None
        for line in data.split('\n'):
            line = line.strip()  # Remove all white spaces
            if line == "!" and interfaceSt:
                interfaceSt = False  # This means interface ended!
            elif line.startswith('interface'):
                interfaceSt = True
                key = normalizeIntfName(line[10:])
            elif interfaceSt:
                if line.startswith('switchport access vlan'):
                    untaggedVlan = line.split(' ')[3]
                    self.facts['interfaces'].setdefault(f"Vlan {untaggedVlan}", {})
                    self.facts['interfaces'][f"Vlan {untaggedVlan}"].setdefault("untagged", [])
                    self.facts['interfaces'][f"Vlan {untaggedVlan}"]["untagged"].append(key)
                elif line.startswith('switchport trunk allowed vlan'):
                    vlans = line.split(' ')[4]
                    for vlan in vlans.split(','):
                        tmpVlan = vlan.split('-')
                        if len(tmpVlan) == 1:
                            self.facts['interfaces'].setdefault(f"Vlan {vlan}", {})
                            self.facts['interfaces'][f"Vlan {vlan}"].setdefault("tagged", [])
                            self.facts['interfaces'][f"Vlan {vlan}"]["tagged"].append(key)
                        elif len(tmpVlan) == 2:
                            for val in range(int(tmpVlan[0]), int(tmpVlan[1]) + 1, 1):
                                self.facts['interfaces'].setdefault(f"Vlan {val}", {})
                                self.facts['interfaces'][f"Vlan {val}"].setdefault("tagged", [])
                                self.facts['interfaces'][f"Vlan {val}"]["tagged"].append(key)


    def storeMacs(self, intfdata):
        """Store Mac inside info for all known device macs"""
        self.facts.setdefault('info', {'macs': []})
        if 'macaddress' in intfdata and intfdata['macaddress']:
            if intfdata['macaddress'] not in self.facts['info']['macs']:
                self.facts['info']['macs'].append(intfdata['macaddress'])

    @staticmethod
    def parseInterfaces(data):
        """Parse interfaces from output"""
        parsed = {}
        newline_count = 0
        interface_start = True
        key = None
        for line in data.split('\n'):
            if interface_start:
                newline_count = 0
            if len(line) == 0:
                newline_count += 1
                if newline_count == 2:
                    interface_start = True
            else:
                match = re.match(r'^(\S+) (\S+) is (up|down)', line)
                if match and interface_start:
                    interface_start = False
                    key = f"{match.group(1)} {match.group(2)}"
                    parsed[key] = line
                else:
                    parsed[key] += '\n%s' % line
        return parsed

    @staticmethod
    def parse_description(data):
        match = re.search(r'Description: (.+)$', data, re.M)
        if match:
            return match.group(1)
        return None

    @staticmethod
    def parse_macaddress(data):
        for reg in [r'address is (\S+),', r'address is (\S+)']:
            match = re.search(reg, data)
            if match:
                if match.group(1) != "not":
                    return match.group(1)
        return None

    @staticmethod
    def parse_ipv4(data):
        match = re.search(r'Internet address is (\S+)', data)
        if match:
            if match.group(1) != "not":
                addr, masklen = match.group(1).split('/')
                return [dict(address=addr, masklen=int(masklen))]
        return None

    @staticmethod
    def parse_ipv6(data):
        match = re.search(r'Global IPv6 address: (\S+)', data)
        if match:
            if match.group(1) != "not":
                addr, masklen = match.group(1).split('/')
                return [dict(address=addr, masklen=int(masklen))]
        return None

    @staticmethod
    def parse_mtu(data):
        match = re.search(r'MTU (\d+)', data)
        if match:
            return int(match.group(1))
        return None

    @staticmethod
    def parse_bandwidth(data):
        match = re.search(r'LineSpeed (\d+)(G|M)?', data)
        if match:
            mgroups = match.groups()
            if mgroups[1] and mgroups[1] == 'G':
                return int(mgroups[0]) * 1000
            elif mgroups[1] and mgroups[1] == 'M':
                return int(mgroups[0])
            return int(mgroups[0])
        return None

    @staticmethod
    def parse_mediatype(data):
        media = re.search(r'(.+) media present, (.+)', data, re.M)
        if media:
            match = re.search(r'type is (.+)$', media.group(0), re.M)
            return match.group(1)
        return None

    @staticmethod
    def parse_type(data):
        match = re.search(r'Hardware is (.+),', data, re.M)
        if match:
            return match.group(1)
        return None

    @staticmethod
    def parse_lineprotocol(data):
        match = re.search(r'line protocol is (\w+[ ]?\w*)\(?.*\)?$', data, re.M)
        if match:
            return match.group(1)
        return None

    @staticmethod
    def parse_operstatus(data):
        match = re.search(r'^(\S+) (\S+) is (up|down),', data, re.M)
        if match:
            return match.group(3)
        return None

    @staticmethod
    def parse_members(data):
        match = re.search(r'^Members in this channel: +([a-zA-Z0-9 /\(\)]+)$', data, re.M)
        out = []
        if match:
            # Ethernet
            allintf = match.group(1).replace('Eth ', '').split(',')
            for intf in allintf:
                out.append(f"Ethernet {intf}")
        return out


FACT_SUBSETS = {'default': Default,
                'lldp': LLDPInfo,
                'routing': Routing}

VALID_SUBSETS = frozenset(FACT_SUBSETS.keys())


def main():
    """main entry point for module execution
    """
    argument_spec = {'gather_subset': {'default': [], 'type': 'list'}}
    argument_spec.update(dellos10_argument_spec)
    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True)
    gather_subset = module.params['gather_subset']
    runable_subsets = set()
    exclude_subsets = set()

    for subset in gather_subset:
        if subset == 'all':
            runable_subsets.update(VALID_SUBSETS)
            continue
        if subset.startswith('!'):
            subset = subset[1:]
            if subset == 'all':
                exclude_subsets.update(VALID_SUBSETS)
                continue
            exclude = True
        else:
            exclude = False
        if subset not in VALID_SUBSETS:
            module.fail_json(msg=f'Bad subset. {subset} not available in {VALID_SUBSETS}')
        if exclude:
            exclude_subsets.add(subset)
        else:
            runable_subsets.add(subset)
    if not runable_subsets:
        runable_subsets.update(VALID_SUBSETS)

    runable_subsets.difference_update(exclude_subsets)
    runable_subsets.add('default')

    facts = {'gather_subset': [runable_subsets]}

    instances = []
    for key in runable_subsets:
        instances.append(FACT_SUBSETS[key](module))

    for inst in instances:
        if inst:
            inst.populate()
            facts.update(inst.facts)

    ansible_facts = {}
    for key, value in iteritems(facts):
        key = 'ansible_net_%s' % key
        ansible_facts[key] = value

    warnings = []
    check_args(module, warnings)
    module.exit_json(ansible_facts=ansible_facts, warnings=warnings)


if __name__ == '__main__':
    main()
