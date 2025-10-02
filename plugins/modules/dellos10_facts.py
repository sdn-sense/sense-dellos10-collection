#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Dell EMC Networking OS10 Facts Module"""
import json
# Copyright: Contributors to the Ansible project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
import os
import tempfile

__metaclass__ = type

import re

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.six import iteritems
from ansible.utils.display import Display
from ansible_collections.sense.dellos10.plugins.module_utils.network.dellos10 import (
    check_args, dellos10_argument_spec, normalizedip, normalizeIntfName,
    run_commands)
from ansible_collections.sense.dellos10.plugins.module_utils.runwrapper import (
    classwrapper, functionwrapper)

display = Display()


@functionwrapper
def dumpFactsToTmp(ansible_facts):
    """
    Dump ansible_facts to a temp JSON file
    """

    def default_serializer(obj):
        if isinstance(obj, set):
            return list(obj)
        if isinstance(obj, bytes):
            return obj.decode("utf-8", errors="replace")
        return str(obj)

    fd, path = tempfile.mkstemp(prefix="ansible_facts_", suffix=".json", dir="/tmp")
    os.close(fd)

    with open(path, "w", encoding="utf-8") as f:
        json.dump(
            ansible_facts, f, indent=2, ensure_ascii=False, default=default_serializer
        )
    return path


@classwrapper
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


@classwrapper
class Routing(FactsBase):
    """Routing Information"""

    COMMANDS = [
        "show running-config",
    ]

    def populate(self):
        """Populate responses from device"""
        super(Routing, self).populate()
        data = self.responses[0].split("\n")
        self.facts["ipv6"] = []
        self.getIPv6Routing(data)
        self.facts["ipv4"] = []
        self.getIPv4Routing(data)

    def getIPv4Routing(self, data):
        """Get IPv4 Routing from running config"""

        for inline in data:
            inline = inline.strip()  # Remove all white spaces
            # Rule 0: Parses route like: ip route 0.0.0.0/0 192.168.255.254
            match = re.match(
                r"ip route (\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}/\d{1,2}) (\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})$",
                inline,
            )
            if match:
                self.facts["ipv4"].append(
                    {"to": match.groups()[0], "from": match.groups()[1]}
                )
                continue
            # Rule 1: Parses route like: ip route vrf lhcone 0.0.0.0/0 192.84.86.242
            match = re.match(
                r"ip route vrf (\w+) (\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}/\d{1,2}) (\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})$",
                inline,
            )
            if match:
                self.facts["ipv4"].append(
                    {
                        "vrf": match.groups()[0],
                        "to": match.groups()[1],
                        "from": match.groups()[2],
                    }
                )
                continue
            # Rule 2: Parses route like: ip route vrf lhcone 192.84.86.0/24 NULL 0
            match = re.match(
                r"ip route vrf (\w+) (\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}/\d{1,2}) (\w+) (\w+)$",
                inline,
            )
            if match:
                self.facts["ipv4"].append(
                    {
                        "vrf": match.groups()[0],
                        "to": match.groups()[1],
                        "intf": f"{match.groups()[2]} {match.groups()[3]}",
                    }
                )
                continue
            # Rule 3: Parses route like: ip route vrf lhcone 192.84.86.0/24 NULL 0 1.2.3.1
            match = re.match(
                r"ip route vrf (\w+) (\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}/\d{1,2}) (\w+) (\w+) (\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})$",
                inline,
            )
            if match:
                self.facts["ipv4"].append(
                    {
                        "vrf": match.groups()[0],
                        "to": match.groups()[1],
                        "intf": f"{match.groups()[2]} {match.groups()[3]}",
                        "from": match.groups()[4],
                    }
                )

    def getIPv6Routing(self, data):
        """Get IPv6 Routing from running config"""
        for inline in data:
            inline = inline.strip()  # Remove all white spaces
            # Rule 0: Matches ipv6 route 2605:d9c0:2:11::/64 fd00::3600:1
            match = re.match(
                r"ipv6 route ([abcdef0-9:]+/\d{1,3}) ([abcdef0-9:]+)$", inline
            )
            if match:
                self.facts["ipv6"].append(
                    {
                        "to": normalizedip(match.groups()[0]),
                        "from": normalizedip(match.groups()[1]),
                    }
                )
                continue
            # Rule 1: Matches ipv6 route vrf lhcone ::/0 2605:d9c0:0:1::2
            match = re.match(
                r"ipv6 route vrf (\w+) ([abcdef0-9:]+/\d{1,3}) ([abcdef0-9:]+)$", inline
            )
            if match:
                self.facts["ipv6"].append(
                    {
                        "vrf": match.groups()[0],
                        "to": normalizedip(match.groups()[1]),
                        "from": normalizedip(match.groups()[2]),
                    }
                )
                continue
            # Rule 2: Matches ipv6 route vrf lhcone 2605:d9c0::/32 NULL 0
            match = re.match(
                r"ipv6 route vrf (\w+) ([abcdef0-9:]+/\d{1,3}) (\w+) (\w+)$", inline
            )
            if match:
                self.facts["ipv6"].append(
                    {
                        "vrf": match.groups()[0],
                        "to": normalizedip(match.groups()[1]),
                        "intf": f"{match.groups()[2]} {match.groups()[3]}",
                    }
                )
                continue
            # Rule 3: Matches ipv6 route vrf lhcone 2605:d9c0::2/128 NULL 0 2605:d9c0:0:1::2
            match = re.match(
                r"ipv6 route vrf (\w+) ([abcdef0-9:]+/\d{1,3}) (\w+) (\w+) ([abcdef0-9:]+)$",
                inline,
            )
            if match:
                self.facts["ipv6"].append(
                    {
                        "vrf": match.groups()[0],
                        "to": normalizedip(match.groups()[1]),
                        "intf": f"{match.groups()[2]} {match.groups()[3]}",
                        "from": normalizedip(match.groups()[4]),
                    }
                )


@classwrapper
class LLDPInfo(FactsBase):
    """LLDP Information and link mapping"""

    COMMANDS = ["show lldp neighbors detail"]

    def populate(self):
        """Populate responses from device"""
        super(LLDPInfo, self).populate()
        data = self.responses[0]
        self.facts["lldp"] = {}
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
        regexs = {
            "local_port_id": r"Local Port ID:\s*(.+)",
            "remote_system_name": r"Remote System Name:\s*(.+)",
            "remote_port_id": r"Remote Port ID:\s*(.+)",
            "remote_chassis_id": r"Remote Chassis ID:\s*(.+)",
        }
        for entry in data.split("-" * 75):
            entryOut = {}
            for regName, regex in regexs.items():
                match = re.search(regex, entry, re.M)
                if match:
                    intfName = match.group(1)
                    if regName == "local_port_id":
                        intfName = normalizeIntfName(intfName)
                    entryOut[regName] = intfName
            if "local_port_id" in entryOut:
                self.facts["lldp"][entryOut["local_port_id"]] = entryOut


@classwrapper
class Default(FactsBase):
    """All Interfaces Class"""

    COMMANDS = [
        "show interface",
        "show interface port-channel",
        "show running-config",
        "show system",
    ]

    def populate(self):
        """Populate responses from device"""
        super(Default, self).populate()

        self.facts.setdefault("info", {"macs": []})
        self.facts.setdefault("interfaces", {})
        calls = {
            "description": self.parse_description,
            "macaddress": self.parse_macaddress,
            "ipv4": self.parse_ipv4,
            "ipv6": self.parse_ipv6,
            "mtu": self.parse_mtu,
            "bandwidth": self.parse_bandwidth,
            "mediatype": self.parse_mediatype,
            "lineprotocol": self.parse_lineprotocol,
            "operstatus": self.parse_operstatus,
            "type": self.parse_type,
            "channel-member": self.parse_members,
        }
        # Dell OS 10 `show interface` will not list port_members... Weird no?
        # but `show interface port-channel will list port_members. so we joint 2 outputs
        interfaceData = self.parseInterfaces(
            self.responses[0] + "\n\n" + self.responses[1]
        )
        for intfName, intfDict in interfaceData.items():
            intf = {}
            for key in calls:
                tmpOut = calls.get(key)(intfDict)
                if tmpOut:
                    intf[key] = tmpOut
            self.facts["interfaces"][intfName] = intf
            self.storeMacs(intf)
        # Use running config to identify all tagged, untagged vlans and mapping
        self.parseRunningConfig(self.responses[2])
        # Also write running config to output
        self.facts["config"] = self.responses[2]

        systemMac = self.parse_stack_mac(self.responses[3])
        if systemMac:
            self.facts["info"]["macs"].append(systemMac)

    @staticmethod
    def parse_stack_mac(data):
        """Parse version"""
        match = re.search(r"^Stack MAC\s*:\s*(.+)", data)
        if match:
            return match.group(1)
        return ""

    def parseRunningConfig(self, data):
        """General Parser to parse ansible config"""
        calls = {
            "tagged": self.parse_tagged,
            "untagged": self.parse_untagged,
            "portmode": self.parse_portmode,
            "switchport": self.parse_switchport,
            "spanning-tree": self.parse_spanning_tree,
            "ip_vrf": self.parse_ip_vrf,
        }
        interfaceSt = False
        intfKey = None
        for line in data.split("\n"):
            line = line.strip()  # Remove all white spaces
            if line == "!" and interfaceSt:
                interfaceSt = False  # This means interface ended!
            elif line.startswith("interface"):
                interfaceSt = True
                intfKey = normalizeIntfName(line[10:])
            elif interfaceSt and intfKey in self.facts["interfaces"]:
                for key, call in calls.items():
                    tmpOut = call(line, intfKey)
                    if tmpOut and isinstance(tmpOut, list):
                        self.facts["interfaces"][intfKey].setdefault(key, [])
                        self.facts["interfaces"][intfKey][key] += tmpOut
                    elif tmpOut and isinstance(tmpOut, str):
                        self.facts["interfaces"][intfKey].setdefault(key, "")
                        self.facts["interfaces"][intfKey][key] = tmpOut

    def storeMacs(self, intfdata):
        """Store Mac inside info for all known device macs"""
        self.facts.setdefault("info", {"macs": []})
        if "macaddress" in intfdata and intfdata["macaddress"]:
            if intfdata["macaddress"] not in self.facts["info"]["macs"]:
                self.facts["info"]["macs"].append(intfdata["macaddress"])

    @staticmethod
    def parseInterfaces(data):
        """Parse interfaces from output"""
        parsed = {}
        key = None
        for line in data.split("\n"):
            if len(line) == 0:
                continue
            match = re.match(r"^(.*) is (.*), line protocol is (.*)", line)
            if match:
                key = match.group(1)
                if key == "NULL":
                    key = None
                    continue
                parsed[key] = line
            elif key:
                parsed[key] += f"\n{line}"
        return parsed

    def parse_tagged(self, line, intfKey):
        """Parse Tagged Vlans"""
        if line.startswith("switchport trunk allowed vlan"):
            vlans = line.split(" ")[4]
            for vlan in vlans.split(","):
                tmpVlan = vlan.split("-")
                if len(tmpVlan) == 1:
                    self.facts["interfaces"].setdefault(f"Vlan {vlan}", {})
                    self.facts["interfaces"][f"Vlan {vlan}"].setdefault("tagged", [])
                    self.facts["interfaces"][f"Vlan {vlan}"]["tagged"].append(intfKey)
                elif len(tmpVlan) == 2:
                    for val in range(int(tmpVlan[0]), int(tmpVlan[1]) + 1, 1):
                        self.facts["interfaces"].setdefault(f"Vlan {val}", {})
                        self.facts["interfaces"][f"Vlan {val}"].setdefault("tagged", [])
                        self.facts["interfaces"][f"Vlan {val}"]["tagged"].append(
                            intfKey
                        )
        return []

    def parse_untagged(self, line, intfKey):
        """Parse Untagged Vlans"""
        if line.startswith("switchport access vlan"):
            untaggedVlan = line.split(" ")[3]
            self.facts["interfaces"].setdefault(f"Vlan {untaggedVlan}", {})
            self.facts["interfaces"][f"Vlan {untaggedVlan}"].setdefault("untagged", [])
            self.facts["interfaces"][f"Vlan {untaggedVlan}"]["untagged"].append(intfKey)
        return []

    @staticmethod
    def parse_portmode(data, _intfKey):
        """Parse Portmode"""
        tmpOut = ""
        if data.startswith("switchport access vlan "):
            tmpOut = ["access"]
        elif data.startswith("switchport trunk allowed vlan"):
            tmpOut = ["trunk"]
        return tmpOut

    @staticmethod
    def parse_switchport(data, _intfKey):
        """Parse Switchport"""
        tmpOut = ""
        if data == "switchport mode trunk":
            tmpOut = "yes"
        elif data == "no switchport":
            tmpOut = "no"
        return tmpOut

    @staticmethod
    def parse_spanning_tree(data, _intfKey):
        """Parse spanning tree"""
        tmpOut = []
        if data.startswith("no spanning-tree"):
            tmpOut = ["no"]
        elif data.startswith("spanning-tree"):
            tmpOut = [data[14:]]
        return tmpOut

    @staticmethod
    def parse_ip_vrf(data, _intfKey):
        """Parse ip vrf"""
        tmpOut = ""
        if data.startswith("ip vrf"):
            tmpOut = data[7:]
        return tmpOut

    @staticmethod
    def parse_description(data):
        """Parse description"""
        match = re.search(r"Description: (.+)$", data, re.M)
        if match:
            return match.group(1)
        return None

    @staticmethod
    def parse_macaddress(data):
        """Parse macaddress"""
        for reg in [r"address is (\S+),", r"address is (\S+)"]:
            match = re.search(reg, data)
            if match:
                if match.group(1) != "not":
                    return match.group(1)
        return None

    @staticmethod
    def parse_ipv4(data):
        """Parse ipv4"""
        match = re.search(r"Internet address is (\S+)", data)
        if match:
            if match.group(1) != "not":
                addr, masklen = match.group(1).split("/")
                return [{"address": addr, "masklen": int(masklen)}]
        return None

    @staticmethod
    def parse_ipv6(data):
        """Parse ipv6"""
        match = re.search(r"Global IPv6 address: (\S+)", data)
        if match:
            if match.group(1) != "not":
                addr, masklen = match.group(1).split("/")
                return [{"address": addr, "masklen": int(masklen)}]
        return None

    @staticmethod
    def parse_mtu(data):
        """Parse mtu"""
        match = re.search(r"MTU (\d+)", data)
        if match:
            return int(match.group(1))
        return None

    @staticmethod
    def parse_bandwidth(data):
        """Parse bandwidth"""
        match = re.search(r"LineSpeed (\d+)(G|M)?", data)
        if match:
            mgroups = match.groups()
            if mgroups[1] and mgroups[1] == "G":
                return int(mgroups[0]) * 1000
            if mgroups[1] and mgroups[1] == "M":
                return int(mgroups[0])
            return int(mgroups[0])
        return None

    @staticmethod
    def parse_mediatype(data):
        """Parse mediatype"""
        media = re.search(r"(.+) media present, (.+)", data, re.M)
        if media:
            match = re.search(r"type is (.+)$", media.group(0), re.M)
            return match.group(1)
        return None

    @staticmethod
    def parse_type(data):
        """Parse type"""
        match = re.search(r"Hardware is (.+),", data, re.M)
        if match:
            return match.group(1)
        return None

    @staticmethod
    def parse_lineprotocol(data):
        """Parse lineprotocol"""
        match = re.search(r"line protocol is (\w+[ ]?\w*)\(?.*\)?$", data, re.M)
        if match:
            return match.group(1)
        return None

    @staticmethod
    def parse_operstatus(data):
        """Parse operstatus"""
        match = re.search(r"^(\S+) (\S+) is (up|down),", data, re.M)
        if match:
            return match.group(3)
        return None

    @staticmethod
    def parse_members(data):
        """Parse port-channel members"""
        match = re.search(
            r"^Members in this channel: +([a-zA-Z0-9 /\-\,]+)$", data, re.M
        )
        out = []
        if match:
            # Ethernet
            allintf = match.group(1).replace("Eth ", "").split(",")
            for vals in allintf:
                if "-" in vals:
                    stVal = vals.split("-")[0].split("/")
                    enVal = vals.split("-")[1].split("/")
                    mod, modline = None, None
                    # If first digit not equal - replace first
                    if (
                        stVal[0] != enVal[0]
                        and stVal[1] == enVal[1]
                        and stVal[2] == enVal[2]
                        and int(stVal[0]) < int(enVal[0])
                    ):
                        modline = f"%s/{stVal[1]}/{stVal[2]}"
                        mod = 0
                    # If second digit not equal - replace second
                    elif (
                        stVal[0] == enVal[0]
                        and stVal[1] != enVal[1]
                        and stVal[2] == enVal[2]
                        and int(stVal[1]) < int(enVal[1])
                    ):
                        modline = f"{stVal[0]}/%s/{stVal[2]}"
                        mod = 1
                    # If third digit not equal - replace third
                    elif (
                        stVal[0] == enVal[0]
                        and stVal[1] == enVal[1]
                        and stVal[2] != enVal[2]
                        and int(stVal[2]) < int(enVal[2])
                    ):
                        modline = f"{stVal[0]}/{stVal[1]}/%s"
                        mod = 2
                    if mod and modline:
                        for val in range(int(stVal[mod]), int(enVal[mod]) + 1, 1):
                            newval = modline % val
                            out.append(f"Ethernet {newval}")
                    else:
                        display.warning(
                            f"Failed increment ports. Report bug. Input Line: {data}"
                        )
                else:
                    out.append(f"Ethernet {vals}")
        return out


FACT_SUBSETS = {"default": Default, "lldp": LLDPInfo, "routing": Routing}

VALID_SUBSETS = frozenset(FACT_SUBSETS.keys())


@functionwrapper
def main():
    """main entry point for module execution"""
    argument_spec = {"gather_subset": {"default": [], "type": "list"}}
    argument_spec.update(dellos10_argument_spec)
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    gather_subset = module.params["gather_subset"]
    runable_subsets = set()
    exclude_subsets = set()

    for subset in gather_subset:
        if subset == "all":
            runable_subsets.update(VALID_SUBSETS)
            continue
        if subset.startswith("!"):
            subset = subset[1:]
            if subset == "all":
                exclude_subsets.update(VALID_SUBSETS)
                continue
            exclude = True
        else:
            exclude = False
        if subset not in VALID_SUBSETS:
            module.fail_json(
                msg=f"Bad subset. {subset} not available in {VALID_SUBSETS}"
            )
        if exclude:
            exclude_subsets.add(subset)
        else:
            runable_subsets.add(subset)
    if not runable_subsets:
        runable_subsets.update(VALID_SUBSETS)

    runable_subsets.difference_update(exclude_subsets)
    runable_subsets.add("default")

    facts = {"gather_subset": [runable_subsets]}

    instances = []
    for key in runable_subsets:
        instances.append(FACT_SUBSETS[key](module))

    for inst in instances:
        if inst:
            inst.populate()
            facts.update(inst.facts)

    ansible_facts = {}
    for key, value in iteritems(facts):
        key = f"ansible_net_{key}"
        ansible_facts[key] = value

    warnings = []
    check_args(module, warnings)
    if len(str(ansible_facts)) > 100000:
        facts_path = dumpFactsToTmp(ansible_facts)
        display.vvv(facts_path)
        module.exit_json(ansible_facts_file={"file": facts_path}, warnings=warnings)
    else:
        module.exit_json(ansible_facts=ansible_facts, warnings=warnings)


if __name__ == "__main__":
    main()
