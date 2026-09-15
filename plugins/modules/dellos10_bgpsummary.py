#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Dell OS 10 BGP Summary
Copyright: Contributors to the SENSE Project
GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

Runs 'show ip bgp [vrf <vrf>] [ipv6 unicast] summary | display-xml' and
normalizes the result into the shared SiteRM BGP schema:
{"vrf": ..., "afi_checked": [...], "peers": [...]}

Dell OS10's CLI streams one '<?xml ...?><rpc-reply>...</rpc-reply>' document
per peer for this command rather than a single well-formed document, so the
raw response is split on '<?xml' boundaries and each fragment parsed
separately with xml.etree.ElementTree.

Title                   : sdn-sense/sense-dellos10-collection
Author                  : Justas Balcas
Email                   : juztas (at) gmail.com
@Copyright              : General Public License v3.0+
Date                    : 2026/09/15
"""
from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

import re
import xml.etree.ElementTree as ET

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.sense.dellos10.plugins.module_utils.network.dellos10 import run_commands
from ansible_collections.sense.dellos10.plugins.module_utils.network.dellos10 import dellos10_argument_spec, check_args
from ansible_collections.sense.dellos10.plugins.module_utils.runwrapper import functionwrapper

_KNOWN_STATES = ("established", "idle", "active", "connect", "opensent", "openconfirm")


@functionwrapper
def normalizeBgpState(rawstate):
    """Normalize a vendor BGP FSM state string to the shared enum."""
    state = str(rawstate).lower()
    return state if state in _KNOWN_STATES else "unknown"


@functionwrapper
def splitXmlDocuments(rawtext):
    """Split a stream of concatenated '<?xml ...?><rpc-reply>...</rpc-reply>'
    documents into a list of individually parseable XML strings."""
    parts = re.split(r"(?=<\?xml)", rawtext)
    return [p.strip() for p in parts if p.strip()]


@functionwrapper
def buildCommand(vrf, iptype):
    """Build the Dell OS10 'show ip bgp ...' command for a single AFI."""
    vrfclause = f"vrf {vrf} " if vrf else ""
    if iptype == "ipv6":
        return f"show ip bgp {vrfclause}ipv6 unicast summary | display-xml"
    return f"show ip bgp {vrfclause}summary | display-xml"


@functionwrapper
def parseBgpSummaryXml(rawtext, iptype, peers):
    """Parse one AFI's 'display-xml' response, appending normalized peers."""
    for doc in splitXmlDocuments(rawtext):
        try:
            root = ET.fromstring(doc)
        except ET.ParseError:
            # Some documents in the stream are empty <bulk><data/></bulk> replies
            continue
        for peerel in root.findall(".//peer-oper"):
            remoteaddr = (peerel.findtext("remote-address") or "").strip()
            if not remoteaddr:
                continue
            uptimems = peerel.findtext("fsm-established-time") or "0"
            try:
                uptimems = int(uptimems)
            except ValueError:
                uptimems = 0
            peers.append({
                "peer": remoteaddr,
                "iptype": iptype,
                "local_asn": _toint(peerel.findtext("local-as")),
                "remote_asn": _toint(peerel.findtext("remote-as")),
                "state": normalizeBgpState(peerel.findtext("bgp-state") or ""),
                "uptime_seconds": int(uptimems // 1000),
                "prefixes_received": _toint(peerel.findtext("in-prefixes")),
                "prefixes_advertised": _toint(peerel.findtext("out-prefixes")),
                "advertised_known": True,
            })


def _toint(value):
    """Best-effort int conversion, None on failure/absence."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


@functionwrapper
def main():
    """main entry point for module execution"""
    argument_spec = {
        "vrf": {"type": "str", "default": ""},
        "type": {"type": "str", "default": "both", "choices": ["ipv4", "ipv6", "both"]},
    }
    argument_spec.update(dellos10_argument_spec)

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    warnings = []
    check_args(module, warnings)

    vrf = module.params["vrf"]
    wanttype = module.params["type"]
    wantafis = ["ipv4", "ipv6"] if wanttype == "both" else [wanttype]

    peers = []
    for iptype in wantafis:
        command = buildCommand(vrf, iptype)
        responses = run_commands(module, [command])
        parseBgpSummaryXml(responses[0] if responses else "", iptype, peers)

    bgp_summary = {"vrf": vrf or None, "afi_checked": wantafis, "peers": peers}

    module.exit_json(changed=False, warnings=warnings, bgp_summary=bgp_summary)


if __name__ == "__main__":
    main()
