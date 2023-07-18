#!/usr/bin/python3
# -*- coding: utf-8 -*-

# Copyright: Contributors to the Ansible project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

import re
from ipaddress import ip_address
from ansible.utils.display import Display
from ansible.module_utils._text import to_text
from ansible.module_utils.basic import env_fallback
from ansible.module_utils.connection import exec_command
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import to_list, ComplexList

display = Display()

_DEVICE_CONFIGS = {}

WARNING_PROMPTS_RE = [
    r"[\r\n]?\[yes/no\]:\s?$",
    r"[\r\n]?\[confirm yes/no\]:\s?$",
    r"[\r\n]?\[y/n\]:\s?$"
]

dellos10_provider_spec = {
    'host': {}, 'port': {'type': int},
    'username': {'fallback': (env_fallback, ['ANSIBLE_NET_USERNAME'])},
    'password': {'fallback': (env_fallback, ['ANSIBLE_NET_PASSWORD']), 'no_log': True},
    'ssh_keyfile': {'fallback': (env_fallback, ['ANSIBLE_NET_SSH_KEYFILE']), 'type': 'path'},
    'authorize': {'fallback': (env_fallback, ['ANSIBLE_NET_AUTHORIZE']), 'type': 'bool'},
    'auth_pass': {'fallback': (env_fallback, ['ANSIBLE_NET_AUTH_PASS']), 'no_log': True},
    'timeout': {'type': 'int'},
}
dellos10_argument_spec = {
    'provider': {'type': 'dict', 'options': dellos10_provider_spec}
}


def check_args(module, warnings):
    """Check args pass"""
    pass


def get_config(module, flags=None):
    """Get running config"""
    flags = [] if flags is None else flags

    cmd = 'show running-config ' + ' '.join(flags)
    cmd = cmd.strip()

    try:
        return _DEVICE_CONFIGS[cmd]
    except KeyError:
        ret, out, err = exec_command(module, cmd)
        if ret != 0:
            module.fail_json(msg='unable to retrieve current config', stderr=to_text(err, errors='surrogate_or_strict'))
        cfg = to_text(out, errors='surrogate_or_strict').strip()
        _DEVICE_CONFIGS[cmd] = cfg
        return cfg


def to_commands(module, commands):
    """Transform commands"""
    spec = {
        'command': {'key': True},
        'prompt': {},
        'answer': {}
    }
    transform = ComplexList(spec, module)
    return transform(commands)


def run_commands(module, commands, check_rc=True):
    """Run Commands"""
    responses = []
    commands = to_commands(module, to_list(commands))
    for cmd in commands:
        cmd = module.jsonify(cmd)
        ret, out, err = exec_command(module, cmd)
        if check_rc and ret != 0:
            module.fail_json(msg=to_text(err, errors='surrogate_or_strict'), rc=ret)
        responses.append(to_text(out, errors='surrogate_or_strict'))
    return responses


def load_config(module, commands):
    """Load config"""
    ret, _out, err = exec_command(module, 'configure terminal')
    if ret != 0:
        module.fail_json(msg='unable to enter configuration mode', err=to_text(err, errors='surrogate_or_strict'))

    for command in to_list(commands):
        if command == 'end':
            continue
        ret, _out, err = exec_command(module, command)
        if ret != 0:
            module.fail_json(msg=to_text(err, errors='surrogate_or_strict'), command=command, rc=ret)

    exec_command(module, 'end')


def normalizedip(ipInput):
    """
    Normalize IPv6 address. It can have leading 0 or not and both are valid.
    This function will ensure same format is used.
    """
    tmp = ipInput.split('/')
    ipaddr = None
    try:
        ipaddr = ip_address(tmp[0]).compressed
    except ValueError:
        ipaddr = tmp[0]
    if len(tmp) == 2:
        return f"{ipaddr}/{tmp[1]}"
    if len(tmp) == 1:
        return ipaddr
    # We return what we get here, because it had multiple / (which is not really valid)
    return ipInput

def normalizeIntfName(intfName):
    intfName = intfName.replace('port-channel', 'Port-channel ')
    intfName = intfName.replace('ethernet', 'Ethernet ')
    intfName = intfName.replace('mgmt', 'Management ')
    return intfName