#!/usr/bin/env python3
#
#    Copyright (C) 2020  Dmitri Rubinstein, DFKI GmbH
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.

# Based on
# https://github.com/doccaz/kvm-scripts/blob/master/qemu-hook-script-python
# https://github.com/rhardouin/libvirt_hooks/blob/master/qemu

import ipaddress
import logging
import os
import os.path
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
import configparser
from collections import namedtuple, defaultdict
from logging.handlers import SysLogHandler

THIS_DIR = os.path.dirname(os.path.realpath(__file__))

CONFIG_FILES = [
    '/etc/libvirt/libvirt-networks.conf',
    os.path.join(THIS_DIR, 'libvirt-networks.conf')
]

NetworkConfig = namedtuple('NetworkConfig', ['name', 'ip_routing_table_id', 'ip_rule_priority'])
NetworkInterface = namedtuple('NetworkInterface', ['name', 'gateway_ip'])
CommandResult = namedtuple('CommandResult', ['returncode', 'output'])

NETWORK_CONFIGS = {}
NETWORK_INTERFACES = {}

# NETWORK_CONFIGS = {
#    'nat223': NetworkConfig('nat223', 99, 99),
#    'ext-net': NetworkConfig('ext-net', 100, 100),
#    'foresight-vm-net-4': NetworkConfig('foresight-vm-net-4', 102, 102)
# }
#
# NETWORK_INTERFACES = {
#    'br2': NetworkInterface('br2', '192.168.81.1')
# }

DEBUG = True

LOG = logging.getLogger(__name__)
# LOG.setLevel(logging.DEBUG)
if DEBUG:
    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(pathname)s:%(lineno)s: %(message)s",
        level=logging.DEBUG
    )
else:
    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(message)s",
        level=logging.INFO
    )
handler = SysLogHandler(address='/dev/log')
fmt = logging.Formatter('libvirt-network-hook: %(levelname)s: %(message)s')
handler.setFormatter(fmt)
LOG.addHandler(handler)


def fix_output(output, maxlen=200):
    if isinstance(output, bytes):
        output = output.decode('utf-8')
    output = output.rstrip('\n')
    if maxlen > 0 and len(output) > maxlen - 3:
        return output[:maxlen - 3] + '...'
    else:
        return output


class CommandError(Exception):

    def __init__(self, command, returncode, stdout, stderr):
        super().__init__('Command {!r} failed with returncode {}, stdout: [{}], stderr: [{}]'.format(
            command, returncode, fix_output(stdout), fix_output(stderr)))
        self.command = command
        self.stdout = stdout
        self.stderr = stderr


def run_command_ext(command, env=None, cwd=None, stdin=None, timeout=15):
    """returns triple (returncode, stdout, stderr)"""
    if env is not None:
        myenv = {}
        for key, value in env.items():
            myenv[str(key)] = str(value)
        env = myenv
    else:
        env = os.environ

    proc = subprocess.Popen(command,
                            stdin=stdin,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            env=env,
                            cwd=cwd,
                            universal_newlines=False)
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()

    return proc.returncode, out, err


def run_command(args, check=True):
    args_str = ' '.join(args)
    LOG.info('Run command: %r', args_str)
    returncode, out, err = run_command_ext(args)
    if check and returncode != 0:
        LOG.error('Command %r failed', args_str)
        raise CommandError(args, returncode, out, err)
    return returncode, out, err


def load_config():
    for cfg_fn in CONFIG_FILES:
        cfg_parser = configparser.ConfigParser()
        # use case sensitive mapping
        cfg_parser.optionxform = str
        if os.path.exists(cfg_fn):
            try:
                cfg_parser.read(cfg_fn)
            except Exception as e:
                LOG.exception('Could not read configuration file %s', cfg_fn)
                continue
            else:
                LOG.info('Configuration file %s was read', cfg_fn)
        else:
            LOG.info('Could not open the configuration file %s', cfg_fn)
            continue
        network_configs = defaultdict(dict)
        for key, value in cfg_parser.items('libvirt-networks'):
            network_name, network_key = key.split('.', 2)
            network_configs[network_name][network_key] = value

        for key, value in cfg_parser.items('network-interfaces'):
            NETWORK_INTERFACES[key] = NetworkInterface(name=key, gateway_ip=value)

        for network_name, network_config in network_configs.items():
            nc = NetworkConfig(
                name=network_name,
                ip_routing_table_id=int(network_config.get('routing_table', 100)),
                ip_rule_priority=int(network_config.get('rule_priority', 100)))
            NETWORK_CONFIGS[network_name] = nc


def main():
    network = sys.argv[1] if len(sys.argv) > 1 else ''
    action = sys.argv[2] if len(sys.argv) > 2 else ''
    state = sys.argv[3] if len(sys.argv) > 3 else ''
    all_args = ' '.join(sys.argv[1:])
    LOG.info('network=%s action=%s state=%s [%s]', network, action, state, all_args)

    try:
        load_config()

        network_config = NETWORK_CONFIGS.get(network)
        if network_config:
            LOG.info('Configuration for libvirt network %s found', network_config.name)
            if action in ('started', 'stopped'):

                xml = sys.stdin.read()
                root = ET.fromstring(xml)
                # tree = ET.parse(sys.stdin)
                # root = tree.getroot()

                bridge_node = root.find(".//bridge")
                if bridge_node is None:
                    LOG.warning('bridge XML element not found in [%s]', xml)
                    return
                bridge_name = bridge_node.attrib['name']
                if not bridge_name:
                    LOG.warning('bridge.name attribute is not set or empty in [%s]', xml)
                    return
                forward_node = root.find(".//forward")
                if forward_node is None:
                    LOG.warning('forward XML element not found in [%s]', xml)
                    return
                forward_dev = forward_node.attrib['dev']
                if not forward_dev:
                    LOG.warning('forward.dev attribute is not set or empty in [%s]', xml)
                    return

                ip_node = root.find('.//ip')
                if ip_node is None:
                    LOG.warning('ip XML element not found in [%s]', xml)
                    return
                ip_address = ip_node.attrib['address']
                if not ip_address:
                    LOG.warning('ip.address attribute is not set or empty in [%s]', xml)
                    return
                ip_netmask = ip_node.attrib['netmask']
                if not ip_netmask:
                    LOG.warning('ip.netmask attribute is not set or empty in [%s]', xml)

                network_interface = NETWORK_INTERFACES.get(forward_dev)
                if not network_interface:
                    LOG.warning('No %s network interface found in the configuration', forward_dev)
                    return
                ip_network = ipaddress.ip_network(address=(ip_address, ip_netmask), strict=False)
                ip_routing_table_id = str(network_config.ip_routing_table_id)
                ip_rule_priority = str(network_config.ip_rule_priority)
                ip_network_and_prefix = '{}/{}'.format(ip_network.network_address, ip_network.prefixlen)
                gateway_ip = network_interface.gateway_ip

                LOG.info('Forwarding device: %s', forward_dev)
                LOG.info('Default gateway for %s network interface: %s', forward_dev, gateway_ip)
                LOG.info('Bridge name: %s', bridge_name)
                LOG.info('IP address and netmask: %s/%s', ip_address, ip_netmask)
                LOG.info('IP address and prefix: %s/%s', ip_address, ip_network.prefixlen)
                LOG.info('IP of network %s: %s', network, ip_network.network_address)
                LOG.info('Routing table ID: %s', ip_routing_table_id)
                LOG.info('Rule priority: %s', ip_rule_priority)
                # Delete table
                LOG.info("Delete old policy rules")
                run_command(['ip', 'rule', 'del', 'priority', ip_rule_priority, 'from', ip_network_and_prefix, 'lookup',
                             ip_routing_table_id], check=False)
                run_command(['ip', 'rule', 'del', 'priority', ip_rule_priority, 'to', ip_network_and_prefix, 'lookup',
                             ip_routing_table_id], check=False)
                run_command(['ip', 'route', 'flush', 'table', ip_routing_table_id], check=False)
                LOG.info("Old policy rules deleted")
                if action == "started":
                    LOG.info("Add new policy rules")
                    run_command(
                        ['ip', 'rule', 'add', 'priority', ip_rule_priority, 'from', ip_network_and_prefix, 'lookup',
                         ip_routing_table_id], check=True)
                    run_command(
                        ['ip', 'rule', 'add', 'priority', ip_rule_priority, 'to', ip_network_and_prefix, 'lookup',
                         ip_routing_table_id], check=True)
                    attempt_num = 0
                    max_num_attempts = 100
                    while True:
                        try:
                            run_command(
                                ['ip', 'route', 'add', 'table', ip_routing_table_id, 'default', 'via', gateway_ip,
                                 'dev', forward_dev], check=True)
                        except CommandError as e:
                            attempt_num += 1
                            if attempt_num == max_num_attempts:
                                LOG.error("Failed after %s attempts to add a route for the %s device", attempt_num,
                                          forward_dev)
                                _, c_stdout, c_stderr = run_command(["ip", "link", "show", forward_dev], check=False)
                                LOG.info("stdout: [%s], stderr: [%s]",
                                         fix_output(c_stdout, 1000), fix_output(c_stderr, 1000))
                                LOG.info("* All connections:")
                                _, c_stdout, c_stderr = run_command(["nmcli", "-t", "-m", "tabular", "con", "show"],
                                                                    check=False)
                                LOG.info("stdout: [%s], stderr: [%s]",
                                         fix_output(c_stdout, 1000), fix_output(c_stderr, 1000))
                                LOG.info("* Active connections:")
                                _, c_stdout, c_stderr = run_command(
                                    ["nmcli", "-t", "-m", "tabular", "con", "show", "--active"], check=False)
                                LOG.info("stdout: [%s], stderr: [%s]",
                                         fix_output(c_stdout, 1000), fix_output(c_stderr, 1000))
                                raise
                            LOG.info('wait one second and retry')
                            time.sleep(1)
                        else:
                            break
                    run_command(
                        ['ip', 'route', 'add', 'table', ip_routing_table_id, ip_network_and_prefix, 'dev', bridge_name,
                         'proto', 'static', 'scope', 'link', 'src', ip_address], check=True)
                    LOG.info("New policy rules added")
                LOG.info("Flush route cache")
                run_command(['ip', 'route', 'flush', 'cache'], check=True)
                LOG.info("Route cache flushed")
    except Exception as e:
        LOG.exception('network hook failed: network=%s action=%s state=%s [%s]', network, action, state, all_args)
    else:
        LOG.info('exiting: network=%s action=%s state=%s [%s]', network, action, state, all_args)


if __name__ == "__main__":
    main()
    sys.exit(0)
