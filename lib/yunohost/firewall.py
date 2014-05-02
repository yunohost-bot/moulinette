# -*- coding: utf-8 -*-

""" License

    Copyright (C) 2013 YunoHost

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program; if not, see http://www.gnu.org/licenses

"""

""" yunohost_firewall.py

    Manage firewall rules
"""
import os
import sys
import yaml
try:
    import miniupnpc
except ImportError:
    sys.stderr.write('Error: Yunohost CLI Require miniupnpc lib\n')
    sys.exit(1)

from moulinette.core import MoulinetteError


def firewall_allow(port=None, protocol='TCP', ipv6=False, no_upnp=False):
    """
    Allow connection port/protocol

    Keyword argument:
        port -- Port to open
        protocol -- Protocol associated with port
        ipv6 -- ipv6
        no_upnp -- Do not request for uPnP

    """
    port = int(port)
    ipv  = "ipv4"
    protocols = [protocol]

    firewall = firewall_list(raw=True)

    upnp = not no_upnp and firewall['uPnP']['enabled']

    if ipv6:
        ipv = "ipv6"

    if protocol == "Both":
        protocols = ['UDP', 'TCP']

    for protocol in protocols:
        if upnp and port not in firewall['uPnP'][protocol]:
            firewall['uPnP'][protocol].append(port)
        if port not in firewall[ipv][protocol]:
            firewall[ipv][protocol].append(port)
        else:
            msignals.display(_("Port already openned: %d" % port), 'warning')

    with open('/etc/yunohost/firewall.yml', 'w') as f:
        yaml.safe_dump(firewall, f, default_flow_style=False)

    return firewall_reload()


def firewall_disallow(port=None, protocol='TCP', ipv6=False):
    """
    Allow connection port/protocol

    Keyword argument:
        port -- Port to open
        protocol -- Protocol associated with port
        ipv6 -- ipv6

    """
    port = int(port)
    ipv  = "ipv4"
    protocols = [protocol]

    firewall = firewall_list(raw=True)

    if ipv6:
        ipv = "ipv6"

    if protocol == "Both":
        protocols = ['UDP', 'TCP']

    for protocol in protocols:
        if port in firewall['uPnP'][protocol]:
            firewall['uPnP'][protocol].remove(port)
        if port in firewall[ipv][protocol]:
            firewall[ipv][protocol].remove(port)
        else:
            msignals.display(_("Port already closed: %d" % port), 'warning')

    with open('/etc/yunohost/firewall.yml', 'w') as f:
        yaml.safe_dump(firewall, f, default_flow_style=False)

    return firewall_reload()


def firewall_list(raw=False):
    """
    List all firewall rules

    Keyword argument:
        raw -- Return the complete YAML dict

    """
    with open('/etc/yunohost/firewall.yml') as f:
        firewall = yaml.load(f)

    if raw:
        return firewall
    else:
        return { "openned_ports": firewall['ipv4']['TCP'] }


def firewall_reload():
    """
    Reload all firewall rules


    """
    from yunohost.hook import hook_callback

    firewall = firewall_list(raw=True)
    upnp = firewall['uPnP']['enabled']

    # IPv4
    if os.system("iptables -P INPUT ACCEPT") != 0:
        raise MoulinetteError(1, _("You cannot play with iptables here. You are either in a container or your kernel does not support it."))
    if upnp:
        try:
            upnpc = miniupnpc.UPnP()
            upnpc.discoverdelay = 200
            if upnpc.discover() == 1:
                upnpc.selectigd()
                for protocol in ['TCP', 'UDP']:
                    for port in firewall['uPnP'][protocol]:
                        if upnpc.getspecificportmapping(port, protocol):
                            try: upnpc.deleteportmapping(port, protocol)
                            except: pass
                        upnpc.addportmapping(port, protocol, upnpc.lanaddr, port, 'yunohost firewall : port %d' % port, '')
            else:
                raise MoulinetteError(1, _("No uPnP device found"))
        except:
            msignals.display(_("An error occured during uPnP port openning"), 'warning')

    os.system("iptables -F")
    os.system("iptables -X")
    os.system("iptables -A INPUT -m state --state ESTABLISHED -j ACCEPT")

    if 22 not in firewall['ipv4']['TCP']:
        firewall_allow(22)

    # Loop
    for protocol in ['TCP', 'UDP']:
        for port in firewall['ipv4'][protocol]:
            os.system("iptables -A INPUT -p %s --dport %d -j ACCEPT" % (protocol, port))

    hook_callback('post_iptable_rules', [upnp, os.path.exists("/proc/net/if_inet6")])

    os.system("iptables -A INPUT -i lo -j ACCEPT")
    os.system("iptables -A INPUT -p icmp -j ACCEPT")
    os.system("iptables -P INPUT DROP")

    # IPv6
    if os.path.exists("/proc/net/if_inet6"):
        os.system("ip6tables -P INPUT ACCEPT")
        os.system("ip6tables -F")
        os.system("ip6tables -X")
        os.system("ip6tables -A INPUT -m state --state ESTABLISHED -j ACCEPT")

        if 22 not in firewall['ipv6']['TCP']:
            firewall_allow(22, ipv6=True)

        # Loop v6
        for protocol in ['TCP', 'UDP']:
            for port in firewall['ipv6'][protocol]:
                os.system("ip6tables -A INPUT -p %s --dport %d -j ACCEPT" % (protocol, port))
    
        os.system("ip6tables -A INPUT -i lo -j ACCEPT")
        os.system("ip6tables -A INPUT -p icmpv6 -j ACCEPT")
        os.system("ip6tables -P INPUT DROP")

    os.system("service fail2ban restart")
    msignals.display(_("Firewall successfully reloaded"), 'success')

    return firewall_list()


def firewall_upnp(action=None):
    """
    Add uPnP cron and enable uPnP in firewall.yml, or the opposite.

    Keyword argument:
        action -- enable/disable

    """

    firewall = firewall_list(raw=True)

    if action:
        action = action[0]

    if action == 'enable':
        firewall['uPnP']['enabled'] = True
        
        with open('/etc/cron.d/yunohost-firewall', 'w+') as f:
            f.write('*/50 * * * * root PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin yunohost firewall reload >>/dev/null')

        msignals.display(_("uPnP successfully enabled"), 'success')

    if action == 'disable':
        firewall['uPnP']['enabled'] = False

        try:
            upnpc = miniupnpc.UPnP()
            upnpc.discoverdelay = 200
            if upnpc.discover() == 1:
                upnpc.selectigd()
                for protocol in ['TCP', 'UDP']:
                    for port in firewall['uPnP'][protocol]:
                        if upnpc.getspecificportmapping(port, protocol):
                            try: upnpc.deleteportmapping(port, protocol)
                            except: pass
        except: pass
                

        try: os.remove('/etc/cron.d/yunohost-firewall')
        except: pass

        msignals.display(_("uPnP successfully disabled"), 'success')

    if action:
        os.system("cp /etc/yunohost/firewall.yml /etc/yunohost/firewall.yml.old")
        with open('/etc/yunohost/firewall.yml', 'w') as f:
            yaml.safe_dump(firewall, f, default_flow_style=False)

    return { "enabled": firewall['uPnP']['enabled'] }


def firewall_stop():
    """
    Stop iptables and ip6tables


    """

    if os.system("iptables -P INPUT ACCEPT") != 0:
        raise MoulinetteError(1, _("You cannot play with iptables here. You are either in a container or your kernel does not support it."))

    os.system("iptables -F")
    os.system("iptables -X")

    if os.path.exists("/proc/net/if_inet6"):
        os.system("ip6tables -P INPUT ACCEPT")
        os.system("ip6tables -F")
        os.system("ip6tables -X")

    if os.path.exists("/etc/cron.d/yunohost-firewall"):
        firewall_upnp('disable')
