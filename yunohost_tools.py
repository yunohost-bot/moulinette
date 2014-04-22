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

""" yunohost_tools.py

    Specific tools
"""
import os
import sys
import yaml
import re
import getpass
import requests
import json
import apt
import apt.progress
from yunohost import YunoHostError, YunoHostLDAP, validate, colorize, get_required_args, win_msg
from yunohost_domain import domain_add, domain_list
from yunohost_dyndns import dyndns_subscribe
from yunohost_backup import backup_init
from yunohost_app import app_ssowatconf, app_fetchlist, app_info, app_upgrade
from yunohost_service import service_log

apps_setting_path= '/etc/yunohost/apps/'

def tools_ldapinit(password=None):
    """
    YunoHost LDAP initialization


    """
    with YunoHostLDAP() as yldap:

        with open('ldap_scheme.yml') as f:
            ldap_map = yaml.load(f)

        for rdn, attr_dict in ldap_map['parents'].items():
            try: yldap.add(rdn, attr_dict)
            except: pass

        for rdn, attr_dict in ldap_map['children'].items():
            try: yldap.add(rdn, attr_dict)
            except: pass

        admin_dict = {
            'cn': 'admin',
            'uid': 'admin',
            'description': 'LDAP Administrator',
            'gidNumber': '1007',
            'uidNumber': '1007',
            'homeDirectory': '/home/admin',
            'loginShell': '/bin/bash',
            'objectClass': ['organizationalRole', 'posixAccount', 'simpleSecurityObject'],
            'userPassword': 'yunohost'
        }

        yldap.update('cn=admin', admin_dict)

    win_msg(_("LDAP has been successfully initialized"))


def tools_adminpw(old_password, new_password):
    """
    Change admin password

    Keyword argument:
        new_password
        old_password

    """
    # Validate password length
    if len(new_password) < 4:
        raise YunoHostError(22, _("Password is too short"))

    old_password.replace('"', '\\"')
    old_password.replace('&', '\\&')
    new_password.replace('"', '\\"')
    new_password.replace('&', '\\&')
    result = os.system('ldappasswd -h localhost -D cn=admin,dc=yunohost,dc=org -w "'+ old_password +'" -a "'+ old_password +'" -s "' + new_password + '"')

    if result == 0:
        win_msg(_("Admin password has been changed"))
    else:
        raise YunoHostError(22, _("Invalid password"))


def tools_maindomain(old_domain=None, new_domain=None, dyndns=False):
    """
    Main domain change tool

    Keyword argument:
        new_domain
        old_domain

    """

    if not old_domain:
        with open('/etc/yunohost/current_host', 'r') as f:
            old_domain = f.readline().rstrip()

        if not new_domain:
            return { 'current_main_domain': old_domain }

    validate(r'^([a-zA-Z0-9]{1}([a-zA-Z0-9\-]*[a-zA-Z0-9])*)(\.[a-zA-Z0-9]{1}([a-zA-Z0-9\-]*[a-zA-Z0-9])*)*(\.[a-zA-Z]{1}([a-zA-Z0-9\-]*[a-zA-Z0-9])*)$', old_domain)

    config_files = [
        '/etc/postfix/main.cf',
        '/etc/metronome/metronome.cfg.lua',
        '/etc/dovecot/dovecot.conf',
        '/usr/share/yunohost/yunohost-config/others/startup',
        '/home/yunohost.backup/tahoe/tahoe.cfg',
        '/etc/amavis/conf.d/05-node_id',
        '/etc/amavis/conf.d/50-user'
    ]

    config_dir = []

    for dir in config_dir:
        for file in os.listdir(dir):
            config_files.append(dir + '/' + file)

    for file in config_files:
        with open(file, "r") as sources:
            lines = sources.readlines()
        with open(file, "w") as sources:
            for line in lines:
                sources.write(re.sub(r''+ old_domain +'', new_domain, line))

    domain_add([new_domain], main=True)

    os.system('rm /etc/ssl/private/yunohost_key.pem')
    os.system('rm /etc/ssl/certs/yunohost_crt.pem')

    command_list = [
        'ln -s /etc/yunohost/certs/'+ new_domain +'/key.pem /etc/ssl/private/yunohost_key.pem',
        'ln -s /etc/yunohost/certs/'+ new_domain +'/crt.pem /etc/ssl/certs/yunohost_crt.pem',
        'echo '+ new_domain +' > /etc/yunohost/current_host',
        'service nginx restart',
        'service metronome restart',
        'service postfix restart',
        'service dovecot restart',
        'service amavis restart'
    ]

    try:
        with open('/etc/yunohost/light') as f: pass
    except IOError:
        command_list.append('service amavis restart')
        #command_list.append('service tahoe-lafs restart')

    for command in command_list:
        if os.system(command) != 0:
            raise YunoHostError(17, _("There were a problem during domain changing"))

    if dyndns: dyndns_subscribe(domain=new_domain)
    elif len(new_domain.split('.')) >= 3:
        r = requests.get('http://dyndns.yunohost.org/domains')
        dyndomains = json.loads(r.text)
        dyndomain  = '.'.join(new_domain.split('.')[1:])
        if dyndomain in dyndomains:
            dyndns_subscribe(domain=new_domain)

    win_msg(_("Main domain has been successfully changed"))


def tools_postinstall(domain, password, dyndns=False):
    """
    YunoHost post-install

    Keyword argument:
        domain -- YunoHost main domain
        dyndns -- Subscribe domain to a DynDNS service
        password -- YunoHost admin password

    """
    try:
        with open('/etc/yunohost/installed') as f: pass
    except IOError:
        print('Installing YunoHost')
    else:
        raise YunoHostError(17, _("YunoHost is already installed"))

    if len(domain.split('.')) >= 3:
        r = requests.get('http://dyndns.yunohost.org/domains')
        dyndomains = json.loads(r.text)
        dyndomain  = '.'.join(domain.split('.')[1:])
        if dyndomain in dyndomains:
            if requests.get('http://dyndns.yunohost.org/test/'+ domain).status_code == 200:
                dyndns=True
            else:
                raise YunoHostError(17, _("Domain is already taken"))

    # Create required folders
    folders_to_create = [
        '/etc/yunohost/apps',
        '/etc/yunohost/certs',
        '/var/cache/yunohost/repo',
        '/home/yunohost.backup',
        '/home/yunohost.app'
    ]

    for folder in folders_to_create:
        try: os.listdir(folder)
        except OSError: os.makedirs(folder)

    # Set hostname to avoid amavis bug
    if os.system('hostname -d') != 0:
        os.system('hostname yunohost.yunohost.org')

    # Add a temporary SSOwat rule to redirect SSO to admin page
    try:
        with open('/etc/ssowat/conf.json.persistent') as json_conf:
            ssowat_conf = json.loads(str(json_conf.read()))
    except IOError:
        ssowat_conf = {}

    if 'redirected_urls' not in ssowat_conf:
        ssowat_conf['redirected_urls'] = {}

    ssowat_conf['redirected_urls']['/'] = domain +'/yunohost/admin'

    with open('/etc/ssowat/conf.json.persistent', 'w+') as f:
        json.dump(ssowat_conf, f, sort_keys=True, indent=4)

    os.system('chmod 644 /etc/ssowat/conf.json.persistent')

    # Create SSL CA
    ssl_dir = '/usr/share/yunohost/yunohost-config/ssl/yunoCA'
    command_list = [
        'echo "01" > '+ ssl_dir +'/serial',
        'rm '+ ssl_dir +'/index.txt',
        'touch '+ ssl_dir +'/index.txt',
        'cp '+ ssl_dir +'/openssl.cnf '+ ssl_dir +'/openssl.ca.cnf ',
        'sed -i "s/yunohost.org/'+ domain +'/g" '+ ssl_dir +'/openssl.ca.cnf ',
        'openssl req -x509 -new -config '+ ssl_dir +'/openssl.ca.cnf -days 3650 -out '+ ssl_dir +'/ca/cacert.pem -keyout '+ ssl_dir +'/ca/cakey.pem -nodes -batch',
        'cp '+ ssl_dir +'/ca/cacert.pem /etc/ssl/certs/ca-yunohost_crt.pem',
        'update-ca-certificates'
    ]

    for command in command_list:
        if os.system(command) != 0:
            raise YunoHostError(17, _("There were a problem during CA creation"))

    with YunoHostLDAP(password='yunohost') as yldap:

        # Initialize YunoHost LDAP base
        tools_ldapinit(password)

        # Initialize backup system
        backup_init()

        # New domain config
        tools_maindomain(old_domain='yunohost.org', new_domain=domain, dyndns=dyndns)

        # Generate SSOwat configuration file
        app_ssowatconf()


        # Change LDAP admin password
        tools_adminpw(old_password='yunohost', new_password=password)

        os.system('touch /etc/yunohost/installed')
        os.system('service yunohost-api restart &')

    win_msg(_("YunoHost has been successfully configured"))


def tools_update(ignore_apps=False, ignore_packages=False):
    """
    Update apps & package cache, then display changelog

    Keyword arguments:
        ignore_apps -- Ignore app list update and changelog
        ignore_packages -- Ignore apt cache update and changelog

    """
    packages = []
    if not ignore_packages:
        cache = apt.Cache()
        # Update APT cache
        if not cache.update():
            raise YunoHostError(1, _("An error occured during APT cache update"))

        cache.open(None)
        cache.upgrade(True)

        # Add changelogs to the result
        for pkg in cache.get_changes():
            packages.append({
                'name': pkg.name,
                'fullname': pkg.fullname,
                'changelog': pkg.get_changelog()
            })
        
    apps = []
    if not ignore_apps:
        app_fetchlist()
        app_list = os.listdir(apps_setting_path)
        if len(app_list) > 0:
            for app_id in app_list:
                if '__' in app_id:
                    original_app_id = app_id[:app_id.index('__')]
                else:
                    original_app_id = app_id

                current_app_dict = app_info(app_id,  raw=True)
                new_app_dict     = app_info(original_app_id, raw=True)

                # Custom app
                if 'lastUpdate' not in new_app_dict or 'git' not in new_app_dict:
                    continue

                if (new_app_dict['lastUpdate'] > current_app_dict['lastUpdate']) \
                      or ('update_time' not in current_app_dict['settings'] \
                           and (new_app_dict['lastUpdate'] > current_app_dict['settings']['install_time'])) \
                      or ('update_time' in current_app_dict['settings'] \
                           and (new_app_dict['lastUpdate'] > current_app_dict['settings']['update_time'])):
                    apps.append({
                        'id': app_id,
                        'label': current_app_dict['settings']['label']
                    })
    
    if len(apps) == 0 and len(packages) == 0:
        win_msg(_("There is nothing to upgrade right now"))

    return { 'packages': packages, 'apps': apps }
        

def tools_upgrade(ignore_apps=False, ignore_packages=False):
    """
    Update apps & package cache, then display changelog

    Keyword arguments:
        ignore_apps -- Ignore apps upgrade
        ignore_packages -- Ignore APT packages upgrade

    """
    if not ignore_packages:
        cache = apt.Cache()
        cache.open(None)
        cache.upgrade(True)
        
        # If API call
        if not os.isatty(1):
            critical_packages = ["yunohost-cli", "yunohost-admin", "yunohost-config-nginx", "ssowat", "python", "nginx"]
            for pkg in cache.get_changes():
                if pkg.name in critical_packages:
                    # Temporarily keep package ...
                    pkg.mark_keep()
                    # ... and set a hourly cron up to upgrade critical packages
                    with open('/etc/cron.d/yunohost-upgrade', 'w+') as f:
                        f.write('@hourly apt-get install '+ ' '.join(critical_packages) + ' -y && rm -f /etc/cron.d/yunohost-upgrade')
        try:
            # Apply APT changes
            cache.commit(apt.progress.text.AcquireProgress(), apt.progress.base.InstallProgress())
        except: pass

    if not ignore_apps:
        try:
            app_upgrade()
        except: pass

    win_msg(_("System successfully upgraded"))

    # Return API logs if it is an API call
    if not os.isatty(1):
        return { "log": service_log('yunohost-api', number="100").values()[0] }
