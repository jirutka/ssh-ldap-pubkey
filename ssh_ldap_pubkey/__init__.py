# -*- coding: utf-8 -*-
from __future__ import absolute_import

import base64
import ldap
import re
import struct
import sys

from .exceptions import *


VERSION = (1, 0, 0)
__version__ = VERSION
__versionstr__ = '.'.join(map(str, VERSION))

DEFAULT_HOST = 'localhost'
DEFAULT_PORT = 389
DEFAULT_TIMEOUT = 10
DEFAULT_LOGIN_ATTR = 'uid'
DEFAULT_FILTER = 'objectclass=posixAccount'
DEFAULT_SCOPE = 'sub'

LDAP_PUBKEY_CLASS = 'ldapPublicKey'
LDAP_PUBKEY_ATTR = 'sshPublicKey'


def keyname(pubkey):
    return pubkey.split()[-1]


def is_valid_openssh_pubkey(pubkey):
    """ Validation based on http://stackoverflow.com/a/2494645/2217862. """
    if not pubkey and len(pubkey.split()) < 2:
        return False

    key_type, data64 = pubkey.split()[0:2]
    try:
        data = base64.decodestring(data64)
    except base64.binascii.Error:
        return False

    int_len = 4
    str_len = struct.unpack('>I', data[:int_len])[0]

    if data[int_len:(int_len + str_len)] != key_type:
        return False

    return True


def parse_config_file(path):
    conf = {}
    with open(path, 'r') as f:
        for line in f:
            m = re.match(r'^(\w+)\s+([^#]+\b)', line)
            if m: conf[m.group(1).lower()] = m.group(2)
    return conf


class LdapSSH(object):

    def __init__(self, conf):
        self.conf = conf
        self._conn = None

    def connect(self):
        conf = self.conf

        if not conf.uri or not conf.base:
            raise ConfigError("Base DN and LDAP URI must be provided.", 1)

        if conf.cacert_dir:
            # this is a global option!
            ldap.set_option(ldap.OPT_X_TLS_CACERTDIR, conf.cacert_dir)

        self._conn = conn = ldap.initialize(conf.uri)
        try:
            conn.protocol_version = conf.ldap_version
            conn.network_timeout = conf.bind_timeout
            conn.timeout = conf.search_timeout

            if conf.bind_dn and conf.bind_pass:
                self._bind(conf.bind_dn, conf.bind_pass)
        except ldap.SERVER_DOWN:
            raise LDAPConnectionError("Can't contact LDAP server.", 3)

    def close(self):
        self._conn and self._conn.unbind_s()

    def add_pubkey(self, login, password, pubkey):
        if not is_valid_openssh_pubkey(pubkey):
            raise InvalidPubKeyError("Invalid key, not in OpenSSH Public Key format.", 1)

        dn = self.find_dn_by_login(login)
        if password:
            self._bind(dn, password)

        if self._has_pubkey(dn, pubkey):
            raise PubKeyAlreadyExistsError(
                "Public key %s already exists." % keyname(pubkey), 1)

        modlist = [(ldap.MOD_ADD, LDAP_PUBKEY_ATTR, pubkey)]
        try:
            self._conn.modify_s(dn, modlist)

        except ldap.OBJECT_CLASS_VIOLATION:
            modlist += [(ldap.MOD_ADD, 'objectClass', LDAP_PUBKEY_CLASS)]
            self._conn.modify_s(dn, modlist)

        except ldap.UNDEFINED_TYPE:
            raise ConfigError(
                "LDAP server doesn't define schema for attribute: %s" % LDAP_PUBKEY_ATTR, 1)

        except ldap.INSUFFICIENT_ACCESS:
            raise InsufficientAccessError("No rights to add key for %s " % dn, 2)

    def find_and_remove_pubkeys(self, login, password, pattern):
        dn = self.find_dn_by_login(login)
        if password:
            self._bind(dn, password)

        pubkeys = [key for key in self._find_pubkeys(dn) if pattern in key]
        for key in pubkeys:
            self._remove_pubkey(dn, key)

        return pubkeys

    def find_pubkeys(self, login):
        return self._find_pubkeys(self.find_dn_by_login(login))

    def find_dn_by_login(self, login):
        conf = self.conf
        filter_s = "(&(%s)(%s=%s))" % (conf.filter, conf.login_attr, login)

        result = self._conn.search_s(conf.base, conf.scope, filter_s, ['dn'])
        if not result:
            raise UserEntryNotFoundError("No user with login '%s' found." % login, 2)

        return result[0][0]

    def _bind(self, dn, password):
        try:
            self._conn.simple_bind_s(dn, password)
        except ldap.INVALID_CREDENTIALS:
            raise InvalidCredentialsError("Invalid credentials for %s." % dn, 2)

    def _find_pubkeys(self, dn):
        result = self._conn.search_s(
            dn, ldap.SCOPE_BASE, attrlist=[LDAP_PUBKEY_ATTR])

        return result[0][1].get(LDAP_PUBKEY_ATTR, [])

    def _has_pubkey(self, dn, pubkey):
        current = self._find_pubkeys(dn)
        is_same_key = lambda k1, k2: k1.split()[1] == k2.split()[1]

        return any(key for key in current if is_same_key(key, pubkey))

    def _remove_pubkey(self, dn, pubkey):
        modlist = [(ldap.MOD_DELETE, LDAP_PUBKEY_ATTR, pubkey)]
        try:
            self._conn.modify_s(dn, modlist)

        except ldap.OBJECT_CLASS_VIOLATION:
            modlist += [(ldap.MOD_DELETE, 'objectClass', LDAP_PUBKEY_CLASS)]
            self._conn.modify_s(dn, modlist)

        except ldap.NO_SUCH_ATTRIBUTE:
            raise NoPubKeyFoundError("No such public key exists: %s." % keyname(pubkey), 1)

        except ldap.INSUFFICIENT_ACCESS:
            raise InsufficientAccessError("No rights to remove key for %s " % dn, 2)


class LdapConfig(object):

    def __init__(self, path):
        conf = parse_config_file(path) if path else {}

        if 'uri' in conf:
            self.uri = conf['uri'].split()[0]  # use just first address for now
        else:
            host = conf.get('host', DEFAULT_HOST)
            port = conf.get('port', DEFAULT_PORT)
            self.uri = "ldap://%s:%s" % (host, port)

        self.base = conf.get('nss_base_passwd', '').split('?')[0] or conf.get('base', None)
        self.bind_dn = conf.get('binddn', None)
        self.bind_pass = conf.get('bindpw', None)
        self.ldap_version = int(conf.get('ldap_version', ldap.VERSION3))
        self.bind_timeout = int(conf.get('bind_timelimit', DEFAULT_TIMEOUT))
        self.search_timeout = int(conf.get('timelimit', DEFAULT_TIMEOUT))
        self.login_attr = conf.get('pam_login_attribute', DEFAULT_LOGIN_ATTR)
        self.filter = conf.get('pam_filter', DEFAULT_FILTER)
        self.cacert_dir = conf.get('tls_cacertdir', None)

        self.scope = {
            'base': ldap.SCOPE_BASE,
            'one': ldap.SCOPE_ONELEVEL,
            'sub': ldap.SCOPE_SUBTREE
        }[conf.get('scope', DEFAULT_SCOPE)]

    def __str__(self):
        return str(self.__dict__)
