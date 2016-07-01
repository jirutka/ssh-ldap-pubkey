# -*- coding: utf-8 -*-
from __future__ import absolute_import, print_function

import base64
import ldap
import struct
import sys

from .exceptions import *


VERSION = (1, 0, 0)
__version__ = VERSION
__versionstr__ = '.'.join(map(str, VERSION))

LDAP_PUBKEY_CLASS = 'ldapPublicKey'
LDAP_PUBKEY_ATTR = 'sshPublicKey'

BAD_REQCERT_WARNING = u'''
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!! WARNING: You've choosen to ignore TLS errors such as invalid certificate. !!
!! This is a VERY BAD thing, never ever use this in production! ᕦ(ò_óˇ)ᕤ     !!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
'''


def keyname(pubkey):
    return pubkey.split()[-1]


def is_valid_openssh_pubkey(pubkey):
    """ Check if the given string is a valid OpenSSH public key.

    This function is based on http://stackoverflow.com/a/2494645/2217862.

    Arguments:
        pubkey (str): The string to validate.
    Returns:
        bool: `True` if the given string is a valid key, `False` otherwise.
    """
    try:
        key_type, data64 = pubkey.split()[0:2]
    except (ValueError, AttributeError):
        return False
    try:
        data = base64.decodestring(data64)
    except base64.binascii.Error:
        return False

    int_len = 4
    str_len = struct.unpack('>I', data[:int_len])[0]

    if data[int_len:(int_len + str_len)] != key_type:
        return False

    return True


class LdapSSH(object):

    def __init__(self, conf):
        self.conf = conf
        self._conn = None

    def connect(self):
        conf = self.conf

        if not conf.uri or not conf.base:
            raise ConfigError("Base DN and LDAP URI must be provided.", 1)

        if conf.tls_require_cert:
            if conf.tls_require_cert not in [ldap.OPT_X_TLS_DEMAND, ldap.OPT_X_TLS_HARD]:
                print(BAD_REQCERT_WARNING, file=sys.stderr)
            # this is a global option!
            ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, conf.tls_require_cert)

        if conf.cacert_dir:
            # this is a global option!
            ldap.set_option(ldap.OPT_X_TLS_CACERTDIR, conf.cacert_dir)

        self._conn = conn = ldap.initialize(conf.uri)
        try:
            conn.protocol_version = conf.ldap_version
            conn.network_timeout = conf.bind_timeout
            conn.timeout = conf.search_timeout

            if conf.ssl == 'start_tls' and conf.ldap_version >= 3:
                conn.start_tls_s()

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
