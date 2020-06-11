# -*- coding: utf-8 -*-
from __future__ import absolute_import, print_function

import base64
import ldap
import re
import struct
import sys

from datetime import date, datetime, timedelta
from .exceptions import *


VERSION = (1, 3, 2)
__version__ = VERSION
__versionstr__ = '.'.join(map(str, VERSION))

BAD_REQCERT_WARNING = u'''
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!! WARNING: You've choosen to ignore TLS errors such as invalid certificate. !!
!! This is a VERY BAD thing, never ever use this in production! ᕦ(ò_óˇ)ᕤ     !!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
'''


def keyname(pubkey):
    return "_".join(pubkey.split()[2:])


def is_valid_openssh_pubkey(pubkey):
    """Check if the given string is a valid OpenSSH public key.

    This function is based on http://stackoverflow.com/a/2494645/2217862.

    Arguments:
        pubkey (str): The string to validate.
    Returns:
        bool: `True` if the given string is a valid key, `False` otherwise.
    """
    try:
        key_type, data64 = map(_encode, pubkey.split()[0:2])
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


def _decode(input):
    return input.decode('utf8')


def _encode(input):
    return input.encode('utf8')


def _decode_all(input):
    if isinstance(input, dict):
        return {_decode_all(key): _decode_all(value)
                for key, value in input.items()}
    elif isinstance(input, list):
        return [_decode_all(element) for element in input]
    elif not isinstance(input, (str)):
        return _decode(input)
    else:
        return input


def _parse_expiration(s):
    return datetime.strptime(s, '%Y-%m-%d').date()


def _calc_expiration(days):
    expire = date.today() + timedelta(days=days)
    return expire.strftime('%Y-%m-%d')


def _find_expiration(s):
    m = re.search(r'expire=(\d{4}-\d{2}-\d{2})', s)
    if m:
        return _parse_expiration(m.group(1))
    return None


def _update_expiration(s, days):
    return re.sub(r'expire=\d{4}-\d{2}-\d{2}', "expire=%s" % _calc_expiration(days), s)


def _add_expiration(pubkey, days):
    fields = pubkey.split()
    expiration = 'expire=%s' % _calc_expiration(days)

    if len(fields) == 2:
        return ' '.join([pubkey, expiration])

    comment = pubkey.split(' ', 2)[-1]
    if _find_expiration(comment) is not None:
        return _update_expiration(pubkey, days)

    return '%s %s' % (pubkey, expiration)


class LdapSSH(object):

    def __init__(self, conf):
        """Initialize new LdapSSH instance.

        Arguments:
            conf (LdapConfig): The LDAP configuration.
        """
        self.conf = conf
        self._conn = None

    def connect(self):
        """Connect to the LDAP server.
        This method must be called before any other methods of this object.

        Raises:
            ConfigError: If Base DN or LDAP URI is missing in the config.
            LDAPConnectionError: If can't connect to the LDAP server.
            ldap.LDAPError:
        """
        conf = self.conf

        if not conf.uris or not conf.base:
            raise ConfigError('Base DN and LDAP URI(s) must be provided.', 1)

        if conf.tls_require_cert:
            if conf.tls_require_cert not in [ldap.OPT_X_TLS_DEMAND, ldap.OPT_X_TLS_HARD]:
                print(BAD_REQCERT_WARNING, file=sys.stderr)
            # this is a global option!
            ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, conf.tls_require_cert)

        if conf.cacert_dir:
            # this is a global option!
            ldap.set_option(ldap.OPT_X_TLS_CACERTDIR, conf.cacert_dir)

        if not conf.referrals:
            # this is a global option!
            ldap.set_option(ldap.OPT_REFERRALS, 0)

        # NOTE: The uri argument is passed directly to the underlying openldap
        # library that allows multiple URIs separated by a space for failover.
        self._conn = conn = ldap.initialize(' '.join(conf.uris))
        try:
            conn.protocol_version = conf.ldap_version
            conn.network_timeout = conf.bind_timeout
            conn.timeout = conf.search_timeout

            if conf.sasl == 'GSSAPI':
                self._bind_sasl_gssapi()
                return

            if conf.ssl == 'start_tls' and conf.ldap_version >= 3:
                conn.start_tls_s()

            if conf.bind_dn and conf.bind_pass:
                self._bind(conf.bind_dn, conf.bind_pass)
        except ldap.SERVER_DOWN:
            raise LDAPConnectionError('Can\'t contact LDAP server.', 3)

    def close(self):
        """Unbind from the LDAP server."""
        self._conn and self._conn.unbind_s()

    def add_pubkey(self, login, password, pubkey, update=False):
        """Add SSH public key to the user with the given ``login``.

        Arguments:
            login (str): Login of the user to add the ``pubkey``.
            password (Optional[str]): The user's password to bind with, or None
                to not (re)bind with the user's credentials.
            pubkey (str): The public key to add.
            update (bool): if `True`, update the expiration date of a pubkey if it already
                exists.
        Raises:
            InvalidPubKeyError: If the ``pubkey`` is invalid.
            PubKeyAlreadyExistsError: If the user already has the given ``pubkey``.
            UserEntryNotFoundError: If the ``login`` is not found.
            ConfigError: If LDAP server doesn't define schema for the attribute specified
                in the config.
            InsufficientAccessError: If the bind user doesn't have rights to add the pubkey.
            ldap.LDAPError:
        """
        conf = self.conf

        if not is_valid_openssh_pubkey(pubkey):
            raise InvalidPubKeyError('Invalid key, not in OpenSSH Public Key format.', 1)

        dn = self.find_dn_by_login(login)
        if password:
            self._bind(dn, password)

        if not update and self._has_pubkey(dn, pubkey):
            raise PubKeyAlreadyExistsError(
                "Public key %s already exists." % keyname(pubkey), 1)

        self._add_pubkey(dn, pubkey, conf.expire)

    def sync_pubkeys(self, login, password, synckeys):
        """Sync SSH public keys to the user with the given ``login``.

        Arguments:
            login (str): Login of the user to add the ``pubkey``.
            password (Optional[str]): The user's password to bind with, or None
                to not (re)bind with the user's credentials.
            synckeys (List[str]): The public keys to sync.
        Raises:
            InvalidPubKeyError: If the ``pubkey`` is invalid.
            UserEntryNotFoundError: If the ``login`` is not found.
            ConfigError: If LDAP server doesn't define schema for the attribute specified
                in the config.
            InsufficientAccessError: If the bind user doesn't have rights to add the pubkey.
            ldap.LDAPError:
        """
        conf = self.conf

        for key in synckeys.splitlines():
            if not is_valid_openssh_pubkey(key):
                raise InvalidPubKeyError('Invalid key, not in OpenSSH Public Key format.', 1)

        dn = self.find_dn_by_login(login)
        if password:
            self._bind(dn, password)

        # grab stored pubkeys and valid pubkeys subset
        valid_pubkeys = []
        pubkeys = list(self._find_pubkeys(dn))
        if pubkeys:
            valid_pubkeys = self._filter(pubkeys, validity="valid", expire=None)

        # split synckeys in two groups:
        # - keys already stored in LDAP
        # - keys that need to be added
        keys_already_present = []
        keys_to_add = []
        for ukey in synckeys.splitlines():
            rawkey = ukey.split()[1]
            keys = [key for key in pubkeys if rawkey in key]
            if keys:
                keys_already_present += keys
            else:
                keys_to_add.append(ukey)

        # total amount of valid keys could be checked here before proceeding

        # add new keys
        for key in keys_to_add:
            self._add_pubkey(dn, key, self.conf.expire)
            print("Key has been added: %s" % keyname(key))

        # log already present entries
        for key in keys_already_present:
            print("Key already stored: %s" % keyname(key))

        # expire/remove valid keys no longer in the user authorized_keys
        for ukey in set(valid_pubkeys) - set(keys_already_present):
            self._remove_pubkey(dn, ukey)
            if conf.purge or _find_expiration(ukey) is None:
                print("Key has been removed: %s" % keyname(ukey))
            else:
                self._add_pubkey(dn, ukey, expire=-1)
                print("Key has been expired: %s" % keyname(ukey))

        # ignore/remove stored keys (not being considered as valid)
        for ukey in set(pubkeys) - set(valid_pubkeys):
            if conf.purge or _find_expiration(ukey) is None:
                self._remove_pubkey(dn, ukey)
                print("Key has been removed: %s" % keyname(ukey))

    def find_and_update_pubkey(self, login, password, ukey):
        """Find and update public keys of the user with ``login`` that have the same raw key as
            ``ukey``.

        Arguments:
            login (str): Login of the user to add the ``pubkey``.
            password (Optional[str]): The user's password to bind with, or None
                to not (re)bind with the user's credentials.
            ukey (str): The key to be updated.
        Raises:
            UserEntryNotFoundError: If the ``login`` is not found.
            InsufficientAccessError: If the bind user doesn't have rights to add the pubkey.
            ldap.LDAPError:
        Returns:
            List[str]: A list of removed public keys.
        """
        dn = self.find_dn_by_login(login)
        if password:
            self._bind(dn, password)

        rawkey = ukey.split()[1]
        pubkeys = [key for key in self._find_pubkeys(dn) if rawkey in key]
        try:
            self.add_pubkey(login, password, ukey, True)
        except PubKeyAlreadyExistsError:
            # in case we are updating with the exact same key (& expiration)
            # just return in order to avoid removing what we want to add
            return []
        for key in pubkeys:
            self._remove_pubkey(dn, key)

        return pubkeys

    def find_and_remove_pubkeys(self, login, password, pattern):
        """Find and remove public keys of the user with the ``login`` that maches the ``pattern``.

        Arguments:
            login (str): Login of the user to add the ``pubkey``.
            password (Optional[str]): The user's password to bind with, or None
                to not (re)bind with the user's credentials.
            pattern (str): The pattern specifying public keys to be removed.
                '*' means all public keys (wildcard).
        Raises:
            UserEntryNotFoundError: If the ``login`` is not found.
            NoPubKeyFoundError: If no public key matching the ``pattern`` is found.
            InsufficientAccessError: If the bind user doesn't have rights to add the pubkey.
            ldap.LDAPError:
        Returns:
            List[str]: A list of removed public keys.
        """
        dn = self.find_dn_by_login(login)
        if password:
            self._bind(dn, password)

        pubkeys = [key for key in self._find_pubkeys(dn) if pattern == '*' or pattern in key]
        for key in pubkeys:
            self._remove_pubkey(dn, key)

        return pubkeys

    def find_pubkeys(self, login):
        """Return public keys of the user with the given ``login``.

        Arguments:
            login (str): The login name of the user.
        Returns:
            List[str]: A list of public keys.
        Raises:
            UserEntryNotFoundError: If the ``login`` is not found.
            ldap.LDAPError:
        """
        conf = self.conf
        pubkeys = self._find_pubkeys(self.find_dn_by_login(login))

        if conf.validity != 'all':
            return self._filter(pubkeys, validity=conf.validity,
                                expire=conf.expire)

        return pubkeys

    def find_all_pubkeys(self):
        """Return public keys of all users.

        Returns:
            List[str]: A list of public keys.
        Raises:
            ldap.LDAPError:
        """
        conf = self.conf
        elements = self._find_all_pubkeys()

        if conf.validity != 'all':
            for e in elements:
                e[conf.pubkey_attr] = self._filter(e[conf.pubkey_attr],
                                                   validity=conf.validity,
                                                   expire=conf.expire)
            return [e for e in elements if len(e[conf.pubkey_attr]) != 0]

        return elements

    def find_dn_by_login(self, login):
        """Returns Distinguished Name (DN) of the user with the given ``login``.

        Arguments:
            login (str): The login name of the user to find.
        Returns:
            str: User's DN.
        Raises:
            UserEntryNotFoundError: If the ``login`` is not found.
            ldap.LDAPError:
        """
        conf = self.conf
        filter_s = conf.filter
        # RFC4515 requires filters to be wrapped with parenthesis '(' and ')'.
        # Over-wrapped filters are invalid! e.g. '((uid=x))'
        #
        # OpenLDAP permits simple filters to omit parenthesis entirely:
        # e.g. 'uid=x' is automatically treated as '(uid=x)'
        #
        # The OpenLDAP behavior is taken as a given in many uses, which can
        # lead to bad assumptions merging filters, because over-wrapped filters
        # ARE still rejected.
        #
        # To cope with these cases, only wrap the incoming filter in
        # parenthesis if it does NOT already have them.
        if filter_s[0] != '(':
            filter_s = '(%s)' % filter_s
        filter_s = "(&%s(%s=%s))" % (filter_s, conf.login_attr, login)

        result = self._conn.search_s(conf.base, conf.scope, filter_s, ['dn'])
        if not result:
            raise UserEntryNotFoundError("No user with login '%s' found." % login, 2)

        return result[0][0]

    def _bind(self, dn, password):
        try:
            self._conn.simple_bind_s(dn, password)
        except ldap.INVALID_CREDENTIALS:
            raise InvalidCredentialsError("Invalid credentials for %s." % dn, 2)

    def _bind_sasl_gssapi(self):
        self._conn.sasl_interactive_bind_s('', ldap.sasl.sasl({}, 'GSSAPI'))

    def _filter(self, pubkeys, validity=None, expire=None):
        filtered = []
        day = today = date.today()
        if expire is not None:
            day += timedelta(expire)
        for key in pubkeys:
            expiration = _find_expiration(key)
            if validity == 'invalid' and (expiration is None):
                filtered.append(key)
            elif validity == 'expired' and (expiration is not None and day > expiration):
                filtered.append(key)
            elif validity == 'valid' and (expiration is not None and day <= expiration):
                filtered.append(key)
            elif validity == 'expire' and (
                expiration is not None and expiration >= today and day > expiration
            ):
                filtered.append(key)

        return filtered

    def _find_pubkeys(self, dn):
        conf = self.conf
        result = self._conn.search_s(
            dn, ldap.SCOPE_BASE, attrlist=[conf.pubkey_attr])

        return map(_decode, result[0][1].get(conf.pubkey_attr, []))

    def _find_all_pubkeys(self):
        conf = self.conf
        result = self._conn.search_s(
            conf.base, ldap.SCOPE_SUBTREE, '(%s=*)' % conf.pubkey_attr, conf.attrs)

        return _decode_all([r[1] for r in result])

    def _has_pubkey(self, dn, pubkey):
        current = self._find_pubkeys(dn)
        is_same_key = lambda k1, k2: k1.split()[1] == k2.split()[1]

        return any(key for key in current if is_same_key(key, pubkey))

    def _remove_pubkey(self, dn, pubkey):
        conf = self.conf

        modlist = [(ldap.MOD_DELETE, conf.pubkey_attr, _encode(pubkey))]
        try:
            self._conn.modify_s(dn, modlist)

        except ldap.OBJECT_CLASS_VIOLATION:
            modlist += [(ldap.MOD_DELETE, 'objectClass', _encode(conf.pubkey_class))]
            self._conn.modify_s(dn, modlist)

        except ldap.NO_SUCH_ATTRIBUTE:
            raise NoPubKeyFoundError("No such public key exists: %s." % keyname(pubkey), 1)

        except ldap.INSUFFICIENT_ACCESS:
            raise InsufficientAccessError("No rights to remove key for %s " % dn, 2)

    def _add_pubkey(self, dn, pubkey, expire):
        conf = self.conf

        if expire is not None:
            pubkey = _add_expiration(pubkey, expire)

        modlist = [(ldap.MOD_ADD, conf.pubkey_attr, _encode(pubkey))]
        try:
            self._conn.modify_s(dn, modlist)

        except ldap.OBJECT_CLASS_VIOLATION:
            modlist += [(ldap.MOD_ADD, 'objectClass', _encode(conf.pubkey_class))]
            self._conn.modify_s(dn, modlist)

        except ldap.TYPE_OR_VALUE_EXISTS:
            raise PubKeyAlreadyExistsError(
                "Public key %s already exists while adding it." % keyname(pubkey), 1)

        except ldap.UNDEFINED_TYPE:
            raise ConfigError(
                "LDAP server doesn't define schema for attribute: %s" % conf.pubkey_attr, 1)

        except ldap.INSUFFICIENT_ACCESS:
            raise InsufficientAccessError("No rights to add key for %s " % dn, 2)
