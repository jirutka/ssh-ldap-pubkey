# -*- coding: utf-8 -*-
import ldap
import re

DEFAULT_HOST = 'localhost'
DEFAULT_PORT = 389
DEFAULT_TIMEOUT = 10
DEFAULT_LOGIN_ATTR = 'uid'
DEFAULT_FILTER = 'objectclass=posixAccount'
DEFAULT_SCOPE = 'sub'


def parse_config(content):
    """Parse configuration options into a dict.

    Blank lines are ignored. Lines beginning with a hash mark (`#`) are comments, and ignored.
    Valid lines are made of an option's name (a sequence of non-blanks), followed by a value.
    The value starts with the first non-blank character after the option's name, and terminates at
    the end of the line, or at the last sequence of blanks before the end of the line.
    Option names are case-insensitive, and converted to lower-case.

    Arguments:
        content (str): The content of a configuration file to parse.
    Returns:
        dict: Parsed options.
    """
    return {
        match.group(1).lower(): match.group(2)
        for match in (
            re.match(r'^(\w+)\s+([^#]+\b)', line)
            for line in content.splitlines()
        ) if match
    }


def parse_config_file(path):
    """Same as :func:`parse_config`, but read options from a file.

    Arguments:
        path (str): Path of the file to read and parse.
    Returns:
        dict: Parsed options.
    """
    with open(path, 'r') as f:
        return parse_config(f.read())


def parse_tls_reqcert_opt(value):
    """Convert `tls_reqcert` option to ldap's `OPT_X_TLS_*` constant."""
    return {
        'never': ldap.OPT_X_TLS_NEVER,
        'allow': ldap.OPT_X_TLS_ALLOW,
        'try': ldap.OPT_X_TLS_TRY,
        'demand': ldap.OPT_X_TLS_DEMAND,
        'hard': ldap.OPT_X_TLS_HARD
    }[value.lower()] if value else None


def parse_scope_opt(value):
    """Convert `scope` option to ldap's `SCOPE_*` constant."""
    return {
        'base': ldap.SCOPE_BASE,
        'one': ldap.SCOPE_ONELEVEL,
        'sub': ldap.SCOPE_SUBTREE
    }[value.lower()] if value else None


class LdapConfig(object):

    def __init__(self, path):
        """Initialize new LdapConfig with options parsed from config file on the ``path``.

        Arguments:
            path (Optional[path]): Path to the config file to read and parse.
                If not provided, then empty config is initialized.
        """
        conf = parse_config_file(path) if path else {}

        if 'uri' in conf:
            self.uris = conf['uri']
        else:
            host = conf.get('host', DEFAULT_HOST)
            port = conf.get('port', DEFAULT_PORT)
            self.uris = ["ldap://%s:%s" % (host, port)]

        self.base = conf.get('nss_base_passwd', '').split('?')[0] or conf.get('base', None)
        self.bind_dn = conf.get('binddn', None)
        self.bind_pass = conf.get('bindpw', None)
        self.ssl = conf.get('ssl', None)
        self.ldap_version = int(conf.get('ldap_version', ldap.VERSION3))
        self.bind_timeout = int(conf.get('bind_timelimit', DEFAULT_TIMEOUT))
        self.search_timeout = int(conf.get('timelimit', DEFAULT_TIMEOUT))
        self.login_attr = conf.get('pam_login_attribute', DEFAULT_LOGIN_ATTR)
        self.filter = conf.get('pam_filter', DEFAULT_FILTER)
        self.cacert_dir = conf.get('tls_cacertdir', None)
        self.tls_require_cert = parse_tls_reqcert_opt(conf.get('tls_reqcert'))
        self.scope = parse_scope_opt(conf.get('scope', DEFAULT_SCOPE))

    @property
    def uri(self):  # for backward compatibility with <1.1.0
        return self.uris[0] if self.uris else None

    @uri.setter
    def uri(self, uri):  # for backward compatibility with <1.1.0
        self.uris = [uri] if uri else None

    def __str__(self):
        return str(self.__dict__)
