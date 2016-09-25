# -*- coding: utf-8 -*-
from io import StringIO
from pytest import mark, raises
from ssh_ldap_pubkey.config import *
from textwrap import dedent
from . import PY3


def describe_parse_config():

    def parses_key_value_separated_by_whitespace():
        content = dedent('''\
            uri  ldap://localhost
            base dc=example, dc=org
            ldap_version\t\t3
        ''')
        expected = {
            'uri': 'ldap://localhost',
            'base': 'dc=example, dc=org',
            'ldap_version': '3'
        }
        assert parse_config(content) == expected

    def strips_trailing_whitespaces():
        content = dedent('''\
            scope base\t
            timelimit 3\t\t
        ''')
        expected = {
            'scope': 'base',
            'timelimit': '3'
        }
        assert parse_config(content) == expected

    def ignores_comments():
        content = dedent('''\
            # The search scope; sub, one, or base.
            scope one
            #timelimit 5
        ''')
        expected = {
            'scope': 'one'
        }
        assert parse_config(content) == expected

    def converts_keys_to_lowercase():
        content = dedent('''\
            ScoPe base
            BASE DC=Example,DC=org
        ''')
        expected = {
            'scope': 'base',
            'base': 'DC=Example,DC=org'
        }
        assert parse_config(content) == expected


def describe_parse_config_file():

    def reads_file_and_calls_parse_config(mocker):
        content = u'scope one\ntimelimit 3\n'
        open_func = 'builtins.open' if PY3 else '__builtin__.open'
        open_mock = mocker.patch(open_func, return_value=StringIO(initial_value=content))

        result = {'scope': 'one', 'timelimit': '3'}
        parse_config_mock = mocker.patch('ssh_ldap_pubkey.config.parse_config', return_value=result)

        assert parse_config_file('/etc/ldap.conf') == result
        open_mock.assert_called_with('/etc/ldap.conf', 'r')
        parse_config_mock.assert_called_with(content)


def describe_parse_tls_reqcert_opt():

    @mark.parametrize('value, expected', [
        ('never',  ldap.OPT_X_TLS_NEVER),
        ('allow',  ldap.OPT_X_TLS_ALLOW),
        ('try',    ldap.OPT_X_TLS_TRY),
        ('demand', ldap.OPT_X_TLS_DEMAND),
        ('hard',   ldap.OPT_X_TLS_HARD),
    ])
    def returns_ldap_OPT_X_TLS_constant_for_valid_value(value, expected):
        assert parse_tls_reqcert_opt(value) == expected
        assert parse_tls_reqcert_opt(value.upper()) == expected

    @mark.parametrize('value', [None, ''])
    def returns_None_when_given_falsy(value):
        assert parse_tls_reqcert_opt(value) is None

    def raises_KeyError_for_invalud_value():
        with raises(KeyError):
            parse_tls_reqcert_opt('whatever')


def describe_parse_scope_opt():

    @mark.parametrize('value, expected', [
        ('base', ldap.SCOPE_BASE),
        ('one',  ldap.SCOPE_ONELEVEL),
        ('sub',  ldap.SCOPE_SUBTREE)
    ])
    def returns_ldap_SCOPE_constant_for_valid_value(value, expected):
        assert parse_scope_opt(value) == expected
        assert parse_scope_opt(value.upper()) == expected

    @mark.parametrize('value', [None, ''])
    def returns_None_when_given_falsy(value):
        assert parse_scope_opt(value) is None

    def raises_KeyError_for_invalud_value():
        with raises(KeyError):
            parse_scope_opt('whatever')
