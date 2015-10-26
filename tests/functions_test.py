# -*- coding: utf-8 -*-
from io import StringIO
from ssh_ldap_pubkey import parse_config, parse_config_file
from textwrap import dedent


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
        open_mock = mocker.patch('__builtin__.open', return_value=StringIO(initial_value=content))

        result = {'scope': 'one', 'timelimit': '3'}
        parse_config_mock = mocker.patch('ssh_ldap_pubkey.parse_config', return_value=result)

        assert parse_config_file('/etc/ldap.conf') == result
        open_mock.assert_called_with('/etc/ldap.conf', 'r')
        parse_config_mock.assert_called_with(content)
