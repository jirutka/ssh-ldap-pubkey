# -*- coding: utf-8 -*-
from pytest import mark
from os import path
from ssh_ldap_pubkey import is_valid_openssh_pubkey

FIXTURES_DIR = path.dirname(__file__) + '/fixtures'


def describe_is_valid_openssh_pubkey():

    @mark.parametrize('key', read_fixtures('valid_ssh_keys'))
    def returns_true_when_given_valid_pubkey(key):
        assert is_valid_openssh_pubkey(key)

    @mark.parametrize('key', read_fixtures('invalid_ssh_keys'))
    def returns_false_when_given_invalid_pubkey(key):
        assert not is_valid_openssh_pubkey(key)


def read_fixtures(filename):
    with open(path.join(FIXTURES_DIR, filename)) as f:
        return f.readlines()
