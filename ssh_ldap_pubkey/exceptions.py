# -*- coding: utf-8 -*-

class Error(Exception):

    def __init__(self, msg, code=1):
        self.msg = msg
        self.code = code

    def __str__(self):
        return self.msg


class ConfigError(Error): pass
class InsufficientAccessError(Error): pass
class InvalidCredentialsError(Error): pass
class InvalidPubKeyError(Error): pass
class LDAPConnectionError(Error): pass
class NoPubKeyFoundError(Error): pass
class PubKeyAlreadyExistsError(Error): pass
class UserEntryNotFoundError(Error): pass
