OpenSSH / LDAP public keys
==========================
[![Build Status](https://github.com/jirutka/ssh-ldap-pubkey/workflows/CI/badge.svg)](https://github.com/jirutka/ssh-ldap-pubkey/actions?query=workflow%3A%22CI%22)
[![Code Climate](https://codeclimate.com/github/jirutka/ssh-ldap-pubkey/badges/gpa.svg)](https://codeclimate.com/github/jirutka/ssh-ldap-pubkey)
[![version](https://img.shields.io/pypi/v/ssh-ldap-pubkey.svg?style=flat)](https://pypi.python.org/pypi/ssh-ldap-pubkey)

This project provides an utility to manage SSH public keys stored in LDAP and also a script for
OpenSSH server to load authorized keys from LDAP.


Why?
----

When you have dozen of servers it becomes difficult to manage your authorized keys. You have to
copy all your public keys to `~/.ssh/authorized_keys` on every server you want to login to. And
what if you someday change your keys?

It’s a good practice to use some kind of a centralized user management, usually an LDAP server.
There you have user’s login, uid, e-mail, … and password. What if we could also store public SSH
keys on LDAP server? With this utility it’s easy as pie.


Alternatives
------------

If you need just a lightweight utility for OpenSSH server to load authorized keys from LDAP,
then you can use [ssh-getkey-ldap](https://github.com/jirutka/ssh-getkey-ldap) written in Lua
or [this one](https://gist.github.com/jirutka/b15c31b2739a4f3eab63) written in POSIX shell
(but it requires `ldapsearch` utility and may not work well on some systems).


Requirements
------------

* Python 3.6+
* [python-ldap] 3.x
* [docopt] 0.6.x

You can install both Python modules from PyPI.
python-ldap requires additional system dependencies – OpenLDAP.
Refer to [Stack Overflow](http://stackoverflow.com/q/4768446/240963) for distribution-specific information.


Installation
------------

### PyPI:

    pip install ssh-ldap-pubkey

### Alpine Linux

    apk add ssh-ldap-pubkey

Note: The package is currently in the (official) _community_ repository; make sure that you have community in `/etc/apk/repositories`.


Usage
-----

List SSH public keys stored in LDAP for the current user:

    ssh-ldap-pubkey list

List SSH public keys stored in LDAP for the specified user:

    ssh-ldap-pubkey list -u flynn

Add the specified SSH public key for the current user to LDAP:

    ssh-ldap-pubkey add ~/.ssh/id_rsa.pub

Remove SSH public key(s) of the current user that matches the specified pattern:

    ssh-ldap-pubkey del flynn@grid

Specify LDAP URI and base DN on command line instead of configuration file:

    ssh-ldap-pubkey list -b ou=People,dc=encom,dc=com -H ldaps://encom.com -u flynn

As the LDAP manager, add SSH public key to LDAP for the specified user:

    ssh-ldap-pubkey add -D cn=Manager,dc=encom,dc=com -u flynn ~/.ssh/id_rsa.pub

Show help for other options:

    ssh-ldap-pubkey --help


Configuration
-------------

Configuration is read from /etc/ldap.conf — file used by LDAP nameservice switch library and the
LDAP PAM module. An example file is included in [etc/ldap.conf][ldap.conf]. The following subset of
parameters are used:

*  **uri** ... URI(s) of the LDAP server(s) to connect to, separated by a space. The URI scheme may
               be ldap, or ldaps. Default is `ldap://localhost`.
*  **nss_base_passwd** ... distinguished name (DN) of the search base.
*  **base** ... distinguished name (DN) of the search base. Used when *nss_base_passwd* is not set.
*  **scope** ... search scope; _sub_, _one_, or _base_ (default is _sub_).
*  **referrals** ... should client automatically follow referrals returned by LDAP servers (default is _on_)?
*  **pam_filter** ... filter to use when searching for the user’s entry, additional to the login
        attribute value assertion (`pam_login_attribute=<login>`). Default is
        _objectclass=posixAccount_.
*  **pam_login_attribute** ... the user ID attribute (default is _uid_).
*  **ldap_version** ... LDAP version to use (default is 3).
*  **sasl** ... enable SASL and specify mechanism to use (currently only GSSAPI is supported).
*  **binddn** ... distinguished name (DN) to bind when reading the user’s entry (default is to bind
                  anonymously).
*  **bindpw** ... credentials to bind with when reading the user’s entry (default is none).
*  **ssl** ... LDAP SSL/TLS method; _off_, _on_, or _start_tls_. If you use LDAP over SSL (i.e. URI `ldaps://`), leave this empty.
*  **timelimit** ... search time limit in seconds (default is 10).
*  **bind_timelimit** ... bind/connect time limit in seconds (default is 10). If multiple URIs are
                          specified in _uri_, then the next one is tried after this timeout.
*  **tls_cacertdir** ... path of the directory with CA certificates for LDAP server certificate
                         verification.
*  **pubkey_class** ... objectClass that should be added/removed to/from the user’s entry when adding/removing first/last public key and the *pubkey_attr* is mandatory for this class.
   This is needed for the original openssh-lpk.schema (not for the one in this repository).
   Default is `ldapPublicKey`.
*  **pubkey_attr** ... name of LDAP attribute used for SSH public keys (default is `sshPublicKey`).

The only required parameter is *nss_base_passwd* or _base_, others have sensitive defaults. You
might want to define _uri_ parameter as well. These parameters can be also defined/overriden
with `--bind` and `--uri` options on command line.

For more information about these parameters refer to ldap.conf man page.


Set up OpenSSH server
--------------------

To configure OpenSSH server to fetch users’ authorized keys from LDAP server:

1.  Make sure that you have installed **ssh-ldap-pubkey** and **ssh-ldap-pubkey-wrapper** in
    `/usr/bin` with owner `root` and mode `0755`.
2.  Add these two lines to /etc/ssh/sshd_config:

        AuthorizedKeysCommand /usr/bin/ssh-ldap-pubkey-wrapper
        AuthorizedKeysCommandUser nobody

3.  Restart sshd and check log file if there’s no problem.

Note: This method is supported by OpenSSH since version 6.2-p1 (or 5.3 onRedHat). If you have an
older version and can’t upgrade, for whatever weird reason, use [openssh-lpk] patch instead.


Set up LDAP server
------------------

Just add the [openssh-lpk.schema] to your LDAP server, **or** add an attribute named `sshPublicKey`
to any existing schema which is already defined in people entries. That’s all.

Note: Presumably, you’ve already set up your LDAP server for centralized unix users management,
i.e. you have the [NIS schema](http://www.zytrax.com/books/ldap/ape/nis.html) and users in LDAP.


License
-------

This project is licensed under [MIT license](http://opensource.org/licenses/MIT).


[python-ldap]: https://pypi.python.org/pypi/python-ldap/
[docopt]: https://pypi.python.org/pypi/docopt/
[ebuild]: https://github.com/cvut/gentoo-overlay/tree/master/sys-auth/ssh-ldap-pubkey
[cvut-overlay]: https://github.com/cvut/gentoo-overlay
[openssh-lpk]: http://code.google.com/p/openssh-lpk/

[ldap.conf]: https://github.com/jirutka/ssh-ldap-pubkey/blob/master/etc/ldap.conf
[openssh-lpk.schema]: https://github.com/jirutka/ssh-ldap-pubkey/blob/master/etc/openssh-lpk.schema
