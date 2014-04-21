OpenSSH / LDAP public keys
==========================

This project provides an utility to manage SSH public keys stored in LDAP and also a script for
OpenSSH server to load authorized keys from LDAP.

Why?
----

When you have dozen of servers it becomes difficult to manage your authorized keys. You have to
copy each of your public key to `~/.ssh/authorized_keys` on each of the server you want to login to
using your SSH key. And what if you someday change your keys?

It’s a good practice to use some kind of centralized users database, mostly a LDAP server. There
you have user’s login, uid, e-mail, … and password. Wouldn’t it be great to have there also public
SSH keys? Yeah! And that’s this project about.


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

    ssh-ldap-pubkey list -b ou=People,dc=encom,dc=com -h ldaps://encom.com -u flynn

Show help for other options:

    ssh-ldap-pubkey --help


Configuration
-------------

Configuration is read from /etc/ldap.conf — file used by LDAP nameservice switch library and the
LDAP PAM module. An example file is included in [etc/ldap.conf][ldap.conf]. The following subset of
parameters are used:

*  **uri** ... URI of the LDAP server to connect to. The URI scheme may be ldap, or ldaps.
               Default is ldap://localhost.
*  **nss_base_passwd** ... distinguished name (DN) of the search base.
*  **base** ... distinguished name (DN) of the search base. Used when *nss_base_passwd* is not set.
*  **scope** ... search scope; _sub_, _one_, or _base_ (default is _sub_).
*  **pam_filter** ... filter to use when searching for the user’s entry, additional to the login
        attribute value assertion (`pam_login_attribute=<login>`). Default is
        _objectclass=posixAccount_.
*  **pam_login_attribute** ... the user ID attribute (default is _uid_).
*  **ldap_version** ... LDAP version to use (default is 3).
*  **binddn** ... distinguished name (DN) to bind when reading the user’s entry (default is to bind
*                 anonymously).
*  **bindpw** ... credentials to bind with when reading the user’s entry (default is none).
*  **timelimit** ... search time limit in seconds (default is 10).
*  **bind_timelimit** ... bind/connect time limit in seconds (default is 10).

The only required parameter is *nss_base_passwd* or _base_, others has sensitive defaults. You
might want to define _uri_ parameter as well. These parameter can be also defined/overriden
with `--bind` and `--uri` option on command line.

For more information about these parameters refer to ldap.conf man page.


Setup OpenSSH server
--------------------

To configure OpenSSH server to fetch users’ authorized keys from LDAP server:

1.  Copy [ssh-ldap-pubkey] and [ssh-ldap-pubkey-wrapper] to /usr/bin with owner root and mode 0755.
2.  Add these two lines to /etc/ssh/sshd_config:

        AuthorizedKeysCommand /usr/bin/ssh-ldap-wrapper
        AuthorizedKeysCommandUser nobody
3.  Restart sshd and check log file if there’s no problem.

Note: This method is supported by OpenSSH since version 6.2-p1 (or 5.3 onRedHat). If you have an
older version and can’t upgrade, for whatever weird reason, then use [openssh-lpk] patch instead.


Setup LDAP server
------------------

Just add a new schema [openssh-lpk.schema] to your LDAP server. That’s all.

Note: I suppose that you’ve already setup your LDAP server for centralized unix users management,
i.e. you have the [NIS schema](http://www.zytrax.com/books/ldap/ape/nis.html) and users in LDAP.


Requirements
------------

1. Python ≥2.5 *
2. [python-ldap]
3. [docopt]

_* I’m sorry, but this script doesn’t work with Python 3 (yet) due to python-ldap library._


License
-------

This project is licensed under [MIT license](http://opensource.org/licenses/MIT).


[openssh-lpk]: http://code.google.com/p/openssh-lpk/
[python-ldap]: https://pypi.python.org/pypi/python-ldap/
[docopt]: https://pypi.python.org/pypi/docopt/

[ssh-ldap-pubkey]: bin/ssh-ldap-pubkey
[ssh-ldap-pubkey-wrapper]: bin/ssh-ldap-pubkey-wrapper
[ldap.conf]: etc/ldap.conf
[openssh-lpk.schema]: etc/openssh-lpk.schema