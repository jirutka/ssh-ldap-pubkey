#!/usr/bin/env python
import sys

# Fix encoding problem on Legacy Python.
if sys.version_info < (3, 0):
    reload(sys)
    sys.setdefaultencoding('utf8')

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

try:
    from pypandoc import convert
    read_md = lambda f: convert(f, 'rst')
except ImportError:
    print("warning: pypandoc module not found, could not convert Markdown to RST")
    read_md = lambda f: open(f, 'r').read()


setup(
    name='ssh-ldap-pubkey',
    version='1.1.0',
    url='https://github.com/jirutka/ssh-ldap-pubkey',
    description='Utility to manage SSH public keys stored in LDAP.',
    long_description=read_md('README.md'),
    author='Jakub Jirutka',
    author_email='jakub@jirutka.cz',
    license='MIT',
    packages=['ssh_ldap_pubkey'],
    scripts=['bin/ssh-ldap-pubkey', 'bin/ssh-ldap-pubkey-wrapper'],
    install_requires=[
        'docopt',
        'pyldap'
    ],
    classifiers=[
        'Environment :: Console',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
        'Topic :: System',
        'Topic :: Utilities'
    ]
)
