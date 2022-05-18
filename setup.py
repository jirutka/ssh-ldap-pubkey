#!/usr/bin/env python3
import sys
from setuptools import setup

setup(
    name='ssh-ldap-pubkey',
    version='1.3.3',
    url='https://github.com/jirutka/ssh-ldap-pubkey',
    description='Utility to manage SSH public keys stored in LDAP.',
    long_description=open('README.md', 'r').read(),
    long_description_content_type='text/markdown',
    author='Jakub Jirutka',
    author_email='jakub@jirutka.cz',
    license='MIT',
    packages=['ssh_ldap_pubkey'],
    scripts=['bin/ssh-ldap-pubkey', 'bin/ssh-ldap-pubkey-wrapper'],
    install_requires=[
        'docopt>=0.6.2,<0.7.0',
        'python-ldap>=3.0.0,<4'
    ],
    classifiers=[
        'Environment :: Console',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX',
        'Programming Language :: Python :: 3',
        'Topic :: System',
        'Topic :: Utilities'
    ]
)
