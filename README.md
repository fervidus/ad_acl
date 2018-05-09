
# audit_rules
[![License](https://img.shields.io/:license-apache-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0.html)
[![Build Status](https://travis-ci.org/autostructure/ad_acl.svg?branch=master)](https://travis-ci.org/autostructure/ad_acl)
[![Puppet Forge](https://img.shields.io/puppetforge/v/autostructure/ad_acl.svg)](https://forge.puppetlabs.com/autostructure/ad_acl)
[![Puppet Forge Score](https://img.shields.io/puppetforge/f/autostructure/ad_acl.svg)](https://forge.puppetlabs.com/autostructure/ad_acl)
[![Puppet Forge Downloads](https://img.shields.io/puppetforge/dt/autostructure/ad_acl.svg)](https://forge.puppetlabs.com/autostructure/ad_acl)

The ad_acl module supplies a audit_rules resource (via a Puppet custom type provider).

#### Table of Contents

1. [Description](#description)
2. [Setup - The basics of getting started with audit_rules](#setup)
    * [Beginning with audit_rules](#beginning-with-audit_rules)
3. [Usage - Configuration options and additional functionality](#usage)
4. [Reference - An under-the-hood peek at what the module is doing and how](#reference)
5. [Limitations - OS compatibility, etc.](#limitations)
6. [Development - Guide for contributing to the module](#development)

## Description

This module control access control lists for Windows Domain Controllers. Unless you can enforce security rules at a domain level you leave large parts of the Windows environment exposed to attack.

## Setup

### Beginning with audit_rules

The following rule will set basic hardening rules on the root domain.

~~~puppet
ad_acl { "CN=Policies,CN=System,${root_domain}":
  audit_rules  => [
    {
      'ad_rights'        => 'WriteProperty, WriteDacl',
      'identity'         => 'S-1-1-0',
      'audit_flags'      => 'Success',
      'inheritance_type' => 'Descendents',
    },
    {
      'ad_rights'        => 'GenericAll',
      'identity'         => 'S-1-1-0',
      'audit_flags'      => 'Failure',
      'inheritance_type' => 'None',
    },
  ],
  access_rules => [
  {
    'identity'            => 'S-1-5-11',
    'ad_rights'           => 'GenericRead',
    'access_control_type' => 'Allow',
    'inheritance_type'    => 'None'
  },
  {
    'identity'            => 'S-1-5-18',
    'ad_rights'           => 'GenericAll',
    'access_control_type' => 'Allow',
    'inheritance_type'    => 'None'
  },
  {
    'identity'            => "${facts['domain_sid']}-512",
    'ad_rights'           => 'CreateChild, DeleteChild, Self, WriteProperty, ExtendedRight, GenericRead, WriteDacl, WriteOwner',
    'access_control_type' => 'Allow',
    'inheritance_type'    => 'None'
  },
  {
    'identity'            => "${facts['domain_sid']}-520",
    'ad_rights'           => 'CreateChild',
    'access_control_type' => 'Allow',
    'inheritance_type'    => 'None'
  }],
}
~~~

## Usage

A typical ACL is made up of audit rules and access rules. They are each passed in as a hash of hashes.


## Reference

### Defined type: ad_acl

The main type of the module, responsible for all its functionality.

#### Parameters

All of the below parameters are optional, unless otherwise noted.

##### Audit Rules

Each audit_rules item contains four parameters:

- ad_rights
- identity
- audit_flags
- inheritance_type

##### Access rules

Each access_rules item contains 4 parameters:

- identity
- ad_rights
- access_control_type
- inheritance_type

## Limitations

This has only been tested on Windows 2012 and Windows 2016.

## Development

Any contributions are welcome.

## Contributors

Bryan Belanger
