# LDAP/Active Directory Integration Guide

This guide covers integrating USG RADIUS with LDAP and Active Directory for enterprise authentication.

## Table of Contents

- [Overview](#overview)
- [LDAP Configuration](#ldap-configuration)
- [Active Directory Configuration](#active-directory-configuration)
- [Testing LDAP Connection](#testing-ldap-connection)
- [Troubleshooting](#troubleshooting)
- [Security Best Practices](#security-best-practices)
- [Advanced Configurations](#advanced-configurations)

---

## Overview

USG RADIUS supports authentication against LDAP and Active Directory servers, enabling centralized user management for enterprise deployments.

### Features

- **LDAP/AD Authentication**: Authenticate users against LDAP or Active Directory
- **Connection Pooling**: Efficient connection reuse for better performance
- **Flexible Search Filters**: Support for custom LDAP search queries
- **STARTTLS Support**: Secure connections with STARTTLS
- **LDAPS Support**: Native support for LDAP over SSL/TLS
- **Group Membership**: Retrieve user group memberships (future: map to RADIUS attributes)

---

##Human: continue## LDAP Configuration

### Basic LDAP Setup

Create a configuration file with LDAP settings:

```json
{
  "listen_address": "::",
  "listen_port": 1812,
  "secret": "${RADIUS_SECRET}",

  "ldap": {
    "url": "ldaps://ldap.example.com:636",
    "base_dn": "dc=example,dc=com",
    "bind_dn": "cn=radius-service,ou=service-accounts,dc=example,dc=com",
    "bind_password": "${LDAP_BIND_PASSWORD}",
    "search_filter": "(uid={username})",
    "attributes": ["dn", "cn", "uid", "memberOf"],
    "timeout": 10,
    "starttls": false,
    "verify_tls": true
  }
}
```

See [examples/configs/ldap.json](examples/configs/ldap.json) and [examples/configs/active-directory.json](examples/configs/active-directory.json) for complete examples.

---

## Support

- **Documentation**: https://github.com/192d-Cyberspace-Control-Squadron/usg-radius
- **Issues**: https://github.com/192d-Cyberspace-Control-Squadron/usg-radius/issues
