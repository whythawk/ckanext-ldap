LDAP authentication for CKAN
============================

This extension brings LDAP authentication to ckan replacing the
built in ckan authentication.


Requirements
------------

python-ldap must be installed and available in the CKAN pyenv.


Configuration
-------------

`ldap` needs adding to the list of `ckan.plugins`

These config options must be provided:

`ckanext_ldap.server_url` the ldap server url eg `ldap://ldap_server`

`ckanext_ldap.base_dn` eg `ou=group,dc=example,dc=com`

`ckanext_ldap.search_attr` eg `MyService`

`ckanext_ldap.user_attr` eg `cn=CkanUsers`

`ckanext_ldap.admin_attr` eg `cn=CkanAdmins`

`ckanext_ldap.allow_anon_access` True/False can unlogged in users browse CKAN
