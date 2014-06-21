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

__These config options must be provided:__

`ckanext_ldap.server_url` the ldap server url eg `ldap://ldap_server`

`ckanext_ldap.base_dn` eg `ou=group,dc=example,dc=com`

`ckanext_ldap.search_attr` eg `MyService`

`ckanext_ldap.user_attr` eg `cn=CkanUsers,ou=group,dc=example,dc=com`

`ckanext_ldap.admin_attr` eg `cn=CkanAdmins,ou=group,dc=example,dc=com`

`ckanext_ldap.allow_anon_access` True/False can unlogged in users browse CKAN

__Optional__

`ckanext_ldap.no_auth_message` custom message shown when user has a valid
account but not permission to access CKAN.
