from setuptools import setup, find_packages

version = '0.1'

setup(
    name='ckanext-ldap',
    version=version,
    description="LDAP authentication for CKAN",
    long_description='''
    ''',
    classifiers=[], # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
    keywords='',
    author='Toby Dacre',
    author_email='toby.dacre@whythawk.com',
    url='http://github.com/whythawk/ckanext-ldap',
    license='AGPL3.0',
    packages=find_packages(exclude=['ez_setup', 'examples', 'tests']),
    namespace_packages=['ckanext', 'ckanext.ldap'],
    include_package_data=True,
    zip_safe=False,
    install_requires=[
        # -*- Extra requirements: -*-
    ],
    entry_points='''
        [ckan.plugins]
        # Add plugins here, e.g.
        ldap=ckanext.ldap.plugin:LdapPlugin
    ''',
)
