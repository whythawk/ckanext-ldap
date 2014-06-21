import uuid
import ldap

from pylons import session

import ckan.plugins as p
import ckan.lib.helpers as h
import ckan.model as model
import ckan.logic.schema as schema

t = p.toolkit


def _no_permissions(context, msg):
    user = context['user']
    return {'success': False, 'msg': msg.format(user=user)}


@t.auth_sysadmins_check
def user_create(context, data_dict):
    msg = p.toolkit._('Users cannot be created.')
    return _no_permissions(context, msg)


@t.auth_sysadmins_check
def user_update(context, data_dict):
    msg = p.toolkit._('Users cannot be edited.')
    return _no_permissions(context, msg)


@t.auth_sysadmins_check
def user_reset(context, data_dict):
    msg = p.toolkit._('Users cannot reset passwords.')
    return _no_permissions(context, msg)


@t.auth_sysadmins_check
def request_reset(context, data_dict):
    msg = p.toolkit._('Users cannot reset passwords.')
    return _no_permissions(context, msg)


class LdapPlugin(p.SingletonPlugin):

    p.implements(p.IAuthenticator, inherit=True)
    p.implements(p.IAuthFunctions, inherit=True)
    p.implements(p.IConfigurable)
    p.implements(p.IConfigurer)

    def update_config(self, config):
        t.add_template_directory(config, 'templates')

    def configure(self, config):
        self.ldap_server = config.get('ckanext_ldap.server_url')
        self.base_dn = config.get('ckanext_ldap.base_dn')
        self.search_attr = config.get('ckanext_ldap.search_attr')
        self.user_attr = config.get('ckanext_ldap.user_attr')
        self.admin_attr = config.get('ckanext_ldap.admin_attr')
        self.allow_anon_access = t.asbool(
            config.get('ckanext_ldap.allow_anon_access'))

    def make_password(self):
        # create a hard to guess password
        out = ''
        for n in xrange(8):
            out += str(uuid.uuid4())
        return out

    def check_ldap(self, password, ldap_user):
        user_dn = 'uid=%s,%s' % (ldap_user, self.base_dn)
        con = ldap.initialize(self.ldap_server)
        try:
            con.simple_bind_s(user_dn, password)
        except (ldap.INVALID_CREDENTIALS, ldap.NO_SUCH_OBJECT):
            msg = 'Sorry, your username or password was entered incorrectly.'
            return False, msg
        filter = '(uid=%s)' % ldap_user
        attr = [self.search_attr]
        results = con.search_s(self.base_dn, ldap.SCOPE_SUBTREE, filter, attr)
        attrs = results[0][1][self.search_attr]
        if '%s,%s' % (self.admin_attr, self.base_dn) in attrs:
            sysadmin = True
        elif '%s,%s' % (self.user_attr, self.base_dn) in attrs:
            sysadmin = False
        else:
            msg = 'Sorry but your account is not authourised to ' + \
                  'access the MOPAC CKAN system.  For access please ' + \
                  'contact the MOPAC team.'
            return False, msg
        details = con.search_s(self.base_dn, ldap.SCOPE_SUBTREE, filter,
                             ['mail', 'displayName'])[0][1]
        email = details['mail'][0]
        fullname = details['displayName'][0]
        return True, {
            'sysadmin': sysadmin,
            'email' : email,
            'fullname' : fullname,
        }

    def ldap(self, password, ldap_user):
        result, msg = self.check_ldap(password, ldap_user)
        if not result:
            return False, msg

        userobj = model.User.get(ldap_user)
        if userobj:
            if userobj.sysadmin != result.get('sysadmin'):
                userobj.sysadmin = result.get('sysadmin')
                model.Session.add(userobj)
                model.Session.commit()
        else:
            # Create the user
            data_dict = {
                'password': self.make_password(),
                'name': ldap_user,
                'email': result.get('email'),
                'fullname': result.get('fullname'),
                'sysadmin': result.get('sysadmin'),
            }
            # Update the user schema to allow user creation
            user_schema = schema.default_user_schema()
            user_schema['email'] = []

            context = {'schema': user_schema, 'ignore_auth': True}
            p.toolkit.get_action('user_create')(context, data_dict)

        session['ldap_user'] = ldap_user
        session.save()
        return True

    def login(self):
        username = t.request.POST.get('login')
        password = t.request.POST.get('password')
        if password and username:
            result, msg = self.ldap(password, username)
            if result:
                h.redirect_to(controller='user', action='dashboard')
            else:
                h.flash_error(msg)

    def logout(self):
        session['ldap_user'] = None
        session.delete()

    def identify(self):
        ldap_user = session.get('ldap_user')
        c = t.c
        if ldap_user:
            c.userobj = model.User.get(ldap_user)
            c.user = ldap_user
        elif not self.allow_anon_access:
            if t.request.environ['PATH_INFO'] != '/user/login':
                t.redirect_to(controller='user', action='login')

    def get_auth_functions(self):
        # we need to prevent some actions being authorized.
        return {
            'user_create': user_create,
            'user_update': user_update,
            'user_reset': user_reset,
            'request_reset': request_reset,
        }
