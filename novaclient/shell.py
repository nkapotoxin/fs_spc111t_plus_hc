# Copyright 2010 Jacob Kaplan-Moss
# Copyright 2011 OpenStack Foundation
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
Command-line interface to the OpenStack Nova API.
"""

from __future__ import print_function
import argparse
import getpass
import glob
import imp
import itertools
import logging
import os
import pkgutil
import sys

from keystoneclient import session as ksession
from oslo.utils import encodeutils
from oslo.utils import strutils
import pkg_resources
import six

HAS_KEYRING = False
all_errors = ValueError
try:
    import keyring
    HAS_KEYRING = True
except ImportError:
    pass

import novaclient
import novaclient.auth_plugin
from novaclient import client
from novaclient import exceptions as exc
import novaclient.extension
from novaclient.i18n import _
from novaclient.openstack.common import cliutils
from novaclient import utils
from novaclient.v1_1 import shell as shell_v1_1
from novaclient.v3 import shell as shell_v3

DEFAULT_OS_COMPUTE_API_VERSION = "1.1"
DEFAULT_NOVA_ENDPOINT_TYPE = 'publicURL'
# NOTE(cyeoh): Having the service type dependent on the API version
# is pretty ugly, but we have to do this because traditionally the
# catalog entry for compute points directly to the V2 API rather than
# the root, and then doing version discovery.
DEFAULT_NOVA_SERVICE_TYPE_MAP = {'1.1': 'compute',
                                 '2': 'compute',
                                 '3': 'computev3'}

logger = logging.getLogger(__name__)


def positive_non_zero_float(text):
    if text is None:
        return None
    try:
        value = float(text)
    except ValueError:
        msg = _("%s must be a float") % text
        raise argparse.ArgumentTypeError(msg)
    if value <= 0:
        msg = _("%s must be greater than 0") % text
        raise argparse.ArgumentTypeError(msg)
    return value


class SecretsHelper(object):
    def __init__(self, args, client):
        self.args = args
        self.client = client
        self.key = None
        self._password = None

    def _validate_string(self, text):
        if text is None or len(text) == 0:
            return False
        return True

    def _make_key(self):
        if self.key is not None:
            return self.key
        keys = [
            self.client.auth_url,
            self.client.projectid,
            self.client.user,
            self.client.region_name,
            self.client.endpoint_type,
            self.client.service_type,
            self.client.service_name,
            self.client.volume_service_name,
        ]
        for (index, key) in enumerate(keys):
            if key is None:
                keys[index] = '?'
            else:
                keys[index] = str(keys[index])
        self.key = "/".join(keys)
        return self.key

    def _prompt_password(self, verify=True):
        pw = None
        if hasattr(sys.stdin, 'isatty') and sys.stdin.isatty():
            # Check for Ctl-D
            try:
                while True:
                    pw1 = getpass.getpass('OS Password: ')
                    if verify:
                        pw2 = getpass.getpass('Please verify: ')
                    else:
                        pw2 = pw1
                    if pw1 == pw2 and self._validate_string(pw1):
                        pw = pw1
                        break
            except EOFError:
                pass
        return pw

    def save(self, auth_token, management_url, tenant_id):
        if not HAS_KEYRING or not self.args.os_cache:
            return
        if (auth_token == self.auth_token and
                management_url == self.management_url):
            # Nothing changed....
            return
        if not all([management_url, auth_token, tenant_id]):
            raise ValueError(_("Unable to save empty management url/auth "
                               "token"))
        value = "|".join([str(auth_token),
                          str(management_url),
                          str(tenant_id)])
        keyring.set_password("novaclient_auth", self._make_key(), value)

    @property
    def password(self):
        # Cache password so we prompt user at most once
        if self._password:
            pass
        elif self._validate_string(self.args.os_password):
            self._password = self.args.os_password
        else:
            verify_pass = strutils.bool_from_string(
                utils.env("OS_VERIFY_PASSWORD", default=False), True)
            self._password = self._prompt_password(verify_pass)
        if not self._password:
            raise exc.CommandError(
                'Expecting a password provided via either '
                '--os-password, env[OS_PASSWORD], or '
                'prompted response')
        return self._password

    @property
    def management_url(self):
        if not HAS_KEYRING or not self.args.os_cache:
            return None
        management_url = None
        try:
            block = keyring.get_password('novaclient_auth', self._make_key())
            if block:
                _token, management_url, _tenant_id = block.split('|', 2)
        except all_errors:
            pass
        return management_url

    @property
    def auth_token(self):
        # Now is where it gets complicated since we
        # want to look into the keyring module, if it
        # exists and see if anything was provided in that
        # file that we can use.
        if not HAS_KEYRING or not self.args.os_cache:
            return None
        token = None
        try:
            block = keyring.get_password('novaclient_auth', self._make_key())
            if block:
                token, _management_url, _tenant_id = block.split('|', 2)
        except all_errors:
            pass
        return token

    @property
    def tenant_id(self):
        if not HAS_KEYRING or not self.args.os_cache:
            return None
        tenant_id = None
        try:
            block = keyring.get_password('novaclient_auth', self._make_key())
            if block:
                _token, _management_url, tenant_id = block.split('|', 2)
        except all_errors:
            pass
        return tenant_id


class NovaClientArgumentParser(argparse.ArgumentParser):

    def __init__(self, *args, **kwargs):
        super(NovaClientArgumentParser, self).__init__(*args, **kwargs)

    def error(self, message):
        """error(message: string)

        Prints a usage message incorporating the message to stderr and
        exits.
        """
        self.print_usage(sys.stderr)
        # FIXME(lzyeval): if changes occur in argparse.ArgParser._check_value
        choose_from = ' (choose from'
        progparts = self.prog.partition(' ')
        self.exit(2, _("error: %(errmsg)s\nTry '%(mainp)s help %(subp)s'"
                     " for more information.\n") %
                     {'errmsg': message.split(choose_from)[0],
                      'mainp': progparts[0],
                      'subp': progparts[2]})


class OpenStackComputeShell(object):

    def _append_global_identity_args(self, parser):
        # Register the CLI arguments that have moved to the session object.
        ksession.Session.register_cli_options(parser)

        parser.set_defaults(insecure=utils.env('NOVACLIENT_INSECURE',
                            default=True))

    def get_base_parser(self):
        parser = NovaClientArgumentParser(
            prog='nova',
            description=__doc__.strip(),
            epilog='See "nova help COMMAND" '
                   'for help on a specific command.',
            add_help=False,
            formatter_class=OpenStackHelpFormatter,
        )

        # Global arguments
        parser.add_argument('-h', '--help',
            action='store_true',
            help=argparse.SUPPRESS,
        )

        parser.add_argument('--version',
                            action='version',
                            version=novaclient.__version__)

        parser.add_argument('--debug',
            default=False,
            action='store_true',
            help=_("Print debugging output"))

        parser.add_argument('--os-cache',
            default=strutils.bool_from_string(
                utils.env('OS_CACHE', default=False), True),
            action='store_true',
            help=_("Use the auth token cache. Defaults to False if "
                   "env[OS_CACHE] is not set."))

        parser.add_argument('--timings',
            default=False,
            action='store_true',
            help=_("Print call timing info"))

        parser.add_argument('--os-auth-token',
                default=utils.env('OS_AUTH_TOKEN'),
                help='Defaults to env[OS_AUTH_TOKEN]')

        parser.add_argument('--os-username',
            metavar='<auth-user-name>',
            default=utils.env('OS_USERNAME', 'NOVA_USERNAME'),
            help=_('Defaults to env[OS_USERNAME].'))
        parser.add_argument('--os_username',
            help=argparse.SUPPRESS)

        parser.add_argument('--os-user-id',
            metavar='<auth-user-id>',
            default=utils.env('OS_USER_ID'),
            help=_('Defaults to env[OS_USER_ID].'))

        parser.add_argument('--os-password',
            metavar='<auth-password>',
            default=utils.env('OS_PASSWORD', 'NOVA_PASSWORD'),
            help=_('Defaults to env[OS_PASSWORD].'))
        parser.add_argument('--os_password',
            help=argparse.SUPPRESS)

        parser.add_argument('--os-tenant-name',
            metavar='<auth-tenant-name>',
            default=utils.env('OS_TENANT_NAME', 'NOVA_PROJECT_ID'),
            help=_('Defaults to env[OS_TENANT_NAME].'))
        parser.add_argument('--os_tenant_name',
            help=argparse.SUPPRESS)

        parser.add_argument('--os-tenant-id',
            metavar='<auth-tenant-id>',
            default=utils.env('OS_TENANT_ID'),
            help=_('Defaults to env[OS_TENANT_ID].'))

        parser.add_argument('--os-auth-url',
            metavar='<auth-url>',
            default=utils.env('OS_AUTH_URL', 'NOVA_URL'),
            help=_('Defaults to env[OS_AUTH_URL].'))
        parser.add_argument('--os_auth_url',
            help=argparse.SUPPRESS)

        parser.add_argument('--os-region-name',
            metavar='<region-name>',
            default=utils.env('OS_REGION_NAME', 'NOVA_REGION_NAME'),
            help=_('Defaults to env[OS_REGION_NAME].'))
        parser.add_argument('--os_region_name',
            help=argparse.SUPPRESS)

        parser.add_argument('--os-auth-system',
            metavar='<auth-system>',
            default=utils.env('OS_AUTH_SYSTEM'),
            help='Defaults to env[OS_AUTH_SYSTEM].')
        parser.add_argument('--os_auth_system',
            help=argparse.SUPPRESS)

        parser.add_argument('--service-type',
            metavar='<service-type>',
            help=_('Defaults to compute for most actions'))
        parser.add_argument('--service_type',
            help=argparse.SUPPRESS)

        parser.add_argument('--service-name',
            metavar='<service-name>',
            default=utils.env('NOVA_SERVICE_NAME'),
            help=_('Defaults to env[NOVA_SERVICE_NAME]'))
        parser.add_argument('--service_name',
            help=argparse.SUPPRESS)

        parser.add_argument('--volume-service-name',
            metavar='<volume-service-name>',
            default=utils.env('NOVA_VOLUME_SERVICE_NAME'),
            help=_('Defaults to env[NOVA_VOLUME_SERVICE_NAME]'))
        parser.add_argument('--volume_service_name',
            help=argparse.SUPPRESS)

        parser.add_argument('--os-endpoint-type',
            metavar='<endpoint-type>',
            dest='endpoint_type',
            default=utils.env('NOVA_ENDPOINT_TYPE',
                default=utils.env('OS_ENDPOINT_TYPE',
                    default=DEFAULT_NOVA_ENDPOINT_TYPE)),
            help=_('Defaults to env[NOVA_ENDPOINT_TYPE], '
                   'env[OS_ENDPOINT_TYPE] or ')
                 + DEFAULT_NOVA_ENDPOINT_TYPE + '.')

        parser.add_argument('--endpoint-type',
            help=argparse.SUPPRESS)
        # NOTE(dtroyer): We can't add --endpoint_type here due to argparse
        #                thinking usage-list --end is ambiguous; but it
        #                works fine with only --endpoint-type present
        #                Go figure.  I'm leaving this here for doc purposes.
        # parser.add_argument('--endpoint_type',
        #     help=argparse.SUPPRESS)

        parser.add_argument('--os-compute-api-version',
            metavar='<compute-api-ver>',
            default=utils.env('OS_COMPUTE_API_VERSION',
                default=DEFAULT_OS_COMPUTE_API_VERSION),
            help=_('Accepts 1.1 or 3, '
                 'defaults to env[OS_COMPUTE_API_VERSION].'))
        parser.add_argument('--os_compute_api_version',
            help=argparse.SUPPRESS)

        parser.add_argument('--bypass-url',
            metavar='<bypass-url>',
            dest='bypass_url',
            default=utils.env('NOVACLIENT_BYPASS_URL'),
            help="Use this API endpoint instead of the Service Catalog. "
                 "Defaults to env[NOVACLIENT_BYPASS_URL]")
        parser.add_argument('--bypass_url',
            help=argparse.SUPPRESS)

        # The auth-system-plugins might require some extra options
        novaclient.auth_plugin.load_auth_system_opts(parser)

        self._append_global_identity_args(parser)

        return parser

    def get_subcommand_parser(self, version):
        parser = self.get_base_parser()

        self.subcommands = {}
        subparsers = parser.add_subparsers(metavar='<subcommand>')

        try:
            actions_module = {
                '1.1': shell_v1_1,
                '2': shell_v1_1,
                '3': shell_v3,
            }[version]
        except KeyError:
            actions_module = shell_v1_1

        self._find_actions(subparsers, actions_module)
        self._find_actions(subparsers, self)

        for extension in self.extensions:
            self._find_actions(subparsers, extension.module)

        self._add_bash_completion_subparser(subparsers)

        return parser

    def _discover_extensions(self, version):
        extensions = []
        for name, module in itertools.chain(
                self._discover_via_python_path(),
                self._discover_via_contrib_path(version),
                self._discover_via_entry_points()):

            extension = novaclient.extension.Extension(name, module)
            extensions.append(extension)

        return extensions

    def _discover_via_python_path(self):
        for (module_loader, name, _ispkg) in pkgutil.iter_modules():
            if name.endswith('_python_novaclient_ext'):
                if not hasattr(module_loader, 'load_module'):
                    # Python 2.6 compat: actually get an ImpImporter obj
                    module_loader = module_loader.find_module(name)

                module = module_loader.load_module(name)
                if hasattr(module, 'extension_name'):
                    name = module.extension_name

                yield name, module

    def _discover_via_contrib_path(self, version):
        module_path = os.path.dirname(os.path.abspath(__file__))
        version_str = "v%s" % version.replace('.', '_')
        ext_path = os.path.join(module_path, version_str, 'contrib')
        ext_glob = os.path.join(ext_path, "*.py")

        for ext_path in glob.iglob(ext_glob):
            name = os.path.basename(ext_path)[:-3]

            if name == "__init__":
                continue

            module = imp.load_source(name, ext_path)
            yield name, module

    def _discover_via_entry_points(self):
        for ep in pkg_resources.iter_entry_points('novaclient.extension'):
            name = ep.name
            module = ep.load()

            yield name, module

    def _add_bash_completion_subparser(self, subparsers):
        subparser = subparsers.add_parser('bash_completion',
            add_help=False,
            formatter_class=OpenStackHelpFormatter
        )
        self.subcommands['bash_completion'] = subparser
        subparser.set_defaults(func=self.do_bash_completion)

    def _find_actions(self, subparsers, actions_module):
        for attr in (a for a in dir(actions_module) if a.startswith('do_')):
            # I prefer to be hyphen-separated instead of underscores.
            command = attr[3:].replace('_', '-')
            callback = getattr(actions_module, attr)
            desc = callback.__doc__ or ''
            action_help = desc.strip()
            arguments = getattr(callback, 'arguments', [])

            subparser = subparsers.add_parser(command,
                help=action_help,
                description=desc,
                add_help=False,
                formatter_class=OpenStackHelpFormatter
            )
            subparser.add_argument('-h', '--help',
                action='help',
                help=argparse.SUPPRESS,
            )
            self.subcommands[command] = subparser
            for (args, kwargs) in arguments:
                subparser.add_argument(*args, **kwargs)
            subparser.set_defaults(func=callback)

    def setup_debugging(self, debug):
        if not debug:
            return

        streamformat = "%(levelname)s (%(module)s:%(lineno)d) %(message)s"
        # Set up the root logger to debug so that the submodules can
        # print debug messages
        logging.basicConfig(level=logging.DEBUG,
                            format=streamformat)

    def main(self, argv):
        # Parse args once to find version and debug settings
        parser = self.get_base_parser()
        (options, args) = parser.parse_known_args(argv)
        self.setup_debugging(options.debug)

        # Discover available auth plugins
        novaclient.auth_plugin.discover_auth_systems()

        # build available subcommands based on version
        self.extensions = self._discover_extensions(
            options.os_compute_api_version)
        self._run_extension_hooks('__pre_parse_args__')

        # NOTE(dtroyer): Hackery to handle --endpoint_type due to argparse
        #                thinking usage-list --end is ambiguous; but it
        #                works fine with only --endpoint-type present
        #                Go figure.
        if '--endpoint_type' in argv:
            spot = argv.index('--endpoint_type')
            argv[spot] = '--endpoint-type'

        subcommand_parser = self.get_subcommand_parser(
            options.os_compute_api_version)
        self.parser = subcommand_parser

        if options.help or not argv:
            subcommand_parser.print_help()
            return 0

        args = subcommand_parser.parse_args(argv)
        self._run_extension_hooks('__post_parse_args__', args)

        # Short-circuit and deal with help right away.
        if args.func == self.do_help:
            self.do_help(args)
            return 0
        elif args.func == self.do_bash_completion:
            self.do_bash_completion(args)
            return 0

        os_username = args.os_username
        os_user_id = args.os_user_id
        os_password = None  # Fetched and set later as needed
        os_tenant_name = args.os_tenant_name
        os_tenant_id = args.os_tenant_id
        os_auth_url = args.os_auth_url
        os_region_name = args.os_region_name
        os_auth_system = args.os_auth_system
        endpoint_type = args.endpoint_type
        insecure = args.insecure
        service_type = args.service_type
        service_name = args.service_name
        volume_service_name = args.volume_service_name
        bypass_url = args.bypass_url
        os_cache = args.os_cache
        cacert = args.os_cacert
        timeout = args.timeout

        # We may have either, both or none of these.
        # If we have both, we don't need USERNAME, PASSWORD etc.
        # Fill in the blanks from the SecretsHelper if possible.
        # Finally, authenticate unless we have both.
        # Note if we don't auth we probably don't have a tenant ID so we can't
        # cache the token.
        auth_token = args.os_auth_token if args.os_auth_token else None
        management_url = bypass_url if bypass_url else None

        if os_auth_system and os_auth_system != "keystone":
            auth_plugin = novaclient.auth_plugin.load_plugin(os_auth_system)
        else:
            auth_plugin = None

        if not endpoint_type:
            endpoint_type = DEFAULT_NOVA_ENDPOINT_TYPE

        if not service_type:
            os_compute_api_version = (options.os_compute_api_version or
                                      DEFAULT_OS_COMPUTE_API_VERSION)
            try:
                service_type = DEFAULT_NOVA_SERVICE_TYPE_MAP[
                    os_compute_api_version]
            except KeyError:
                service_type = DEFAULT_NOVA_SERVICE_TYPE_MAP[
                    DEFAULT_OS_COMPUTE_API_VERSION]
            service_type = cliutils.get_service_type(args.func) or service_type

        # If we have an auth token but no management_url, we must auth anyway.
        # Expired tokens are handled by client.py:_cs_request
        must_auth = not (cliutils.isunauthenticated(args.func)
                         or (auth_token and management_url))

        # FIXME(usrleon): Here should be restrict for project id same as
        # for os_username or os_password but for compatibility it is not.
        if must_auth:
            if auth_plugin:
                auth_plugin.parse_opts(args)

            if not auth_plugin or not auth_plugin.opts:
                if not os_username and not os_user_id:
                    raise exc.CommandError(_("You must provide a username "
                            "or user id via --os-username, --os-user-id, "
                            "env[OS_USERNAME] or env[OS_USER_ID]"))

            if not os_tenant_name and not os_tenant_id:
                raise exc.CommandError(_("You must provide a tenant name "
                        "or tenant id via --os-tenant-name, "
                        "--os-tenant-id, env[OS_TENANT_NAME] "
                        "or env[OS_TENANT_ID]"))

            if not os_auth_url:
                if os_auth_system and os_auth_system != 'keystone':
                    os_auth_url = auth_plugin.get_auth_url()

            if not os_auth_url:
                    raise exc.CommandError(_("You must provide an auth url "
                            "via either --os-auth-url or env[OS_AUTH_URL] "
                            "or specify an auth_system which defines a "
                            "default url with --os-auth-system "
                            "or env[OS_AUTH_SYSTEM]"))

        completion_cache = client.CompletionCache(os_username, os_auth_url)

        self.cs = client.Client(options.os_compute_api_version,
                os_username, os_password, os_tenant_name,
                tenant_id=os_tenant_id, user_id=os_user_id,
                auth_url=os_auth_url, insecure=insecure,
                region_name=os_region_name, endpoint_type=endpoint_type,
                extensions=self.extensions, service_type=service_type,
                service_name=service_name, auth_system=os_auth_system,
                auth_plugin=auth_plugin, auth_token=auth_token,
                volume_service_name=volume_service_name,
                timings=args.timings, bypass_url=bypass_url,
                os_cache=os_cache, http_log_debug=options.debug,
                cacert=cacert, timeout=timeout,
                completion_cache=completion_cache)

        # Now check for the password/token of which pieces of the
        # identifying keyring key can come from the underlying client
        if must_auth:
            helper = SecretsHelper(args, self.cs.client)
            if (auth_plugin and auth_plugin.opts and
                    "os_password" not in auth_plugin.opts):
                use_pw = False
            else:
                use_pw = True

            tenant_id = helper.tenant_id
            # Allow commandline to override cache
            if not auth_token:
                auth_token = helper.auth_token
            if not management_url:
                management_url = helper.management_url
            if tenant_id and auth_token and management_url:
                self.cs.client.tenant_id = tenant_id
                self.cs.client.auth_token = auth_token
                self.cs.client.management_url = management_url
                self.cs.client.password_func = lambda: helper.password
            elif use_pw:
                # We're missing something, so auth with user/pass and save
                # the result in our helper.
                self.cs.client.password = helper.password
                self.cs.client.keyring_saver = helper

        try:
            # This does a couple of bits which are useful even if we've
            # got the token + service URL already. It exits fast in that case.
            if not cliutils.isunauthenticated(args.func):
                self.cs.authenticate()
        except exc.Unauthorized:
            raise exc.CommandError(_("Invalid OpenStack Nova credentials."))
        except exc.AuthorizationFailure:
            raise exc.CommandError(_("Unable to authorize user"))

        if options.os_compute_api_version == "3" and service_type != 'image':
            # NOTE(cyeoh): create an image based client because the
            # images api is no longer proxied by the V3 API and we
            # sometimes need to be able to look up images information
            # via glance when connected to the nova api.
            image_service_type = 'image'
            # NOTE(hdd): the password is needed again because creating a new
            # Client without specifying bypass_url will force authentication.
            # We can't reuse self.cs's bypass_url, because that's the URL for
            # the nova service; we need to get glance's URL for this Client
            if not os_password:
                os_password = helper.password
            self.cs.image_cs = client.Client(
                options.os_compute_api_version, os_username,
                os_password, os_tenant_name, tenant_id=os_tenant_id,
                auth_url=os_auth_url, insecure=insecure,
                region_name=os_region_name, endpoint_type=endpoint_type,
                extensions=self.extensions, service_type=image_service_type,
                service_name=service_name, auth_system=os_auth_system,
                auth_plugin=auth_plugin,
                volume_service_name=volume_service_name,
                timings=args.timings, bypass_url=bypass_url,
                os_cache=os_cache, http_log_debug=options.debug,
                cacert=cacert, timeout=timeout)

        args.func(self.cs, args)

        if args.timings:
            self._dump_timings(self.cs.get_timings())

    def _dump_timings(self, timings):
        class Tyme(object):
            def __init__(self, url, seconds):
                self.url = url
                self.seconds = seconds
        results = [Tyme(url, end - start) for url, start, end in timings]
        total = 0.0
        for tyme in results:
            total += tyme.seconds
        results.append(Tyme("Total", total))
        utils.print_list(results, ["url", "seconds"], sortby_index=None)

    def _run_extension_hooks(self, hook_type, *args, **kwargs):
        """Run hooks for all registered extensions."""
        for extension in self.extensions:
            extension.run_hooks(hook_type, *args, **kwargs)

    def do_bash_completion(self, _args):
        """
        Prints all of the commands and options to stdout so that the
        nova.bash_completion script doesn't have to hard code them.
        """
        commands = set()
        options = set()
        for sc_str, sc in self.subcommands.items():
            commands.add(sc_str)
            for option in sc._optionals._option_string_actions.keys():
                options.add(option)

        commands.remove('bash-completion')
        commands.remove('bash_completion')
        print(' '.join(commands | options))

    @utils.arg(
        'command',
        metavar='<subcommand>',
        nargs='?',
        help='Display help for <subcommand>')
    def do_help(self, args):
        """
        Display help about this program or one of its subcommands.
        """
        if args.command:
            if args.command in self.subcommands:
                self.subcommands[args.command].print_help()
            else:
                raise exc.CommandError(_("'%s' is not a valid subcommand") %
                                       args.command)
        else:
            self.parser.print_help()


# I'm picky about my shell help.
class OpenStackHelpFormatter(argparse.HelpFormatter):
    def __init__(self, prog, indent_increment=2, max_help_position=32,
                 width=None):
        super(OpenStackHelpFormatter, self).__init__(prog, indent_increment,
              max_help_position, width)

    def start_section(self, heading):
        # Title-case the headings
        heading = '%s%s' % (heading[0].upper(), heading[1:])
        super(OpenStackHelpFormatter, self).start_section(heading)


def main():
    try:
        argv = [encodeutils.safe_decode(a) for a in sys.argv[1:]]
        OpenStackComputeShell().main(argv)

    except Exception as e:
        logger.debug(e, exc_info=1)
        details = {'name': encodeutils.safe_encode(e.__class__.__name__),
                   'msg': encodeutils.safe_encode(six.text_type(e))}
        print("ERROR (%(name)s): %(msg)s" % details,
              file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt as e:
        print("... terminating nova client", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()
