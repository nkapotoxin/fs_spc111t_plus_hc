# Copyright 2013 IBM Corp.
#
#   Licensed under the Apache License, Version 2.0 (the "License"); you may
#   not use this file except in compliance with the License. You may obtain
#   a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#   License for the specific language governing permissions and limitations
#   under the License.

"""Notifications module for OpenStack Identity Service resources"""

import collections
import inspect
import logging
import socket

from oslo.config import cfg
from oslo import messaging
import pycadf
from pycadf import cadftaxonomy as taxonomy
from pycadf import cadftype
from pycadf import credential
from pycadf import eventfactory
from pycadf import resource

from keystone.i18n import _, _LE
from keystone.openstack.common import log


notifier_opts = [
    cfg.StrOpt('default_publisher_id',
               help='Default publisher_id for outgoing notifications'),
]

LOG = log.getLogger(__name__)
# NOTE(gyee): actions that can be notified. One must update this list whenever
# a new action is supported.
_ACTIONS = collections.namedtuple(
    'NotificationActions',
    'created, deleted, disabled, updated, internal')
ACTIONS = _ACTIONS(created='created', deleted='deleted', disabled='disabled',
                   updated='updated', internal='internal')

SAML_AUDIT_TYPE = 'http://docs.oasis-open.org/security/saml/v2.0'
# resource types that can be notified
_SUBSCRIBERS = {}
_notifier = None


CONF = cfg.CONF
CONF.register_opts(notifier_opts)

try:  # Python 2.7+
    getcallargs = inspect.getcallargs
except AttributeError:  # Python 2.6 support
    def getcallargs(f, *positional, **named):
        """A very simplified version of inspect.getcallargs.

        It will work in our specific case where we are using decorators
        around methods.

        """
        argspec = inspect.getargspec(f)

        # setup the defaults
        callargs = dict(zip(argspec.args[-len(argspec.defaults):],
                            argspec.defaults))

        callargs.update(named)
        for n, arg in enumerate(positional):
            callargs[argspec.args[n]] = arg

        return callargs

# NOTE(morganfainberg): Special case notifications that are only used
# internally for handling token persistence token deletions
INVALIDATE_USER_TOKEN_PERSISTENCE = 'invalidate_user_tokens'
INVALIDATE_USER_PROJECT_TOKEN_PERSISTENCE = 'invalidate_user_project_tokens'
INVALIDATE_USER_OAUTH_CONSUMER_TOKENS = 'invalidate_user_consumer_tokens'


class ManagerNotificationWrapper(object):
    """Send event notifications for ``Manager`` methods.

    Sends a notification if the wrapped Manager method does not raise an
    ``Exception`` (such as ``keystone.exception.NotFound``).

    :param operation:  one of the values from ACTIONS
    :param resource_type: type of resource being affected
    :param public:  If True (default), the event will be sent to the notifier
                API.  If False, the event will only be sent via
                notify_event_callbacks to in process listeners

    """
    def __init__(self, operation, resource_type, public=True,
                 resource_id_arg_index=1, result_id_arg_attr=None):
        self.operation = operation
        self.resource_type = resource_type
        self.public = public
        self.resource_id_arg_index = resource_id_arg_index
        self.result_id_arg_attr = result_id_arg_attr

    def __call__(self, f):
        def wrapper(*args, **kwargs):
            """Send a notification if the wrapped callable is successful."""
            try:
                result = f(*args, **kwargs)
            except Exception:
                raise
            else:
                if self.result_id_arg_attr is not None:
                    resource_id = result[self.result_id_arg_attr]
                else:
                    resource_id = args[self.resource_id_arg_index]
                _send_notification(
                    self.operation,
                    self.resource_type,
                    resource_id,
                    public=self.public)
            return result

        return wrapper


def created(*args, **kwargs):
    """Decorator to send notifications for ``Manager.create_*`` methods."""
    return ManagerNotificationWrapper(ACTIONS.created, *args, **kwargs)


def updated(*args, **kwargs):
    """Decorator to send notifications for ``Manager.update_*`` methods."""
    return ManagerNotificationWrapper(ACTIONS.updated, *args, **kwargs)


def disabled(*args, **kwargs):
    """Decorator to send notifications when an object is disabled."""
    return ManagerNotificationWrapper(ACTIONS.disabled, *args, **kwargs)


def deleted(*args, **kwargs):
    """Decorator to send notifications for ``Manager.delete_*`` methods."""
    return ManagerNotificationWrapper(ACTIONS.deleted, *args, **kwargs)


def internal(*args, **kwargs):
    """Decorator to send notifications for internal notifications only."""
    kwargs['public'] = False
    return ManagerNotificationWrapper(ACTIONS.internal, *args, **kwargs)


def _get_callback_info(callback):
    if getattr(callback, 'im_class', None):
        return [getattr(callback, '__module__', None),
                callback.im_class.__name__,
                callback.__name__]
    else:
        return [getattr(callback, '__module__', None), callback.__name__]


def register_event_callback(event, resource_type, callbacks):
    if event not in ACTIONS:
        raise ValueError(_('%(event)s is not a valid notification event, must '
                           'be one of: %(actions)s') %
                         {'event': event, 'actions': ', '.join(ACTIONS)})

    if not hasattr(callbacks, '__iter__'):
        callbacks = [callbacks]

    for callback in callbacks:
        if not callable(callback):
            msg = _LE('Method not callable: %s') % callback
            LOG.error(msg)
            raise TypeError(msg)
        _SUBSCRIBERS.setdefault(event, {}).setdefault(resource_type, set())
        _SUBSCRIBERS[event][resource_type].add(callback)

        if LOG.logger.getEffectiveLevel() <= logging.DEBUG:
            # Do this only if its going to appear in the logs.
            msg = 'Callback: `%(callback)s` subscribed to event `%(event)s`.'
            callback_info = _get_callback_info(callback)
            callback_str = '.'.join(i for i in callback_info if i is not None)
            event_str = '.'.join(['identity', resource_type, event])
            LOG.debug(msg, {'callback': callback_str, 'event': event_str})


def notify_event_callbacks(service, resource_type, operation, payload):
    """Sends a notification to registered extensions."""
    if operation in _SUBSCRIBERS:
        if resource_type in _SUBSCRIBERS[operation]:
            for cb in _SUBSCRIBERS[operation][resource_type]:
                subst_dict = {'cb_name': cb.__name__,
                              'service': service,
                              'resource_type': resource_type,
                              'operation': operation,
                              'payload': payload}
                LOG.debug('Invoking callback %(cb_name)s for event '
                          '%(service)s %(resource_type)s %(operation)s for'
                          '%(payload)s', subst_dict)
                cb(service, resource_type, operation, payload)


def _get_notifier():
    """Return a notifier object.

    If _notifier is None it means that a notifier object has not been set.
    If _notifier is False it means that a notifier has previously failed to
    construct.
    Otherwise it is a constructed Notifier object.
    """
    global _notifier

    if _notifier is None:
        host = CONF.default_publisher_id or socket.gethostname()
        try:
            transport = messaging.get_transport(CONF)
            _notifier = messaging.Notifier(transport, "identity.%s" % host)
        except Exception:
            LOG.exception(_("Failed to construct notifier"))
            _notifier = False

    return _notifier


def clear_subscribers():
    _SUBSCRIBERS.clear()


def reset_notifier():
    global _notifier
    _notifier = None


def _send_notification(operation, resource_type, resource_id, public=True):
    """Send notification to inform observers about the affected resource.

    This method doesn't raise an exception when sending the notification fails.

    :param operation: operation being performed (created, updated, or deleted)
    :param resource_type: type of resource being operated on
    :param resource_id: ID of resource being operated on
    :param public:  if True (default), the event will be sent
                    to the notifier API.
                    if False, the event will only be sent via
                    notify_event_callbacks to in process listeners.
    """
    payload = {'resource_info': resource_id}
    service = 'identity'

    notify_event_callbacks(service, resource_type, operation, payload)

    if public:
        notifier = _get_notifier()
        if notifier:
            context = {}
            event_type = '%(service)s.%(resource_type)s.%(operation)s' % {
                'service': service,
                'resource_type': resource_type,
                'operation': operation}
            try:
                notifier.info(context, event_type, payload)
            except Exception:
                LOG.exception(_(
                    'Failed to send %(res_id)s %(event_type)s notification'),
                    {'res_id': resource_id, 'event_type': event_type})


def _get_request_audit_info(context, user_id=None):
    remote_addr = None
    http_user_agent = None

    if context and 'environment' in context and context['environment']:
        environment = context['environment']
        remote_addr = environment.get('REMOTE_ADDR')
        http_user_agent = environment.get('HTTP_USER_AGENT')
        if not user_id:
            user_id = environment.get('KEYSTONE_AUTH_CONTEXT',
                                      {}).get('user_id')

    host = pycadf.host.Host(address=remote_addr, agent=http_user_agent)
    initiator = resource.Resource(typeURI=taxonomy.ACCOUNT_USER,
                                  name=user_id, host=host)
    return initiator


class CadfNotificationWrapper(object):
    """Send CADF event notifications for various methods.

    Sends CADF notifications for events such as whether an authentication was
    successful or not.

    """

    def __init__(self, action):
        self.action = action

    def __call__(self, f):
        def wrapper(wrapped_self, context, user_id, *args, **kwargs):
            """Always send a notification."""

            initiator = _get_request_audit_info(context, user_id)
            try:
                result = f(wrapped_self, context, user_id, *args, **kwargs)
            except Exception:
                # For authentication failure send a cadf event as well
                _send_audit_notification(self.action, initiator,
                                         taxonomy.OUTCOME_FAILURE)
                raise
            else:
                _send_audit_notification(self.action, initiator,
                                         taxonomy.OUTCOME_SUCCESS)
                return result

        return wrapper


class CadfRoleAssignmentNotificationWrapper(object):
    """Send CADF notifications for ``role_assignment`` methods.

    Sends a CADF notification if the wrapped method does not raise an
    ``Exception`` (such as ``keystone.exception.NotFound``).

    :param operation: one of the values from ACTIONS (create or delete)
    """

    ROLE_ASSIGNMENT = 'role_assignment'

    def __init__(self, operation):
        self.operation = "%s.%s" % (operation, self.ROLE_ASSIGNMENT)

    def __call__(self, f):
        def wrapper(wrapped_self, role_id, *args, **kwargs):
            """Send a notification if the wrapped callable is successful."""

            """ NOTE(stevemar): The reason we go through checking kwargs
            and args for possible target and actor values is because the
            create_grant() (and delete_grant()) method are called
            differently in various tests.
            Using named arguments, i.e.:
                create_grant(user_id=user['id'], domain_id=domain['id'],
                             role_id=role['id'])

            Or, using positional arguments, i.e.:
                create_grant(role_id['id'], user['id'], None,
                             domain_id=domain['id'], None)

            Or, both, i.e.:
                create_grant(role_id['id'], user_id=user['id'],
                             domain_id=domain['id'])

            Checking the values for kwargs is easy enough, since it comes
            in as a dictionary

            The actual method signature is
                create_grant(role_id, user_id=None, group_id=None,
                             domain_id=None, project_id=None,
                             inherited_to_projects=False)

            So, if the values of actor or target are still None after
            checking kwargs, we can check the positional arguments,
            based on the method signature.
            """
            call_args = getcallargs(f, wrapped_self, role_id, *args, **kwargs)
            inherited = call_args['inherited_to_projects']
            context = call_args['context']

            initiator = _get_request_audit_info(context)

            audit_kwargs = {}
            if call_args['project_id']:
                audit_kwargs['project'] = call_args['project_id']
            elif call_args['domain_id']:
                audit_kwargs['domain'] = call_args['domain_id']

            if call_args['user_id']:
                audit_kwargs['user'] = call_args['user_id']
            elif call_args['group_id']:
                audit_kwargs['group'] = call_args['group_id']

            audit_kwargs['inherited_to_projects'] = inherited
            audit_kwargs['role'] = role_id

            try:
                result = f(wrapped_self, role_id, *args, **kwargs)
            except Exception:
                _send_audit_notification(self.operation, initiator,
                                         taxonomy.OUTCOME_FAILURE,
                                         **audit_kwargs)
                raise
            else:
                _send_audit_notification(self.operation, initiator,
                                         taxonomy.OUTCOME_SUCCESS,
                                         **audit_kwargs)
                return result

        return wrapper


def send_saml_audit_notification(action, context, user_id, group_ids,
                                 identity_provider, protocol, token_id,
                                 outcome):
    initiator = _get_request_audit_info(context)
    audit_type = SAML_AUDIT_TYPE
    user_id = user_id or taxonomy.UNKNOWN
    token_id = token_id or taxonomy.UNKNOWN
    group_ids = group_ids or []
    cred = credential.FederatedCredential(token=token_id, type=audit_type,
                                          identity_provider=identity_provider,
                                          user=user_id, groups=group_ids)
    initiator.credential = cred
    _send_audit_notification(action, initiator, outcome)


def _send_audit_notification(action, initiator, outcome, **kwargs):
    """Send CADF notification to inform observers about the affected resource.

    This method logs an exception when sending the notification fails.

    :param action: CADF action being audited (e.g., 'authenticate')
    :param initiator: CADF resource representing the initiator
    :param outcome: The CADF outcome (taxonomy.OUTCOME_PENDING,
        taxonomy.OUTCOME_SUCCESS, taxonomy.OUTCOME_FAILURE)

    """

    event = eventfactory.EventFactory().new_event(
        eventType=cadftype.EVENTTYPE_ACTIVITY,
        outcome=outcome,
        action=action,
        initiator=initiator,
        target=resource.Resource(typeURI=taxonomy.ACCOUNT_USER),
        observer=resource.Resource(typeURI=taxonomy.SERVICE_SECURITY))

    for key, value in kwargs.items():
        setattr(event, key, value)

    context = {}
    payload = event.as_dict()
    service = 'identity'
    event_type = '%(service)s.%(action)s' % {'service': service,
                                             'action': action}

    notifier = _get_notifier()

    if notifier:
        try:
            notifier.info(context, event_type, payload)
        except Exception:
            # diaper defense: any exception that occurs while emitting the
            # notification should not interfere with the API request
            LOG.exception(_(
                'Failed to send %(action)s %(event_type)s notification'),
                {'action': action, 'event_type': event_type})


emit_event = CadfNotificationWrapper


role_assignment = CadfRoleAssignmentNotificationWrapper
