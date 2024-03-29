# Copyright 2013 New Dream Network, LLC (DreamHost)
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

import itertools
from six import moves

from neutron.plugins.common import constants as qconstants
from neutron.services.loadbalancer import constants


PROTOCOL_MAP = {
    constants.PROTOCOL_TCP: 'tcp',
    constants.PROTOCOL_HTTP: 'http',
    constants.PROTOCOL_HTTPS: 'tcp',
}

BALANCE_MAP = {
    constants.LB_METHOD_ROUND_ROBIN: 'roundrobin',
    constants.LB_METHOD_LEAST_CONNECTIONS: 'leastconn',
    constants.LB_METHOD_SOURCE_IP: 'source'
}

STATS_MAP = {
    constants.STATS_ACTIVE_CONNECTIONS: 'scur',
    constants.STATS_TOTAL_CONNECTIONS: 'stot',
    constants.STATS_IN_BYTES: 'bin',
    constants.STATS_OUT_BYTES: 'bout',
}

ACTIVE_PENDING_STATUSES = qconstants.ACTIVE_PENDING_STATUSES
INACTIVE = qconstants.INACTIVE


def save_config(cfg_data, socket_path=None,
                user_group='nogroup'):
    """Convert a logical configuration to the HAProxy version."""
    data = []
    data.extend(_build_global(socket_path=socket_path,
                              user_group=user_group))
    data.extend(_build_defaults())
    data.extend(cfg_data)
    return '\n'.join(data)


def get_config_data(logical_config):
    data = []
    data.extend(_build_frontend(logical_config))
    data.extend(_build_listeners(logical_config))
    data.extend(_build_backend(logical_config))
    return '\n'.join(data) 


def _build_global(socket_path=None, user_group='nogroup'):
    opts = [
        'daemon',
        'user nobody',
        'group %s' % user_group,
        'log /dev/log local3 info',
        'log /dev/log local3 notice'
    ]

    if socket_path:
        opts.append('stats socket %s mode 0666 level user' % socket_path)

    return itertools.chain(['global'], ('\t' + o for o in opts))


def _build_defaults():
    opts = [
        'log global',
        'retries 3',
        'option splice-auto',
        'option redispatch',
        'timeout connect 5000',
        'timeout client 50000',
        'timeout server 50000',
    ]

    return itertools.chain(['defaults'], ('\t' + o for o in opts))


def _build_frontend(config):
    protocol = config['vip']['protocol']

    opts = [
        'option splice-auto',
        'option tcplog',
        'bind %s:%d transparent' % (
            _get_first_ip_from_port(config['vip']['port']),
            config['vip']['protocol_port']
        ),
        'mode %s' % PROTOCOL_MAP[protocol],
        'default_backend %s' % config['pool']['id'],
    ]

    if config['vip']['connection_limit'] >= 0:
        opts.append('maxconn %s' % config['vip']['connection_limit'])

    if protocol == constants.PROTOCOL_HTTP:
        opts.append('option forwardfor')

    return itertools.chain(
        ['frontend %s' % config['vip']['id']],
        ('\t' + o for o in opts)
    )

def _build_listeners(config):
    # add the listeners
    opts = []
    for listener in config['listeners']:
        protocol = listener['protocol']
        listen_opts = [
        'frontend %s-%s' % (config['vip']['id'],listener['protocol_port']),
        '\toption splice-auto',
        '\toption tcplog',
        '\tbind %s:%d' % (
            _get_first_ip_from_port(config['vip']['port']),
            listener['protocol_port']
        ),
        '\tmode %s' % PROTOCOL_MAP[protocol],
        '\tdefault_backend %s' % config['pool']['id']
        ]
        opts.extend(listen_opts)
    return itertools.chain([],(o for o in opts))

def _build_backend(config):
    protocol = config['pool']['protocol']
    lb_method = config['pool']['lb_method']

    opts = [
        'mode %s' % PROTOCOL_MAP[protocol],
        'balance %s' % BALANCE_MAP.get(lb_method, 'roundrobin'),
        'option splice-auto'
    ]

    if protocol == constants.PROTOCOL_HTTP:
        opts.append('option forwardfor')

    # add the first health_monitor (if available)
    server_addon, health_opts = _get_server_health_option(config)
    opts.extend(health_opts)

    # add session persistence (if available)
    persist_opts = _get_session_persistence(config)
    opts.extend(persist_opts)

    # add the members
    for member in config['members']:
        if ((member['status'] in ACTIVE_PENDING_STATUSES or
             member['status'] == INACTIVE)
            and member['admin_state_up']):
            server = (('server %(id)s %(address)s:%(protocol_port)s '
                       'weight %(weight)s') % member) + server_addon
            if _has_http_cookie_persistence(config):
                server += ' cookie %d' % config['members'].index(member)
            opts.append(server)

    return itertools.chain(
        ['backend %s' % config['pool']['id']],
        ('\t' + o for o in opts)
    )


def _get_first_ip_from_port(port):
    for fixed_ip in port['fixed_ips']:
        return fixed_ip['ip_address']


def _get_server_health_option(config):
    """return the first active health option."""
    for monitor in config['healthmonitors']:
        # not checking the status of healthmonitor for two reasons:
        # 1) status field is absent in HealthMonitor model
        # 2) only active HealthMonitors are fetched with
        # LoadBalancerCallbacks.get_logical_device
        if monitor['admin_state_up']:
            break
    else:
        return '', []

    server_addon = ' check inter %(delay)ds fall %(max_retries)d' % monitor
    opts = [
        'timeout check %ds' % monitor['timeout']
    ]

    if monitor['type'] in (constants.HEALTH_MONITOR_HTTP,
                           constants.HEALTH_MONITOR_HTTPS):
        opts.append('option httpchk %(http_method)s %(url_path)s' % monitor)
        opts.append(
            'http-check expect rstatus %s' %
            '|'.join(_expand_expected_codes(monitor['expected_codes']))
        )

    if monitor['type'] == constants.HEALTH_MONITOR_HTTPS:
        opts.append('option ssl-hello-chk')

    return server_addon, opts


def _get_session_persistence(config):
    persistence = config['vip'].get('session_persistence')
    if not persistence:
        return []

    opts = []
    if persistence['type'] == constants.SESSION_PERSISTENCE_SOURCE_IP:
        opts.append('stick-table type ip size 10k')
        opts.append('stick on src')
    elif (persistence['type'] == constants.SESSION_PERSISTENCE_HTTP_COOKIE and
          config.get('members')):
        opts.append('cookie SRV insert indirect nocache')
    elif (persistence['type'] == constants.SESSION_PERSISTENCE_APP_COOKIE and
          persistence.get('cookie_name')):
        opts.append('appsession %s len 56 timeout 3h' %
                    persistence['cookie_name'])

    return opts


def _has_http_cookie_persistence(config):
    return (config['vip'].get('session_persistence') and
            config['vip']['session_persistence']['type'] ==
            constants.SESSION_PERSISTENCE_HTTP_COOKIE)


def _expand_expected_codes(codes):
    """Expand the expected code string in set of codes.

    200-204 -> 200, 201, 202, 204
    200, 203 -> 200, 203
    """

    retval = set()
    for code in codes.replace(',', ' ').split(' '):
        code = code.strip()

        if not code:
            continue
        elif '-' in code:
            low, hi = code.split('-')[:2]
            retval.update(str(i) for i in moves.xrange(int(low), int(hi) + 1))
        else:
            retval.add(code)
    return retval

