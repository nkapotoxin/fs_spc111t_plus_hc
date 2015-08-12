# Copyright (c) 2011 OpenStack Foundation
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
CPU Weigher.  Weigh hosts by their CPU usage.

The default is to spread instances across all hosts evenly.  If you prefer
stacking, you can set the 'cpu_weight_multiplier' option to a negative
number and the weighing has the opposite effect of the default.
"""

from oslo.config import cfg
from nova.scheduler.filters import utils
from nova.scheduler import weights
from nova.openstack.common import log as logging
from nova.i18n import _LW

LOG = logging.getLogger(__name__)

# default cpu_weight_multiplier is 0.0,if use cpu instead of ram
# need to config cpu_weight_multiplier
cpu_weight_opts = [
        cfg.FloatOpt('cpu_weight_multiplier',
                     default=0.0,
                     help='Multiplier used for weighing cpu.  Negative '
                          'numbers mean to stack vs spread.'),
]

CONF = cfg.CONF
CONF.register_opts(cpu_weight_opts)

CONF.import_opt('cpu_allocation_ratio', 'nova.scheduler.filters.core_filter')


class CPUWeigher(weights.BaseHostWeigher):
    minval = 0

    def weight_multiplier(self):
        """Override the weight multiplier."""
        return CONF.cpu_weight_multiplier

    def _validate_num_values(self, vals, default=None):
        """repair community edit bug"""
        num_values = len(vals)
        if num_values == 0:
            return default
        try:
            float_vals = map(lambda x: float(x), vals)
            return min(float_vals)
        except Exception:
            pass
        return default

    def _weigh_object(self, host_state, weight_properties):
        """if aggregate don't set ratio, weight is zero"""
        aggregate_vals = utils.aggregate_values_from_db(
            weight_properties['context'],
            host_state.host,
            'cpu_allocation_ratio')

        try:
            ratio = self._validate_num_values(
                aggregate_vals, CONF.cpu_allocation_ratio)
        except ValueError as e:
            LOG.warning(_LW("Could not decode cpu_allocation_ratio: '%s'"), e)
            ratio = CONF.cpu_allocation_ratio
        return host_state.vcpus_total*ratio - host_state.vcpus_used
