from oslo.config import cfg
from nova.scheduler import weights
from nova.huawei.scheduler import utils as h_utils

# default cpu_usage_multiplier is 0.0,if use cpu instead of ram or cpu core
# need to config cpu_usage_weight_multiplier
cpu_usage_weight_opts = [
        cfg.FloatOpt('cpu_usage_weight_multiplier',
                     default=0.0,
                     help='Multiplier usage for weighing cpu.  Negative '
                          'numbers mean to stack vs spread.'),
]

CONF = cfg.CONF
CONF.register_opts(cpu_usage_weight_opts)

class CPUUsageWeigher(weights.BaseHostWeigher):
    minval = 0

    def weight_multiplier(self):
        """Override cpu usage"""
        return CONF.cpu_usage_weight_multiplier

    def _weigh_object(self, host_state, weight_properties):
        """
        :param host_state:
        :param weight_properties:
        :return:
        """
        usage = h_utils.get_host_cpu_usage(host_state)
        if usage is not None:
            if usage > 100:
                usage = 100.0
            if usage < 0:
                usage = 0.0
            return (100 - usage)
        return 0