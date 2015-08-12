# -*- encoding: utf-8 -*-

from sys import argv
from oslo.config import cfg
from oslo import messaging

CONF=cfg.CONF

class ironicAgentApi(object):
    def __init__(self):
        transport = messaging.get_transport(CONF)
        target = messaging.Target(topic='ironic-agent')
        self.rpc_client = messaging.RPCClient(transport, target)

    def get_volume_connector(self, host=None, kwargs=None):
        ctxt = self.rpc_client.prepare(server=host, version='1.0', retry=3)
        return ctxt.call({}, "get_volume_connector", **kwargs)

    def attach_volume(self, host=None, kwargs=None):
        ctxt = self.rpc_client.prepare(server=host, version='1.0', retry=3)
        return ctxt.call({}, "attach_volume", **kwargs)

    def detach_volume(self, host=None, kwargs=None):
        ctxt = self.rpc_client.prepare(server=host, version='1.0', retry=3)
        return ctxt.call({}, "detach_volume", **kwargs)
        
    def attach_interface(self, host=None, kwargs=None):
        ctxt = self.rpc_client.prepare(server=host, version='1.0')
        return ctxt.call({}, "attach_interface", **kwargs)
        
    def detach_interface(self, host=None, kwargs=None):
        ctxt = self.rpc_client.prepare(server=host, version='1.0')
        return ctxt.call({}, "detach_interface", **kwargs)

    def clean_local_disk(self, host=None, kwargs=None):
        ctxt = self.rpc_client.prepare(server=host, version='1.0')
        return ctxt.call({}, "clean_local_disk", **kwargs)