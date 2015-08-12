# Copyright (c) 2011 OpenStack Foundation
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

"""Compute-related Utilities and helpers."""

from nova.i18n import _
from nova import objects
from oslo.config import cfg
from lxml import etree
from nova.openstack.common import log

CONF = cfg.CONF

LOG = log.getLogger(__name__)


def get_address_from_xml(xmldoc):
    pci_slots = []
    
    for c in xmldoc.getchildren():
        if c.tag == 'address' and c.get('type') == 'pci':
            pci_slots.append(int(c.get('slot'), 16))
        elif 'bus=pci.0,addr=' in c.get('value', ''):
            pci_slots.append(int(c.get('value')[-4:], 16))
        child_pci_slots = get_address_from_xml(c)
        pci_slots.extend(child_pci_slots)
    
    return pci_slots


def modify_device_xml(sourceXml, pciSlot):
    xml_doc = etree.fromstring(sourceXml)
    xml_doc.append(etree.Element("address", 
                                 type = "pci", 
                                 domain = "0x0000", 
                                 bus = "0x00", 
                                 slot = "0x%x" % pciSlot, 
                                 function = "0x0"))
    xml_str = etree.tostring(xml_doc, pretty_print = True)
    
    return xml_str