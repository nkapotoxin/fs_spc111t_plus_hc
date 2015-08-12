import socket
from struct import pack
from optparse import OptionParser

def _send_arp(device, sender_mac, tag):
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.SOCK_RAW)
        sock.bind((device, socket.SOCK_RAW))

        ARPOP_REQUEST = pack('!H', 0x0001)

        source_mac = pack('!6B', *[int(x,16) for x in sender_mac.split(':')])
        target_mac = pack('!6B', *(0xFF,)*6)

        src_ip = "0.0.0.0"
        dst_ip = "0.0.0.0"
        sender_ip = pack('!4B', *[int(x) for x in src_ip.split('.')])
        target_ip = pack('!4B', *[int(x) for x in dst_ip.split('.')])

        fill = pack('!18B', *(0x00,)*18)
        if tag != "None" and int(tag) != 0:
            arpframe = [
            ### ETHERNET
            # destination MAC addr
            target_mac,
            # source MAC addr
            source_mac,
            pack('!H', 0x8100),
            pack('!H', int(tag)),
            # protocol type (=ARP)
            pack('!H', 0x0806),

            ### ARP
            # logical protocol type (Ethernet/IP)
            pack('!HHBB', 0x0001, 0x0800, 0x0006, 0x0004),
            # operation type
            ARPOP_REQUEST,
            # sender MAC addr
            source_mac,
            # sender IP addr
            sender_ip,
            # target hardware addr
            target_mac,
            # target IP addr
            target_ip,
            pack('!30B', *(0x00,)*30)
            ]
        else:
            arpframe = [
            ### ETHERNET
            # destination MAC addr
            target_mac,
            # source MAC addr
            source_mac,
            # protocol type (=ARP)
            pack('!H', 0x0806),

            ### ARP
            # logical protocol type (Ethernet/IP)
            pack('!HHBB', 0x0001, 0x0800, 0x0006, 0x0004),
            # operation type
            ARPOP_REQUEST,
            # sender MAC addr
            source_mac,
            # sender IP addr
            sender_ip,        # target hardware addr
            target_mac,
            # target IP addr        target_ip,
            pack('!30B', *(0x00,)*30)
            ]
        # send the ARP
        sock.send(''.join(arpframe))
        sock.send(''.join(arpframe))
        sock.send(''.join(arpframe))

def send_arps(device, str_mac_vlan):
    list_mac_vlan = str_mac_vlan.split(";")
    for mac_vlan in list_mac_vlan:
        if not mac_vlan:
            continue
        tmp = mac_vlan.split(",")
        mac = tmp[0].strip()
        vlan = tmp[1].strip()
        _send_arp(device, mac, vlan)

def commandline():
    parser = OptionParser(
        usage="%prog [OPTIONS] device str_mac_vlan ")

    (options, args) = parser.parse_args()

    if len(args) != 2:
        parser.error("error")

    class Args(object):
        pass
    ret = Args()

    ret.device = args[0]
    ret.str_mac_vlan = args[1]
    return ret

def main():
    args = commandline()
    send_arps(args.device,args.str_mac_vlan)
    exit(0)

if __name__ == "__main__":
    main()