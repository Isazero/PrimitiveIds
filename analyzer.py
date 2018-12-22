from scapy.all import *
import sys

ip_list = ""
ports_list = []


def detect_ip(packet):
    if 'IP' in packet:
        global ip_list
        ip_src = packet['IP'].src
        if ip_src not in ip_list:
            ip_list += " " + ip_src

        return ip_list


def detect_ports(packet):
    global ports_list
    if 'TCP' in packet:
        dport = packet['TCP'].dport
        if dport not in ports_list:
            ports_list.append(dport)
    if 'UDP' in packet:
        dport = packet['UDP'].dport
        if dport not in ports_list:
            ports_list.append(dport)

    return ports_list


def print_ports(p_list):
    print("Amount of scanned ports: %s" % len(p_list))
    composite_list = [p_list[x:x + 10] for x in range(0, len(p_list), 10)]
    for i in composite_list:
        print(' '.join(map(str, i)))


def print_ip(ips):
    print("Source(s) from which suspicious traffic came: %s" % ips)


def print_packets_amount(pckts):
    print("Amount of suspicious packets: %s" % pckts)


packets = PcapReader(sys.argv[1])

null_scan = 0
xmas_scan = 0
ping = 0
udp_scan = 0
halfopen_scan_succes = 0
halfopen_scan_closed = 0

ip_list_null = ""
ports_list_null = []
ip_list_xmas = ""
ports_list_xmas = []
ip_list_icmp = ""
ip_list_udp = ""
ports_list_udp = []
ip_list_halfopen = ""
ports_list_halfopen = []
next_packet = None
for index, packet in enumerate(packets):
    if packet.haslayer('TCP'):
        flag = packet['TCP'].flags
        if flag == 0x000:
            ip_list_null = detect_ip(packet)
            ports_list_null = detect_ports(packet)
            null_scan += 1
        if flag == 0x029:
            ip_list_xmas = detect_ip(packet)
            ports_list_xmas = detect_ports(packet)
            xmas_scan += 1
        if flag == 0x002:
            next_packet = packets.next()
            if next_packet.haslayer('TCP'):
                next_flag = next_packet['TCP'].flags
                if next_flag == 0x012:
                    afternext_packet = packets.next()
                    if afternext_packet.haslayer('TCP'):
                        afternext_flag = afternext_packet['TCP'].flags
                        if afternext_flag == 0x004:
                            halfopen_scan_succes += 1
                            ip_list_halfopen = detect_ip(packet)
                            ports_list_halfopen = detect_ports(packet)
            elif next_flag == 0x014:
                halfopen_scan_closed += 1
                ip_list_halfopen = detect_ip(packet)
                ports_list_halfopen = detect_ports(packet)
    if packet.haslayer('ICMP'):
        packet_type = packet['ICMP'].type
        if packet_type == 8:
            ip_list_icmp = detect_ip(packet)
            ping += 1
    if packet.haslayer('UDP'):
        udp_length = packet['UDP'].len
        if udp_length == 8:
            udp_scan += 1
            ip_list_udp = detect_ip(packet)
            ports_list_udp = detect_ports(packet)

if null_scan != 0:
    print("Null scan packets below \n")
    print_ip(ip_list_null)
    print_ports(ports_list_null)
    print_packets_amount(null_scan)
if xmas_scan != 0:
    print("****************************************")
    print("Xmas scan packets below \n")
    print_ip(ip_list_xmas)
    print_ports(ports_list_xmas)
    print_packets_amount(xmas_scan)
if ping != 0:
    print("****************************************")
    print("Icmp ping packets below \n")
    print_ip(ip_list_icmp)
    print_packets_amount(ping)
if udp_scan != 0:
    print("****************************************")
    print("UDP scan packets below \n")
    print_ip(ip_list_udp)
    print_ports(ports_list_udp)
    print_packets_amount(udp_scan)
if halfopen_scan_succes != 0 or halfopen_scan_closed != 0:
    print("****************************************")
    print("Half-Open scan packets below \n")
    print_ip(ip_list_halfopen)
    print_ports(ports_list_halfopen)
    print("Amount of successful scans: %s " % halfopen_scan_succes)
    print("Amount of unsuccessful scans: %s " % halfopen_scan_closed)
