#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING

import socket
import struct
import time

class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext

        print 'bypass mode!'
        
    def handle_packet(self, pkt_dir, pkt):
        # The example code here prints out the source/destination IP addresses,
        # which is unnecessary for your submission.
        src_ip = pkt[12:16]
        dst_ip = pkt[16:20]
        ipid, = struct.unpack('!H', pkt[4:6])    # IP identifier (big endian)

        # TESTING HEADER LENGTH
        header = ord(pkt[0])
        mask = 15
        header_length_in_bytes = header & mask
        header_length = header_length_in_bytes * 4
        dns_parse = []
        
        # TESTING PROTOCOL 
        protocol = ord(pkt[9:10])
        if protocol == 6:
            print 'tcp'
        elif protocol == 17:
            dns_start = header_length + 8
            # print dns_start
            qd_count_start = dns_start+4
            qd_count_end = qd_count_start+2
            qd_count, = struct.unpack('!H', pkt[qd_count_start:qd_count_end])
            # print'qd count'
            # print qd_count
            q_name_start = dns_start+12
            part = ord(pkt[q_name_start])
            while part != 0:
                part = ord(pkt[q_name_start])
                if part == 0:
                    break
                if part < 40:
                    dns_part = []
                    for x in range(0,part):
                        q_name_start+=1
                        part2 = ord(pkt[q_name_start])
                        dns_part.append(chr(part2))
                    dns_parse.append(''.join(dns_part))
                q_name_start+=1
            print dns_parse
            qtype, = struct.unpack('!H', pkt[q_name_start+1:q_name_start+3])
            print 'qtype'
            print qtype
            qclass, = struct.unpack('!H', pkt[q_name_start+3:q_name_start+5])
            print 'qclass'
            print type(qclass)
            print qclass 

        else:
            print 'icmp'

        port, = '',
        
        #TESTING PORT
        # port_length = header_length + 2
        # print port_length
        # port, = struct.unpack('!H', pkt[header_length:port_length])
        # print port


        if pkt_dir == PKT_DIR_INCOMING:
            dir_str = 'incoming'
        else:
            dir_str = 'outgoing'

        print '%s len=%4dB, IPID=%5d  %15s -> %15s' % (dir_str, len(pkt), ipid,
                socket.inet_ntoa(src_ip), socket.inet_ntoa(dst_ip))

        # ... and simply allow the packet.
        if pkt_dir == PKT_DIR_INCOMING:
            self.iface_int.send_ip_packet(pkt)
        elif pkt_dir == PKT_DIR_OUTGOING:
            self.iface_ext.send_ip_packet(pkt)
