#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
import socket
import struct

# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries, though.

class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext
        # (protocol, external ip, port) : line number
        drop_rules = {}
        pass_rules = {}
        geo = {}

        value = config['rule']
        parser = open(value)
        count = 0
        for line in parser:
            count += 1
            split = line.split()
            if split != []:
                if split[0].lower() == 'drop':
                    if split[1].lower() == 'dns': #DNS PACKETS
                        tup = ('udp', split[2], '53')
                        drop_rules[tup] = count
                    else:
                        tup = (split[1], split[2], split[3])
                        drop_rules[tup] = count
                elif split[0].lower() == 'pass':
                    if split[1].lower() == 'dns': #DNS PACKETS
                        tup = ('udp', split[2], '53')
                        drop_rules[tup] = count
                    else:
                        tup = (split[1], split[2], split[3])
                        pass_rules[tup] = count
            else:
                pass

        parser.close()

        poop = open('geoipdb.txt')
        for line in poop:
            split = line.split()
            if geo.has_key(split[2]):
                geo[split[2]].append(split[0:2])
            else:
                geo[split[2]] = [[split[0], split[1]]]
        poop.close()

        for key in geo:
            print key
            print geo[key]
            print '\n'
            # TODO: Load the GeoIP DB ('geoipdb.txt') as well.
        # TODO: Also do some initialization if needed.

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        pass
    #     # IP Header length
    #     header = ord(pkt[0])
    #     mask = 15
    #     header_length_in_bytes = header & mask
    #     header_length = header_length_in_bytes * 4

    #     # External IP 
    #     external_ip = ''
    #     if pkt_dir == PKT_DIR_INCOMING:
    #         external_ip = socket.inet_ntoa(pkt[12:16])
    #     else:
    #         external_ip = socket.inet_ntoa(pkt[16:20])

    #     port, = '',
    #     protocol = ord(pkt[9:10])
    #     prot = ''

    #     # Port and Protocol
    #     if protocol == 6: # TCP
    #         prot = 'tcp'
    #         if pkt_dir == PKT_DIR_INCOMING: # use source port
    #             port_start = header_length
    #             port_end = header_length+2
    #             port, = struct.unpack('!H', pkt[port_start:port_end])
    #         else: # use destination port
    #             port_start = header_length+2
    #             port_end = header_length+4
    #             port, = struct.unpack('!H', pkt[port_start:port_end])
    #         checker = (prot, external_ip, port)
    #         self.check_to_send(checker, pkt_dir, pkt)

    #     elif protocol == 17: # UDP
    #         prot = 'udp'
    #         if pkt_dir == PKT_DIR_INCOMING: # use source port
    #             port_start = header_length
    #             port_end = header_length+2
    #             port, = struct.unpack('!H', pkt[port_start:port_end])
    #         else: # use destination port
    #             port_start = header_length+2
    #             port_end = header_length+4
    #             port, = struct.unpack('!H', pkt[port_start:port_end])
    #         checker = (prot, external_ip, port)
    #         self.check_to_send(checker, pkt_dir, pkt)

    #     elif protocol == 1: # ICMP
    #         prot = 'icmp'
    #         port, = pkt[header_length: header_length+1], 
    #         checker = (prot, external_ip, port)
    #         self.check_to_send(checker, pkt_dir, pkt)

    #     else: # not any of the protocols just send the packet
    #         if pkt_dir == PKT_DIR_INCOMING:
    #             self.iface_int.send_ip_packet(pkt)
    #         elif pkt_dir == PKT_DIR_OUTGOING:
    #             self.iface_ext.send_ip_packet(pkt)

    # def check_to_send(self, tup, pkt_dir, pkt):
    #     # LEFT TO CHECK -- COUNTRY CODE/DOMAIN NAME
    #     line_number = 0
    #     to_send = True
    #     for key in drop_rules:
    #         if key[0] == tup[0]: # checks if the protocol matches
    #             port_split = key[2].split('-')
    #             # checks if port is any, equal or in range 
    #             if port_split[0] == 'any' or port_split[0] == tup[2] or (int(tup[2]) < int(port_split[1]) and int(tup[2]) > int(port_split[0]):
    #                 if (key[1] == 'any' or key[1] == tup[1]):
    #                     if drop_rules[key] > line_number:
    #                         line_number = drop_rules[key]
    #                         to_send = False
    #     for key in pass_rules:
    #         if key[0] == tup[0]:
    #             if (key[1] == 'any' or key[1] == tup[1]) and (key[2] == 'any' or key[2] == tup[2]):
    #                 if drop_rules[key] > line_number:
    #                     line_number = drop_rules[key]
    #                     to_send = True
    #     if to_send is True:
    #         if pkt_dir == PKT_DIR_INCOMING:
    #             self.iface_int.send_ip_packet(pkt)
    #         elif pkt_dir == PKT_DIR_OUTGOING:
    #             self.iface_ext.send_ip_packet(pkt)
    # TODO: You can add more methods as you want.
    def check_ext_ip(self, key, pkt_address):
        cidr = False
        split = key.split('/')
        if len(split) == 2:
            cidr = True
        if cidr == True:
            comp = ''
            list_of_nums = split[0].split('.')
            for x in list_of_nums:
                temp = bin(x)
                temp1 = temp[2:]
                if len(temp1) != 8:
                    count = len(temp1)
                    while count < 8:
                        temp1 = '0' + temp1
                        count += 1
                comp += temp1
            comp2 = ''
            list_of_nums_2 = pkt_address.split('.')
            for x in list_of_nums_2:
                temp = bin(x)
                temp1 = temp[2:]
                if len(temp1) != 8:
                    count = len(temp1)
                    while count < 8:
                        temp1 = '0' + temp1
                        count += 1
                comp2 += temp1
            if comp[0:int(split[1])] == comp2[0:int(split[1])]:
                return True
            else:
                return False
        else:
            if key == 'any':
                return True
            elif key == pkt_address:
                return True
            elif len(key) == 2:
                list_1 = geo[key]
                mid = len(list_1/2)
                if list_1[mid][0]
                    split_pkt_address = pkt_address.split('.')

            else:
                return False 

def binary_search(self, array, pkt_address):
        if len(array) == 0:
            return False

        mid = int(len(array)/2)
        split_pkt_address = pkt_address.split('.')
        pkt_address_num = ''
        #packet ip address
        for x in split_pkt_address:
            pkt_address_num += x

        mid_start = array[mid][0]
        mid_end = array[mid][1]

        #middle array start address
        mid_start_split = mid_start.split('.')
        mid_start_num = ''
        for x in mid_start_split:
            mid_start_num += x

        #middle array end address
        mid_end_split = mid_end.split('.')
        mid_end_num = ''
        for x in mid_end_split:
            mid_end_num += x

        # check if it has been found
        if int(pkt_address_num) >= int(mid_start_num) and int(pkt_address_num) =< int(mid_end_num):
            return True
        # smaller than the start range
        elif int(pkt_address_num) < int(mid_start_num):
            return self.binary_search(array[0:mid], pkt_address)
        # greater than end range
        elif int(pkt_address_num) > int(mid_end_num):
            return self.binary_search(array[mid:], pkt_address)
        else:
            return False






# TODO: You may want to add more classes/functions as well.
