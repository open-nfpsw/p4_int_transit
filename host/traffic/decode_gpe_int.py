#!/usr/bin/python

# Copyright (C) 2016, Netronome Systems, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#     Unless required by applicable law or agreed to in writing, software
#     distributed under the License is distributed on an "AS IS" BASIS,
#     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#     See the License for the specific language governing permissions and
#     limitations under the License.
#
#
# A simple utility for decoding GPE INT packets either from a pcap
# or from the network directly
#

import sys
import time

import pcapy
from pcapfile import savefile

from collections import OrderedDict

##############################################################################
# Header definitions                                                         #
##############################################################################

hdr_eth = OrderedDict()
hdr_ipv4 = OrderedDict()
hdr_udp = OrderedDict()
hdr_vxlan_gpe = OrderedDict()
hdr_vxlan_gpe_int = OrderedDict()
hdr_int_header = OrderedDict()

hdr_int_switch_id = OrderedDict()
hdr_int_ingress_ts = OrderedDict()
hdr_int_egress_ts = OrderedDict()
#hdr_int_ingress_port_id = OrderedDict()
#hdr_int_hop_latency = OrderedDict()
hdr_int_q_occupancy = OrderedDict()
hdr_int_ingress_tstamp = OrderedDict()
hdr_int_egress_port_id = OrderedDict()
hdr_int_q_congestion = OrderedDict()
hdr_int_egress_port_tx_utilization = OrderedDict()

hdr_eth['dstAddr'] = 48
hdr_eth['srcAddr'] = 48
hdr_eth['etherType'] = 16

hdr_ipv4['version'] = 4
hdr_ipv4['ihl'] = 4
hdr_ipv4['diffserv'] = 8
hdr_ipv4['totalLen'] = 16
hdr_ipv4['identification '] = 16
hdr_ipv4['flags'] = 3
hdr_ipv4['fragOffset'] = 13
hdr_ipv4['ttl'] = 8
hdr_ipv4['protocol'] = 8
hdr_ipv4['hdrChecksum'] = 16
hdr_ipv4['srcAddr'] = 32
hdr_ipv4['dstAddr'] = 32

hdr_udp['srcPort'] = 16
hdr_udp['dstPort'] = 16
hdr_udp['length'] = 16
hdr_udp['checksum'] = 16

hdr_vxlan_gpe['flags'] = 8
hdr_vxlan_gpe['reserved'] = 16
hdr_vxlan_gpe['next_proto'] = 8
hdr_vxlan_gpe['vni'] = 24
hdr_vxlan_gpe['reserved2'] = 8

hdr_vxlan_gpe_int['int_type'] = 8
hdr_vxlan_gpe_int['rsvd'] = 8
hdr_vxlan_gpe_int['len'] = 8
hdr_vxlan_gpe_int['next_proto'] = 8

hdr_int_header['ver'] = 2
hdr_int_header['rep'] = 2
hdr_int_header['c'] = 1
hdr_int_header['e'] = 1
hdr_int_header['rsvd1'] = 5
hdr_int_header['ins_cnt'] = 5
hdr_int_header['max_hop_cnt'] = 8
hdr_int_header['total_hop_cnt'] = 8
hdr_int_header['instruction_mask_0003'] = 4
hdr_int_header['instruction_mask_0407'] = 4
hdr_int_header['instruction_mask_0811'] = 4
hdr_int_header['instruction_mask_1215'] = 4
hdr_int_header['rsvd2'] = 16

hdr_int_switch_id['bos'] = 1
hdr_int_switch_id['switch_id'] = 31

hdr_int_ingress_ts['bos'] = 1
hdr_int_ingress_ts['value'] = 31

hdr_int_egress_ts['bos'] = 1
hdr_int_egress_ts['value'] = 31

# Compliant INT headers
#hdr_int_ingress_port_id['bos'] = 1
#hdr_int_ingress_port_id['ingress_port_id_1'] = 15
#hdr_int_ingress_port_id['ingress_port_id_0'] = 16

#hdr_int_hop_latency['bos'] = 1
#hdr_int_hop_latency['hop_latency'] = 31
 
hdr_int_q_occupancy['bos'] = 1
hdr_int_q_occupancy['q_occupancy1'] = 7
hdr_int_q_occupancy['q_occupancy0'] = 24

hdr_int_ingress_tstamp['bos'] = 1
hdr_int_ingress_tstamp['ingress_tstamp'] = 31

hdr_int_egress_port_id['bos'] = 1
hdr_int_egress_port_id['egress_port_id'] = 31

hdr_int_q_congestion['bos'] = 1
hdr_int_q_congestion['q_congestion'] = 31

hdr_int_egress_port_tx_utilization['bos'] = 1
hdr_int_egress_port_tx_utilization['egress_port_tx_utilization'] = 31

##############################################################################
# Packet parsing                                                             #
##############################################################################

#
# dump header data
#
def header_print(hdr, hdrname, indent_amount, compact=True):
    I = indent_amount * " "
    if compact == False:
        print I + "--------------------------"
        print I + hdrname
        print I + "--------------------------"
        for fld, fldobj in hdr.items():
            print I + "%s[%d] = 0x%x" % (fld, fldobj['width'], fldobj['value'])
    else:
        print I + hdrname + " |",
        for fld, fldobj in hdr.items():
            print "%s : 0x%x |" % (fld, fldobj['value']),
        print ""

#
# byte oriented header extract
#
def header_extract(hdr_def, data_obj):
    leftover_width = 0
    leftover_value = 0
    ret = OrderedDict()

    for fld, width in hdr_def.items():
        #print fld
        #print width
        #print "--------"
        toget = width
        field_offset = 0
        field_value = 0

        ret[fld] = {'width' : width}

        while toget:
            if leftover_width:
                chunk_width = min(leftover_width, toget)
                leftover_width = leftover_width - chunk_width
                chunk_value = leftover_value >> leftover_width
                leftover_value = leftover_value & (((1 << chunk_width) - 1) << leftover_width)
            else:
                # max one byte at a time
                chunk_width = min(8, toget)
                chunk_value = ord(data_obj['data'][data_obj['offset']])
                if chunk_width != 8:
                    leftover_width = 8 - chunk_width
                    leftover_value = chunk_value & ((1 << leftover_width) - 1)
                    chunk_value >>= leftover_width

                data_obj['offset'] += 1

            field_value |= chunk_value << (toget - chunk_width) 

            #print "%x [%d]" % (field_value, toget)
            toget -= chunk_width
        ret[fld]['value'] = field_value

    if leftover_width:        
        print "bad header definition - not byte aligned"
        sys.exit(1)
    return ret

##############################################################################
# Base INT packet processing                                                 #
##############################################################################

def process_int_pkt(pkt_data):
    data_obj = {'data' : pkt_data, 'offset' : 0}

    #
    # extract headers
    #
    eth = header_extract(hdr_eth, data_obj)
    ipv4 = header_extract(hdr_ipv4, data_obj)
    udp = header_extract(hdr_udp, data_obj)
    vxlan_gpe = header_extract(hdr_vxlan_gpe, data_obj)
    vxlan_gpe_int = header_extract(hdr_vxlan_gpe_int, data_obj)
    int_header = header_extract(hdr_int_header, data_obj)

    #
    #santity checks
    #

    #header_print(eth, "ethernet")
    if eth['etherType']['value'] != 0x800:
        print "Non IPv4"
        return

    #header_print(ipv4, "ipv4")
    if ipv4['protocol']['value'] != 0x11:
        print "Non UDP"
        return
    #header_print(udp, "udp")
    if udp['dstPort']['value'] != 4790:
        print "Non VXLAN GPE"
        return

    #header_print(vxlan_gpe_int, "vxlan_gpe_int")
    #header_print(int_header, "int_header", 4)

    ##############################################################################
    # INT instruction processing                                                 #
    ##############################################################################

    #
    # identify the present INT instructions
    #

    present_options = []

    fields_mask = int_header['instruction_mask_0003']['value'] << 4;
    fields_mask |= int_header['instruction_mask_0407']['value'] << 0;

    options_in_order = [
       ("switch_id",                  hdr_int_switch_id),
       #("ingress_port_id",           hdr_int_ingress_port_id),
       #("hop_latency",               hdr_int_hop_latency),
       ("ingress_ts",                 hdr_int_ingress_ts),
       ("egress_ts",                  hdr_int_egress_ts),
       ("q_occupancy",                hdr_int_q_occupancy),
       ("ingress_tstamp",             hdr_int_ingress_tstamp),
       ("egress_port_id",             hdr_int_egress_port_id),
       ("q_congestion",               hdr_int_q_congestion),
       ("egress_port_tx_utilization", hdr_int_egress_port_tx_utilization),
       ]

    for i in reversed(range(len(options_in_order))):
        if fields_mask & (1 << i):
            present_options.append(options_in_order[len(options_in_order) - i - 1])

    ins_count = int_header['ins_cnt']['value']

    if len(present_options) != ins_count:
        print "error: conflicting instruction count %d " \
              "and instruction mask (%x) with %d bits set" % \
              (ins_count, fields_mask, len(present_options))

    int_len = vxlan_gpe_int['len']['value']

    opt_len = int_len - 3 # 2xLW for int_header + 1xLW vxlan_gpe_int

    if opt_len % ins_count:
        print "error: options length %d is not a multiple of " \
               "instruction count %d " % (opt_len, ins_count)

    opt_sets = opt_len / ins_count
    hdr = None

    for opt_set in range(opt_sets):
        if 0:
            print "%%%%%%%%%%%%%%%%%%%%%%%%%%"
            print "INT option set %d of %d" % (opt_set + 1, opt_sets)
            print "%%%%%%%%%%%%%%%%%%%%%%%%%%"

        for option_name, option_header in present_options: 
            hdr = header_extract(option_header, data_obj)
            header_print(hdr, "[%d] " % (opt_set) + option_name, 4)
    if hdr:
        if hdr['bos']['value'] == 0:
            print "        Invalid BOS"

##############################################################################
# Packet data preperation                                                    #
##############################################################################

#pkts = ['\x003DUfw\x00"3DUf\x08\x00E\x00\x00T\x00\x01\x00\x00@\x11f4\n\x00\x00\x01\n\x00\x00d\xff\x02\x12\xb6\x00@\x00\x00\x00\x00\x00\x05\x11"3\x00\x01\x00\x08\x03\x00\x05\xff\x01\xec\x00\x00\x00\x00\x08\xfe\xed\x00\x00\x00\x08\x00\x00\x01\x11\x01\x11\x11\x11\x80\x00\x00\t\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00']

if len(sys.argv) != 2:
    print "expect either interface or pcap file as argument"
    sys.exit(1)
    

pkts = None
try:
    capfile = open(sys.argv[1], 'rb')
    capdata = savefile.load_savefile(capfile)
    pkts = []
    for pkt_no in range(len(capdata.packets)):
        pkts.append(str(capdata.packets[pkt_no]))
except:
    pass

pktno = 0
if pkts != None:
    for pkt_data in pkts:
        print "packet #%d" % pktno
        process_int_pkt(pkt_data)
        pktno += 1
else:
    try:
        p = pcapy.open_live(sys.argv[1], 1500 , 1 , 0)
    except:
        print "invalid interface or pcap file provided"
        sys.exit(1)

    while True:
        try:
            (header, packet) = p.next()
        except:
            continue

        print "packet #%d" % pktno
        process_int_pkt(str(packet))
        pktno += 1
