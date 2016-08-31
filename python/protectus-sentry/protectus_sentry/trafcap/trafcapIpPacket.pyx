# trafcapIpPacket.py
#
# Copyright (c) 2013 Protectus,LLC.  All Rights Reserved.
#
# Classes to help pull data off the wire and update mongo
import subprocess
import time
import trafcap
from datetime import datetime
import traceback
import re
#import numpy
from bisect import bisect_left, insort
# for packet injection
import socket
from impacket import ImpactDecoder, ImpactPacket
import os, sys
from struct import unpack  # For IP Address parsing
from ctypes import Structure, c_uint16, c_uint32, c_uint64, c_int16, c_uint8, c_double, c_char

# CYTHON
from trafcapIpPacket cimport BYTES_RING_SIZE, BYTES_DOC_SIZE, TCPPacketHeaders, TCPSession
from libc.stdint cimport uint64_t, uint32_t, uint16_t, int16_t
from libc.string cimport memset
from libc.stdlib cimport malloc
from cpf_ring cimport *
import random

class IpPacket(object):
    """
    Parent class for handling IPv4 packets 
    """
    # Used to strip chars from end of TCP length field
    leading_num_re=re.compile("""
    ^([0-9]+).*
    """,re.X)

    def __init__(self):
        return

    @classmethod
    def parse(pc, pkt):
        return

    # Legend for how data is stored in the Session Bytes dictionary 
    # and the Capture Bytes dictionary 
    #      [0]         [1] [2]               [3]                       [4]
    # ip1,p1,ip2,p2             offset                                 pkts 
    #  [list(key)   ,  sb,  se, [[0,   ip1_bytes,  ip2_bytes], [],...],  1]
    b_key=0; b_addr1=0; b_port1=1; b_addr2=2; b_port2=3; b_vl=4
    b_sb=1; b_se=2; 
    b_array=3; b_offset=0; b_bytes1=1; b_bytes2=2
    b_pkts=4
    b_ldwt=5       # last_db_write_time
    b_csldw=6      # changed_since_last_db_write
    #b_cc1=7
    #b_loc1=8
    #b_cc2=9
    #b_loc2=10

    capture_dict_key = ((0,0,0,0),0, (0,0,0,0),0,None)

    # Legend for Group dictionary data structure:
    #   0       1   2   3  4  5   6  7  8  9
    #                                       +------- document window ------+
    #  ip1 p1=0 b1 ip2 p2 b2 tbm tem ns ne b[[offset, b1, b2], [...], .....]
    #                                        +--- chunck----+
    # Note that p1 is not stored in TrafcapContainer dictionary
    g_ip1=0;         g_b1=1
    g_ip2=2; g_p2=3; g_b2=4
    g_tbm=5; g_tem=6
    g_ns=7; g_ne=8
    g_b=9; g_offset=0; g_1=1; g_2=2
    g_pkts=10
    g_proto=11
    g_cc1=12
    g_loc1=13
    g_cc2=14
    g_loc2=15
    g_id=16      # mongo object id
    g_vl=17      # vlan id

    # Session criteria is same for TCP and UDP....ICMP and Other must override
#    @classmethod
#    def buildCriteriaDoc(pc, ci, si, a_info):
#        session_criteria = {"ip1":trafcap.tupleToInt(a_info[ci][pc.i_addr]),
#                         "p1":a_info[ci][pc.i_port],
#                         "ip2":trafcap.tupleToInt(a_info[si][pc.i_addr]),
#                         "p2":a_info[si][pc.i_port],
#                         "tbm":trafcap.secondsToMinute(a_info[pc.i_tb]),
#                         "tem":{'$gte':trafcap.secondsToMinute(a_info[pc.i_tb])}}
#        return session_criteria

    # Session info is different for each protocol
    @classmethod
    def buildInfoDoc(pc, ci, si, a_info):
        return

    @classmethod
    def buildBytesDoc(pc, ci, si, a_info, a_bytes):
        session_bytes = {"ip1":trafcap.tupleToInt(a_info[ci][pc.i_addr]),
                         "p1":a_info[ci][pc.i_port],
                         "ip2":trafcap.tupleToInt(a_info[si][pc.i_addr]),
                         "p2":a_info[si][pc.i_port],
                         "sb":a_bytes[pc.b_sb],
                         "se":a_bytes[pc.b_se],
                         "sbm":trafcap.secondsToMinute(a_bytes[pc.b_sb]),
                         "sem":trafcap.secondsToMinute(a_bytes[pc.b_se]),
                         "pk":a_bytes[pc.b_pkts],
                         "pr":a_info[pc.i_proto],
                         "b":a_bytes[pc.b_array],
                         "cc1":a_info[pc.i_cc1],
                         "loc1":a_info[pc.i_loc1],
                         "cc2":a_info[pc.i_cc2],
                         "loc2":a_info[pc.i_loc2]}
        if a_info[pc.i_vl]: session_bytes['vl'] = a_info[pc.i_vl]
        return session_bytes

    @classmethod
    def buildGroupsDoc(pc, a_group):
        #group_criteria = {"ip1":a_group[pc.g_ip1],
        #                  "ip2":a_group[pc.g_ip2],
        #                  "p2":a_group[pc.g_p2],
        #                  "tbm":a_group[pc.g_tbm]}

        group_bytes = []
        for item in a_group[pc.g_b]:
            if item[pc.g_1] != 0 or item[pc.g_2] != 0:
                group_bytes.append(item)

        group_data = {"ip1":a_group[pc.g_ip1],
                      "b1":a_group[pc.g_b1],
                      "ip2":a_group[pc.g_ip2],
                      "p2":a_group[pc.g_p2],
                      "b2":a_group[pc.g_b2],
                      "tbm":a_group[pc.g_tbm],
                      "tem":a_group[pc.g_tem],
                      "ns":a_group[pc.g_ns],
                      "ne":a_group[pc.g_ne],
                      #"pk":a_group[pc.g_pkts],
                      "pr":a_group[pc.g_proto],
                      "b":group_bytes,
                      "cc1":a_group[pc.g_cc1],
                      "loc1":a_group[pc.g_loc1],
                      "cc2":a_group[pc.g_cc2],
                      "loc2":a_group[pc.g_loc2]}
        if a_group[pc.g_vl]: group_data['vl'] = a_group[pc.g_vl]
        return group_data

    @classmethod
    def startSniffer(pc):
        return

    @classmethod
    def getSessionKey(pc, a_bytes):
        # If no vlan_id, set it to None so key is valid.  Happens at startup
        # when reading docs in from mongo to create session_history
        if not 'vl' in a_bytes: a_bytes['vl'] = None
        return (a_bytes['ip1'], a_bytes['p1'], a_bytes['ip2'], a_bytes['p2'], a_bytes['vl'])

    @classmethod
    def getGroupKey(pc, a_bytes):
        return (a_bytes['ip1'], a_bytes['ip2'], a_bytes['p2'])

    @classmethod
    def updateGroupsDict(pc, a_bytes, chunck_size, doc_win_start):
        tmp_array = []
        for a_index in range(0, 90, 1):
            tmp_array.append([a_index*chunck_size, 0, 0])

        a_group =[a_bytes['ip1'], 0,
                  a_bytes['ip2'], a_bytes['p2'], 0,
                  doc_win_start, trafcap.secondsToMinute(a_bytes['se']),
                  0, 0,
                  tmp_array, 0, 
                  a_bytes.get('pr', None),
                  a_bytes.get('cc1', None),
                  a_bytes.get('loc1', None),
                  a_bytes.get('cc2', None),
                  a_bytes.get('loc2', None),
                  None, 
                  a_bytes.get('vl', None)]

        return a_group

    @classmethod
    def updateInfoDict(pc, data, a_info):
        print 'Override IpPacket.updateInfoDict() in subclass'
        return

    @classmethod
    def findClient(pc, data, new_info):
        return

    @classmethod
    def findInOutBytes(pc, data):
        subnet = trafcap.local_subnet
        # See if traffic is inbound or outbound & update the inbound index
        ip1 = data[pc.p_ip1]
        ip2 = data[pc.p_ip2]
        inbound_bytes = 0
        outbound_bytes = 0
        if ip1[pc.p_bytes] > 0:
            # ip1 has traffic 
            if trafcap.inLocalSubnet(subnet, ip1[pc.p_addr]) and not \
               trafcap.inLocalSubnet(subnet, ip2[pc.p_addr]):
                # outbound traffic
                outbound_bytes += ip1[pc.p_bytes] 
            else:
                # ip1 !in local_subnet or ip2 in local_subnet 
                # This case handles inbound, internal, and external traffic 
                inbound_bytes += ip1[pc.p_bytes]
        
        if ip2[pc.p_bytes] > 0: 
            # ip2 has traffic 
            if trafcap.inLocalSubnet(subnet, ip2[pc.p_addr]) and not \
               trafcap.inLocalSubnet(subnet, ip1[pc.p_addr]):
                # outbound traffic
                outbound_bytes += ip2[pc.p_bytes] 
            else:
                # ip2 !in local_subnet or ip1 in local_subnet 
                # This case handles inbound, internal, and external traffic 
                inbound_bytes += ip2[pc.p_bytes]

        return inbound_bytes, outbound_bytes
        
    @classmethod
    def buildInfoDictItem(pc, key, data):
        print 'Override IpPacket.buildInfoDictItem() in subclass'

    @classmethod
    def buildBytesDictItem(pc, key, data, curr_seq, ip1_bytes, ip2_bytes):
        if key == pc.capture_dict_key:
            new_bytes = [list(key), curr_seq, curr_seq, 
                         [[0,0,0]], 1, 
                         float(data[pc.p_etime]), True]
        else:
            new_bytes = [list(key), curr_seq, curr_seq,
                         [[0, ip1_bytes, ip2_bytes]], 1, 
                         float(data[pc.p_etime]), True]
        return new_bytes


cdef inline uint64_t peg_to_minute(uint64_t timestamp):
    return timestamp - (timestamp % 60)

cdef inline uint64_t peg_to_15minute(uint64_t timestamp):
    return timestamp - (timestamp % 900)

cdef inline uint64_t peg_to_180minute(uint64_t timestamp):
    return timestamp - (timestamp % 10800)

cdef inline calc_group1_offset(uint64_t timestamp):
    #return ((timestamp-timestamp%10)/10)%90
    return (timestamp/10)%90

cdef inline calc_group2_offset(uint64_t timestamp):
    #return ((timestamp-timestamp%10)/120)%90
    return (timestamp/120)%90

# These used to find shared_memory capture_group slot from group_tbm.
# Three reserved capture_group slots so slot number will be either 0, 1, or 2.  
#cdef inline calc_capture_group1_slot(uint64_t timestamp):
#    return (timestamp/900)%3

#cdef inline calc_capture_group2_slot(uint64_t timestamp):
#    return (timestamp/10800)%3


# Heads up: These structs are defined twice so that both pure python and
# lower-level cython can know about them.  Useful for shared memory stuff.
class PythonGenericPacketHeaders(Structure):
    _fields_ = (
        ("timestamp", c_double),
    )
    

class PythonTCPPacketHeaders(Structure):
    _fields_ = (
        ("base", PythonGenericPacketHeaders),
        ("ip1", c_uint32),
        ("port1", c_uint16),
        ("ip2", c_uint32),
        ("port2", c_uint16),
        ("vlan_id", c_int16),
        ("bytes", c_uint64),
        ("flags", c_uint16)
    )

class PythonUDPPacketHeaders(Structure):
    _fields_ = (
        ("base", PythonGenericPacketHeaders),
        ("ip1", c_uint32),
        ("port1", c_uint16),
        ("ip2", c_uint32),
        ("port2", c_uint16),
        ("vlan_id", c_int16),
        ("bytes", c_uint64),
    )


class PythonGenericSession(Structure):
    _fields_ = (
        ("tb", c_double),
        ("te", c_double),

        ("packets", c_uint64),
        ("traffic_bytes", c_uint32 * BYTES_RING_SIZE * 2)
    )

class PythonTCPSession(Structure):
    _fields_ = (
        ("base", PythonGenericSession),
        ("ip1", c_uint32),
        ("port1", c_uint16),
        ("bytes1", c_uint64),
        ("flags1", c_uint16),
        ("cc1", c_char * 2),

        ("ip2", c_uint32),
        ("port2", c_uint16),
        ("bytes2", c_uint64),
        ("flags2", c_uint16),
        ("cc2", c_char * 2),

        ("vlan_id", c_int16),
    )

class PythonUDPSession(Structure):
    _fields_ = (
        ("base", PythonGenericSession),
        ("ip1", c_uint32),
        ("port1", c_uint16),
        ("bytes1", c_uint64),
        ("cc1", c_char * 2),

        ("ip2", c_uint32),
        ("port2", c_uint16),
        ("bytes2", c_uint64),
        ("cc2", c_char * 2),

        ("vlan_id", c_int16),
    )

class PythonGenericGroup(Structure):
    _fields_ = (
        ("tbm", c_double),
        ("tem", c_double),
        ("traffic_bytes", c_uint32 * 90 * 2),
        ("ns", c_uint32),
        ("ne", c_uint32),
        ("csldw", c_uint8),
    )

class PythonTCPGroup(Structure):
    _fields_ = (
        ("base", PythonGenericGroup),
        ("ip1", c_uint32),
        ("bytes1", c_uint64),
        ("cc1", c_char * 2),

        ("ip2", c_uint32),
        ("port2", c_uint16),
        ("bytes2", c_uint64),
        ("cc2", c_char * 2),

        ("vlan_id", c_int16),
    )

class PythonUDPGroup(Structure):
    _fields_ = (
        ("base", PythonGenericGroup),
        ("ip1", c_uint32),
        ("bytes1", c_uint64),
        ("cc1", c_char * 2),

        ("ip2", c_uint32),
        ("port2", c_uint16),
        ("bytes2", c_uint64),
        ("cc2", c_char * 2),

        ("vlan_id", c_int16),
    )


cdef int parse_tcp_packet(GenericPacketHeaders* g_pkt, pfring_pkthdr* hdr) except -1:
    cdef TCPPacketHeaders* shared_pkt = <TCPPacketHeaders*>g_pkt

    shared_pkt.ip1 = hdr.extended_hdr.parsed_pkt.ip_src.v4
    shared_pkt.ip2 = hdr.extended_hdr.parsed_pkt.ip_dst.v4
    shared_pkt.port1 = hdr.extended_hdr.parsed_pkt.l4_src_port
    shared_pkt.port2 = hdr.extended_hdr.parsed_pkt.l4_dst_port
    shared_pkt.base.timestamp = <double>hdr.ts.tv_sec + (<double>hdr.ts.tv_usec / 1000000.0)
    #shared_pkt.vlan_id = hdr.extended_hdr.parsed_pkt.vlan_id
    shared_pkt.vlan_id = hdr.extended_hdr.parsed_pkt.vlan_id if trafcap.ingest_vlan_id else 0
    shared_pkt.bytes = hdr.c_len
    shared_pkt.flags = hdr.extended_hdr.parsed_pkt.tcp.flags


cdef int parse_udp_packet(GenericPacketHeaders* g_pkt, pfring_pkthdr* hdr) except -1:
    cdef UDPPacketHeaders* shared_pkt = <UDPPacketHeaders*>g_pkt

    shared_pkt.ip1 = hdr.extended_hdr.parsed_pkt.ip_src.v4
    shared_pkt.ip2 = hdr.extended_hdr.parsed_pkt.ip_dst.v4
    shared_pkt.port1 = hdr.extended_hdr.parsed_pkt.l4_src_port
    shared_pkt.port2 = hdr.extended_hdr.parsed_pkt.l4_dst_port
    shared_pkt.base.timestamp = <double>hdr.ts.tv_sec + (<double>hdr.ts.tv_usec / 1000000.0)
    #shared_pkt.vlan_id = hdr.extended_hdr.parsed_pkt.vlan_id
    shared_pkt.vlan_id = hdr.extended_hdr.parsed_pkt.vlan_id if trafcap.ingest_vlan_id else 0
    shared_pkt.bytes = hdr.c_len


cdef int print_tcp_packet(GenericPacketHeaders* g_packet) except -1:
    cdef TCPPacketHeaders* packet = <TCPPacketHeaders*>g_packet

    print "IP1: ", str(packet.ip1)
    print "port1: ", str( packet.port1)
    print ""
    print "IP2: ", str( packet.ip2)
    print "port2: ", str( packet.port2)
    print ""
    print "bytes: ", str( packet.bytes)
    print "flags: ", str( packet.flags)
    print "vlanid: ", str( packet.vlan_id)
    print "timestamp: ", str( packet.base.timestamp)

cdef int print_tcp_session(GenericSession* g_session, uint64_t time_marker) except -1:
    cdef TCPSession* session = <TCPSession*>g_session

    print "IP1: ", str(session.ip1),
    print "port1: ", str( session.port1),
    print "bytes1: ", str( session.bytes1),
    print "flags1: ", str( session.flags1)
    print "IP2: ", str( session.ip2),
    print "port2: ", str( session.port2),
    print "bytes2: ", str( session.bytes2),
    print "flags2: ", str( session.flags2)
    print "vlanid: ", str( session.vlan_id),
    print "time begin: ", str( session.base.tb),
    print "time end: ", str( session.base.te),
    print "num packets: ", str( session.base.packets)
    print "B1\tB2"
    for cursor in range(BYTES_RING_SIZE):
        b = session.base.traffic_bytes[cursor]
        print str(b[0])+"\t"+str(b[1])+("<--" if cursor == time_marker % BYTES_RING_SIZE else "")
    
cdef int print_tcp_group(GenericGroup* g_group, uint64_t time_marker, uint8_t group_type) except -1:
    cdef TCPGroup* group = <TCPGroup*>g_group

    print "IP1: ", str(group.ip1),
    print "bytes1: ", str( group.bytes1),
    print "IP2: ", str( group.ip2),
    print "port2: ", str( group.port2),
    print "bytes2: ", str( group.bytes2),
    print "vlanid: ", str( group.vlan_id),
    print "time begin: ", str( group.base.tbm),
    print "time end: ", str( group.base.tem),
    print "ns: ", str( group.base.ns),
    print "ne: ", str( group.base.ne)
    print "B1\tB2"
    for cursor in range(90):
        offset = calc_group2_offset(time_marker) if group_type else calc_group1_offset(time_marker)
        b0 = group.base.traffic_bytes[cursor][0]
        b1 = group.base.traffic_bytes[cursor][1]
        if b0 != 0 and b1 != 0:
            print str(cursor)+"\t"+\
                              str(b0)+\
                              "\t"+\
                              str(b1)+("<--" if cursor == offset else "")
    
cdef GenericSession* alloc_tcp_capture_session():
    cdef TCPSession* session = <TCPSession*>malloc(sizeof(TCPSession))

    # Zero out almost everything
    memset(session, 0, sizeof(TCPSession))

    session.base.tb = time.time()
    session.base.te = time.time()
    session.vlan_id = -1

    return <GenericSession*>session

cdef GenericSession* alloc_udp_capture_session():
    cdef UDPSession* session = <UDPSession*>malloc(sizeof(UDPSession))

    # Zero out almost everything
    memset(session, 0, sizeof(UDPSession))

    session.base.tb = time.time()
    session.base.te = time.time()
    session.vlan_id = -1

    return <GenericSession*>session

cdef int generate_tcp_session(GenericSession* g_session, GenericPacketHeaders* g_packet):
    cdef TCPSession *session = <TCPSession*>g_session
    cdef TCPPacketHeaders* packet = <TCPPacketHeaders*>g_packet

    # SYN flag detected
    if packet.flags == 2:
        session.ip1 = packet.ip1
        session.port1 = packet.port1
        session.flags1 = packet.flags<<((packet.flags&16)/2)
        session.bytes1 = packet.bytes
        session.base.traffic_bytes[<uint64_t>packet.base.timestamp % BYTES_RING_SIZE][0] = packet.bytes

        session.ip2 = packet.ip2
        session.port2 = packet.port2
        session.bytes2 = 0
        session.flags2 = 0

    # SYN-ACK flags detected - not sure what happened to SYN packet
    elif (packet.flags == 18) or (packet.port2 > packet.port1): 
        session.ip1 = packet.ip2
        session.port1 = packet.port2
        session.bytes1 = 0
        session.flags1 = 0

        session.ip2 = packet.ip1
        session.port2 = packet.port1
        session.flags2 = packet.flags<<((packet.flags&16)/2)
        session.bytes2 = packet.bytes
        session.base.traffic_bytes[<uint64_t>packet.base.timestamp % BYTES_RING_SIZE][1] = packet.bytes

    # No SYN bit and (port1 >= port2)
    else:
        session.ip1 = packet.ip1
        session.port1 = packet.port1
        session.flags1 = packet.flags<<((packet.flags&16)/2)
        session.bytes1 = packet.bytes
        session.base.traffic_bytes[<uint64_t>packet.base.timestamp % BYTES_RING_SIZE][0] = packet.bytes

        session.ip2 = packet.ip2
        session.port2 = packet.port2
        session.bytes2 = 0
        session.flags2 = 0

    session.vlan_id = packet.vlan_id
    session.base.tb = packet.base.timestamp
    session.base.te = packet.base.timestamp
    session.base.packets = 1

    session.cc1[0] = 0
    session.cc1[1] = 0
    session.cc2[0] = 0
    session.cc2[1] = 0

    return 0
    
cdef int generate_udp_session(GenericSession* g_session, GenericPacketHeaders* g_packet):
    cdef UDPSession *session = <UDPSession*>g_session
    cdef UDPPacketHeaders* packet = <UDPPacketHeaders*>g_packet

    if (packet.port2 > packet.port2):
        session.ip1 = packet.ip1
        session.port1 = packet.port1
        session.bytes1 = packet.bytes
        session.base.traffic_bytes[<uint64_t>packet.base.timestamp % BYTES_RING_SIZE][0] = packet.bytes

        session.ip2 = packet.ip2
        session.port2 = packet.port2
        session.bytes2 = 0

    else:
        session.ip1 = packet.ip2
        session.port1 = packet.port2
        session.bytes1 = 0

        session.ip2 = packet.ip1
        session.port2 = packet.port1
        session.bytes2 = packet.bytes
        session.base.traffic_bytes[<uint64_t>packet.base.timestamp % BYTES_RING_SIZE][1] = packet.bytes

    session.vlan_id = packet.vlan_id
    session.base.tb = packet.base.timestamp
    session.base.te = packet.base.timestamp
    session.base.packets = 1

    session.cc1[0] = 0
    session.cc1[1] = 0
    session.cc2[0] = 0
    session.cc2[1] = 0

    return 0
    
cdef int update_tcp_session(GenericSession* g_session, GenericPacketHeaders* g_packet):
    cdef TCPSession* session = <TCPSession*>g_session
    cdef TCPPacketHeaders* packet = <TCPPacketHeaders*>g_packet

    # We need timestamp to be an int to navigate bytes
    cdef uint64_t current_packet_second = <uint64_t>packet.base.timestamp
    cdef uint64_t last_packet_second = <uint64_t>session.base.te

    # Clean up old bytes slots, if needed.  The slots to be cleaned are
    # everything between the last update and the current time, including
    # the current time, but not including the last update.  
    cdef int slot_second
    if last_packet_second <= current_packet_second - BYTES_RING_SIZE:
        # Clear everything
        memset(session.base.traffic_bytes, 0, sizeof(session.base.traffic_bytes))
    elif last_packet_second < current_packet_second:
        # Only clear the slots that have occured between then and now.
        for slot_second in range(last_packet_second + 1, current_packet_second + 1):
            session.base.traffic_bytes[slot_second % BYTES_RING_SIZE][0] = 0
            session.base.traffic_bytes[slot_second % BYTES_RING_SIZE][1] = 0

    #session.vlan_id = vlan
    #session.tb = 
    session.base.te = packet.base.timestamp
    session.base.packets += 1
    cdef int bytes_slot = current_packet_second % BYTES_RING_SIZE
    if (session.ip1 == packet.ip1):
        #session.ip1 = packet.ip1
        #session.port1 = packet.port1
        session.bytes1 += packet.bytes
        session.flags1 |= packet.flags<<((packet.flags&16)/2)
        session.base.traffic_bytes[bytes_slot][0] += packet.bytes

    else:
        #session.ip2 = packet.ip2
        #session.port2 = packet.port2
        session.bytes2 += packet.bytes
        session.flags2 |= packet.flags<<((packet.flags&16)/2)
        session.base.traffic_bytes[bytes_slot][1] += packet.bytes

    return 0

cdef int update_udp_session(GenericSession* g_session, GenericPacketHeaders* g_packet):
    cdef UDPSession* session = <UDPSession*>g_session
    cdef UDPPacketHeaders* packet = <UDPPacketHeaders*>g_packet

    # We need timestamp to be an int to navigate bytes
    cdef uint64_t current_packet_second = <uint64_t>packet.base.timestamp
    cdef uint64_t last_packet_second = <uint64_t>session.base.te

    # Clean up old bytes slots, if needed.  The slots to be cleaned are
    # everything between the last update and the current time, including
    # the current time, but not including the last update.  
    cdef int slot_second
    if last_packet_second <= current_packet_second - BYTES_RING_SIZE:
        # Clear everything
        memset(session.base.traffic_bytes, 0, sizeof(session.base.traffic_bytes))
    elif last_packet_second < current_packet_second:
        # Only clear the slots that have occured between then and now.
        for slot_second in range(last_packet_second + 1, current_packet_second + 1):
            session.base.traffic_bytes[slot_second % BYTES_RING_SIZE][0] = 0
            session.base.traffic_bytes[slot_second % BYTES_RING_SIZE][1] = 0

    #session.vlan_id = vlan
    #session.tb = 
    session.base.te = packet.base.timestamp
    session.base.packets += 1
    cdef int bytes_slot = current_packet_second % BYTES_RING_SIZE
    if (session.ip1 == packet.ip1):
        #session.ip1 = packet.ip1
        #session.port1 = packet.port1
        session.bytes1 += packet.bytes
        session.base.traffic_bytes[bytes_slot][0] += packet.bytes

    else:
        #session.ip2 = packet.ip2
        #session.port2 = packet.port2
        session.bytes2 += packet.bytes
        session.base.traffic_bytes[bytes_slot][1] += packet.bytes

    return 0



cdef object generate_tcp_session_key_from_pkt(GenericPacketHeaders* g_pkt):
    cdef TCPPacketHeaders* pkt = <TCPPacketHeaders*>g_pkt
    
    key = 0
    if pkt.ip1 > pkt.ip2:
        key += pkt.ip1
        key *= 2 ** 16    # shift to make room for port1
        key += pkt.port1
        key *= 2 ** 32    # shift to make room for ip2 
        key += pkt.ip2
        key *= 2 ** 16    # shift to make room for port2
        key += pkt.port2
        key *= 2 ** 16    # shift to make room for vlan_id
    else:
        key += pkt.ip2
        key *= 2 ** 16
        key += pkt.port2
        key *= 2 ** 32
        key += pkt.ip1
        key *= 2 ** 16
        key += pkt.port1
        key *= 2 ** 16
        
    key += pkt.vlan_id

    return <object>key
      

cdef object generate_udp_session_key_from_pkt(GenericPacketHeaders* g_pkt):
    cdef UDPPacketHeaders* pkt = <UDPPacketHeaders*>g_pkt
    
    key = 0
    if pkt.ip1 > pkt.ip2:
        key += pkt.ip1
        key *= 2 ** 16
        key += pkt.port1
        key *= 2 ** 32
        key += pkt.ip2
        key *= 2 ** 16
        key += pkt.port2
        key *= 2 ** 16
    else:
        key += pkt.ip2
        key *= 2 ** 16
        key += pkt.port2
        key *= 2 ** 32
        key += pkt.ip1
        key *= 2 ** 16
        key += pkt.port1
        key *= 2 ** 16
        
    key += pkt.vlan_id

    return <object>key
        

cdef object generate_tcp_session_key_from_session(GenericSession* g_session):
    cdef TCPSession* session = <TCPSession*>g_session
    
    key = 0
    if session.ip1 > session.ip2:
        key += session.ip1
        key *= 2 ** 16
        key += session.port1
        key *= 2 ** 32
        key += session.ip2
        key *= 2 ** 16
        key += session.port2
        key *= 2 ** 16
    else:
        key += session.ip2
        key *= 2 ** 16
        key += session.port2
        key *= 2 ** 32
        key += session.ip1
        key *= 2 ** 16
        key += session.port1
        key *= 2 ** 16
        
    key += session.vlan_id

    return <object>key

cdef object generate_udp_session_key_from_session(GenericSession* g_session):
    cdef UDPSession* session = <UDPSession*>g_session
    
    key = 0
    if session.ip1 > session.ip2:
        key += session.ip1
        key *= 2 ** 16
        key += session.port1
        key *= 2 ** 32
        key += session.ip2
        key *= 2 ** 16
        key += session.port2
        key *= 2 ** 16
    else:
        key += session.ip2
        key *= 2 ** 16
        key += session.port2
        key *= 2 ** 32
        key += session.ip1
        key *= 2 ** 16
        key += session.port1
        key *= 2 ** 16
        
    key += session.vlan_id

    return <object>key

cdef object generate_tcp_group_key_from_session(GenericSession* g_session, uint8_t group_type):
    cdef TCPSession* session = <TCPSession*>g_session
    
    key = 0
    if session.ip1 > session.ip2:
        key += session.ip1
        key *= 2 ** 32 
        key += session.ip2
        key *= 2 ** 16 
        key += session.port2
        key *= 2 ** 16
    else:
        key += session.ip2
        key *= 2 ** 16 
        key += session.port2
        key *= 2 ** 32 
        key += session.ip1
        key *= 2 ** 16 
        
    key += session.vlan_id
    key *= 2 ** 64 
    key += peg_to_180minute(<uint64_t>session.base.tb) if group_type else peg_to_15minute(<uint64_t>session.base.tb)

    return <object>key

cdef object generate_udp_group_key_from_session(GenericSession* g_session, uint8_t group_type):
    cdef UDPSession* session = <UDPSession*>g_session
    
    key = 0
    if session.ip1 > session.ip2:
        key += session.ip1
        key *= 2 ** 32 
        key += session.ip2
        key *= 2 ** 16 
        key += session.port2
        key *= 2 ** 16
    else:
        key += session.ip2
        key *= 2 ** 16 
        key += session.port2
        key *= 2 ** 32 
        key += session.ip1
        key *= 2 ** 16 
        
    key += session.vlan_id
    key *= 2 ** 64 
    key += peg_to_180minute(<uint64_t>session.base.tb) if group_type else peg_to_15minute(<uint64_t>session.base.tb)

    return <object>key

cdef object generate_tcp_group_key_from_group(GenericGroup* g_group):
    cdef TCPGroup* group = <TCPGroup*>g_group
    
    key = 0
    if group.ip1 > group.ip2:
        key += group.ip1
        key *= 2 ** 32 
        key += group.ip2
        key *= 2 ** 16 
        key += group.port2
        key *= 2 ** 16
    else:
        key += group.ip2
        key *= 2 ** 16 
        key += group.port2
        key *= 2 ** 32 
        key += group.ip1
        key *= 2 ** 16 
        
    key += group.vlan_id
    key *= 2 ** 64 
    key += group.base.tbm

    return <object>key

cdef object generate_udp_group_key_from_group(GenericGroup* g_group):
    cdef UDPGroup* group = <UDPGroup*>g_group
    
    key = 0
    if group.ip1 > group.ip2:
        key += group.ip1
        key *= 2 ** 32 
        key += group.ip2
        key *= 2 ** 16 
        key += group.port2
        key *= 2 ** 16
    else:
        key += group.ip2
        key *= 2 ** 16 
        key += group.port2
        key *= 2 ** 32 
        key += group.ip1
        key *= 2 ** 16 
        
    key += group.vlan_id
    key *= 2 ** 64 
    key += group.base.tbm

    return <object>key


cdef int write_tcp_session(object info_bulk_writer, object bytes_bulk_writer, object info_collection, list object_ids, GenericSession* g_session, int slot, uint64_t second_to_write_from, uint64_t second_to_write_to, GenericSession* g_capture_session, GenericSession* l_session, object live_session_locks) except -1:
    cdef TCPSession* session = <TCPSession*>g_session
    cdef TCPSession* capture_session = <TCPSession*>g_capture_session
    cdef TCPSession* live_session = <TCPSession*>l_session

    cdef uint64_t sb = second_to_write_from
    cdef uint64_t se
    cdef int tdm

    # General Plan for writes:
    # At this point, we know there needs to be a write.  The question is
    # whether or not we need to create and insert a new info doc or not.  If we
    # need a new info_doc, we insert without using the bulk_writer, because we
    # want to get back the object id.  Everything else is just added to the
    # bulk_writer for later execution.

    # Note: Sometimes we wrap numbers in python int() before we commit them to
    # a dictionary.  This is to prevent Cython from making uint64 into python
    # Longs by default.  (Since we're commiting to disk, we'll do our best to
    # save bytes.

    object_id = object_ids[slot]
    if not object_id:
        # We need to insert a new info doc
        info_doc = {
            "ip1":session.ip1,
            "p1":session.port1,
            "b1":int(session.bytes1),
            "f1":session.flags1,
            "ip2":session.ip2,
            "p2":session.port2,
            "b2":int(session.bytes2),
            "f2":session.flags2,
            "bt":int(session.bytes1+session.bytes2),
            "tbm":peg_to_minute(<uint64_t>session.base.tb),
            "tem":peg_to_minute(<uint64_t>session.base.te),
            "tb":session.base.tb,
            "te":session.base.te,
            "pk":int(session.base.packets)
        }

        # Set CC and vlanId only for sessionInfo & Bytes, not for captureInfo & Bytes
        if live_session_locks:
            # Get cc for new info_doc and update session (which is actually a session_copy)
            cc1, name1, loc1 = trafcap.geoIpLookupInt(session.ip1)
            cc2, name2, loc2 = trafcap.geoIpLookupInt(session.ip2)
            
            # May need to update cc1 &/or cc2 in original session.
            if cc1 or cc2:
                lock = live_session_locks[slot % SESSIONS_PER_LOCK]
                lock.acquire()
    
                if cc1: 
                    info_doc["cc1"] = cc1
                    # Populate session_copy for use when creating bytes_doc 
                    # Populate original session for use during future writes
                    session.cc1[0] = live_session.cc1[0] = ord(cc1[0])
                    session.cc1[1] = live_session.cc1[1] = ord(cc1[1])
    
                if cc2: 
                    info_doc["cc2"] = cc2
                    # Populate session_copy for use when creating bytes_doc 
                    # Populate original session for use during future writes
                    session.cc2[0] = live_session.cc2[0] = ord(cc2[0])
                    session.cc2[1] = live_session.cc2[1] = ord(cc2[1])
    
                lock.release()

            if session.vlan_id >= 0: info_doc['vl'] = session.vlan_id
                    
        tdm = <int>(session.base.te - session.base.tb)
        if tdm >= trafcap.lrs_min_duration: info_doc['tdm'] = tdm

        # Insert the new doc and record the objectid
        if trafcap.options.mongo:
            try:
                object_ids[slot] = info_collection.insert(info_doc)
            except Exception, e:
                # Something went wrong 
                if not trafcap.options.quiet:
                    print e, info_doc, traceback.format_exc()
                trafcap.logException(e, info_doc=info_doc)
            #print info_doc,"at",object_ids[slot]

    else:
        # If we're not inserting a new doc, we're updating an existing one.
        set_doc = { "b1": int(session.bytes1),
                    "b2": int(session.bytes2),
                    "bt": int(session.bytes1+session.bytes2),
                    "pk": int(session.base.packets),
                    "te": session.base.te,
                    "tem": peg_to_minute(<uint64_t>session.base.te) }

        tdm = <int>(session.base.te - session.base.tb)
        if tdm >= trafcap.lrs_min_duration: set_doc['tdm'] = tdm

        info_update = { "$set": set_doc } 

        if trafcap.options.mongo:
            try:
                info_bulk_writer.find({"_id": object_ids[slot]}).update(info_update)
            except Exception, e:
                # Something went wrong 
                if not trafcap.options.quiet:
                    print e, info_update,traceback.format_exc()
                trafcap.logException(e, info_update=info_update)

    # We always need to write a bytes doc.
    bytes_to_write = []
    bytes_doc = {
            "ip1":session.ip1,
            "p1":session.port1,
            "b1":int(session.bytes1),
            "ip2":session.ip2,
            "p2":session.port2,
            "b2":int(session.bytes2),
            "b":bytes_to_write,
            "sb": sb,
            "sbm": peg_to_minute(sb)
    }

    # Set CC and vlan only for sessionInfo & Bytes, not for captureInfo & Bytes
    if live_session_locks:
        # Populate bytes_doc country code from session_copy
        if session.cc1[0] != 0:
            bytes_doc["cc1"] = chr(session.cc1[0]) + chr(session.cc1[1])
    
        if session.cc2[0] != 0:
            bytes_doc["cc2"] = chr(session.cc2[0]) + chr(session.cc2[1])
    
        if session.vlan_id >= 0: bytes_doc['vl'] = session.vlan_id

    cdef int second, i
    cdef uint32_t* bytes_subarray

    # Set se default in case range in for statement below is empty
    #se = <uint64_t>session.base.te
    se = second_to_write_from

    # Generate the bytes array.  Write all non-zero sub-arrays from the second
    # to write up to the end of the data we have, inclusive.
    for second in range(second_to_write_from, min(second_to_write_to, <uint64_t>session.base.te + 1)):
        i = second % BYTES_RING_SIZE
        bytes_subarray = session.base.traffic_bytes[i]
        if bytes_subarray[0] > 0 or bytes_subarray[1] > 0:
            # Update the session end time
            se = second
            # Append a new Bytes subarray
            bytes_to_write.append([
                int(second - second_to_write_from),
                bytes_subarray[0],
                bytes_subarray[1]
            ])
            # Update the capture session
            capture_session.bytes1 += bytes_subarray[0]
            capture_session.bytes2 += bytes_subarray[1]
            capture_session.base.traffic_bytes[i][0] += bytes_subarray[0]
            capture_session.base.traffic_bytes[i][1] += bytes_subarray[1]

    bytes_doc["se"] = se
    bytes_doc["sem"] = peg_to_minute(se)

    # Update capture_session timestamp
    capture_session.base.te = max(capture_session.base.te, session.base.te)

    # add to writes if the bytes array is not empty
    # Performance improvement todo - don't build bytes_doc if no bytes_to_write
    if trafcap.options.mongo and bytes_to_write:
        try:
            bytes_bulk_writer.insert(bytes_doc)
        except Exception, e:
            # Something went wrong 
            if not trafcap.options.quiet:
                print e, bytes_doc,traceback.format_exc()
            trafcap.logException(e, bytes_doc=bytes_doc)

    return 0 


cdef int write_udp_session(object info_bulk_writer, object bytes_bulk_writer, object info_collection, list object_ids, GenericSession* g_session, int slot, uint64_t second_to_write_from, uint64_t second_to_write_to, GenericSession* g_capture_session, GenericSession* l_session, object live_session_locks) except -1:
    cdef UDPSession* session = <UDPSession*>g_session
    cdef UDPSession* capture_session = <UDPSession*>g_capture_session
    cdef UDPSession* live_session = <UDPSession*>l_session

    cdef uint64_t sb = second_to_write_from
    cdef uint64_t se
    cdef int tdm

    # General Plan for writes:
    # At this point, we know there needs to be a write.  The question is
    # whether or not we need to create and insert a new info doc or not.  If we
    # need a new info_doc, we insert without using the bulk_writer, because we
    # want to get back the object id.  Everything else is just added to the
    # bulk_writer for later execution.

    # Note: Sometimes we wrap numbers in python int() before we commit them to
    # a dictionary.  This is to prevent Cython from making uint64 into python
    # Longs by default.  (Since we're commiting to disk, we'll do our best to
    # save bytes.

    object_id = object_ids[slot]
    if not object_id:
        # We need to insert a new info doc
        info_doc = {
            "ip1":session.ip1,
            "p1":session.port1,
            "b1":int(session.bytes1),
            "ip2":session.ip2,
            "p2":session.port2,
            "b2":int(session.bytes2),
            "bt":int(session.bytes1+session.bytes2),
            "tbm":peg_to_minute(<uint64_t>session.base.tb),
            "tem":peg_to_minute(<uint64_t>session.base.te),
            "tb":session.base.tb,
            "te":session.base.te,
            "pk":int(session.base.packets)
        }

        # Set CC and vlanId only for sessionInfo & Bytes, not for captureInfo & Bytes
        if live_session_locks:
            # Get cc for new info_doc and update session (which is actually a session_copy)
            cc1, name1, loc1 = trafcap.geoIpLookupInt(session.ip1)
            cc2, name2, loc2 = trafcap.geoIpLookupInt(session.ip2)
            
            # May need to update cc1 &/or cc2 in original session.
            if cc1 or cc2:
                lock = live_session_locks[slot % SESSIONS_PER_LOCK]
                lock.acquire()
    
                if cc1: 
                    info_doc["cc1"] = cc1
                    # Populate session_copy for use when creating bytes_doc 
                    # Populate original session for use during future writes
                    session.cc1[0] = live_session.cc1[0] = ord(cc1[0])
                    session.cc1[1] = live_session.cc1[1] = ord(cc1[1])
    
                if cc2: 
                    info_doc["cc2"] = cc2
                    # Populate session_copy for use when creating bytes_doc 
                    # Populate original session for use during future writes
                    session.cc2[0] = live_session.cc2[0] = ord(cc2[0])
                    session.cc2[1] = live_session.cc2[1] = ord(cc2[1])
    
                lock.release()

            if session.vlan_id >= 0: info_doc['vl'] = session.vlan_id
                    
        tdm = <int>(session.base.te - session.base.tb)
        if tdm >= trafcap.lrs_min_duration: info_doc['tdm'] = tdm

        # Insert the new doc and record the objectid
        if trafcap.options.mongo:
            try:
                object_ids[slot] = info_collection.insert(info_doc)
            except Exception, e:
                # Something went wrong 
                if not trafcap.options.quiet:
                    print e, info_doc,traceback.format_exc()
                trafcap.logException(e, info_doc=info_doc)
            #print info_doc,"at",object_ids[slot]

    else:
        # If we're not inserting a new doc, we're updating an existing one.
        set_doc = { "b1": int(session.bytes1),
                    "b2": int(session.bytes2),
                    "bt": int(session.bytes1+session.bytes2),
                    "pk": int(session.base.packets),
                    "te": session.base.te,
                    "tem": peg_to_minute(<uint64_t>session.base.te) }

        tdm = <int>(session.base.te - session.base.tb)
        if tdm >= trafcap.lrs_min_duration: set_doc['tdm'] = tdm

        info_update = { "$set": set_doc }

        if trafcap.options.mongo:
            try:
                info_bulk_writer.find({"_id": object_ids[slot]}).update(info_update)
            except Exception, e:
                # Something went wrong 
                if not trafcap.options.quiet:
                    print e, info_update,traceback.format_exc()
                trafcap.logException(e, info_update=info_update)

    # We always need to write a bytes doc.
    bytes_to_write = []
    bytes_doc = {
            "ip1":session.ip1,
            "p1":session.port1,
            "b1":int(session.bytes1),
            "ip2":session.ip2,
            "p2":session.port2,
            "b2":int(session.bytes2),
            "b":bytes_to_write,
            "sb": sb,
            "sbm": peg_to_minute(sb)
    }

    # Set CC and vlan only for sessionInfo & Bytes, not for captureInfo & Bytes
    if live_session_locks:
        # Populate bytes_doc country code from session_copy
        if session.cc1[0] != 0:
            bytes_doc["cc1"] = chr(session.cc1[0]) + chr(session.cc1[1])
    
        if session.cc2[0] != 0:
            bytes_doc["cc2"] = chr(session.cc2[0]) + chr(session.cc2[1])
    
        if session.vlan_id >= 0: bytes_doc['vl'] = session.vlan_id

    cdef int second, i
    cdef uint32_t* bytes_subarray
    # Generate the bytes array.  Write all non-zero sub-arrays from the second
    # to write up to the end of the data we have, inclusive.
    for second in range(second_to_write_from, min(second_to_write_to, <uint64_t>session.base.te + 1)):
        i = second % BYTES_RING_SIZE
        bytes_subarray = session.base.traffic_bytes[i]
        if bytes_subarray[0] > 0 or bytes_subarray[1] > 0:
            # Update the session end time
            se = second
            # Append a new Bytes subarray
            bytes_to_write.append([
                int(second - second_to_write_from),
                bytes_subarray[0],
                bytes_subarray[1]
            ])
            # Update the capture session
            capture_session.bytes1 += bytes_subarray[0]
            capture_session.bytes2 += bytes_subarray[1]
            capture_session.base.traffic_bytes[i][0] += bytes_subarray[0]
            capture_session.base.traffic_bytes[i][1] += bytes_subarray[1]

    bytes_doc["se"] = se
    bytes_doc["sem"] = peg_to_minute(se)

    # Update capture_session timestamp
    capture_session.base.te = max(capture_session.base.te, session.base.te)

    # add to writes
    if trafcap.options.mongo:
        try:
            bytes_bulk_writer.insert(bytes_doc)
        except Exception, e:
            # Something went wrong 
            if not trafcap.options.quiet:
                print e, bytes_doc,traceback.format_exc()
            trafcap.logException(e, bytes_doc=bytes_doc)

    return 0 

cdef int init_tcp_capture_group(GenericGroup* g_group, uint8_t group_type, uint64_t session_tb):
    cdef TCPGroup* group = <TCPGroup*>g_group
    memset(group, 0, sizeof(TCPGroup))
    group.base.tbm = peg_to_180minute(session_tb) if group_type else \
                     peg_to_15minute(session_tb)
    #group.base.tem = peg_to_minute(time.time())
    #group.base.csldw = 0 
    group.base.ne = 1
    group.vlan_id = -1
    return 0


cdef int init_udp_capture_group(GenericGroup* g_group, uint8_t group_type, uint64_t session_tb):
    cdef UDPGroup* group = <UDPGroup*>g_group
    memset(group, 0, sizeof(UDPGroup))
    group.base.tbm = peg_to_180minute(session_tb) if group_type else \
                     peg_to_15minute(session_tb)
    #group.base.tem = peg_to_minute(time.time())
    #group.base.csldw = 0 
    group.base.ne = 1
    group.vlan_id = -1
    return 0

#cdef GenericGroup* alloc_tcp_capture_group():
#    cdef TCPGroup* group = <TCPGroup*>malloc(sizeof(TCPGroup))
#
#    # Zero out almost everything
#    memset(group, 0, sizeof(TCPGroup))
#
#    group.base.tbm = peg_to_15minute(time.time())
#    group.base.tem = peg_to_minute(time.time())
#    group.base.csldw = 1 
#    group.vlan_id = -1
#
#    return <GenericGroup*>group

#cdef GenericGroup* alloc_udp_capture_group():
#    cdef UDPGroup* group = <UDPGroup*>malloc(sizeof(UDPGroup))
#
#    # Zero out almost everything
#    memset(group, 0, sizeof(UDPGroup))
#
#    group.base.tbm = peg_to_15minute(time.time())
#    group.base.tem = peg_to_minute(time.time())
#    group.base.csldw = 1 
#    group.vlan_id = -1
#
#    return <GenericGroup*>group

cdef int write_tcp_group(object group_bulk_writer, object group_collection, list object_ids, GenericGroup* g_group, int slot, uint8_t group_type) except -1:
    cdef TCPGroup* group = <TCPGroup*>g_group

    # General Plan for writes:
    # At this point, we know there needs to be a write.  The question is
    # whether or not we need to create and insert a new doc or not.  If we
    # need a new doc, we insert without using the bulk_writer, because we
    # want to get back the object id.  Everything else is just added to the
    # bulk_writer for later execution.

    # Note: Sometimes we wrap numbers in python int() before we commit them to
    # a dictionary.  This is to prevent Cython from making uint64 into python
    # Longs by default.  (Since we're commiting to disk, we'll do our best to
    # save bytes.

    # Start by creating the bytes array from all non-zero group byte entries.
    # Group will always have 90 traffic_byte items - some may be zero.
    cdef uint32_t* bytes_subarray
    bytes_to_write = []
    cdef int offset, offset_width
    offset_width = 120 if group_type else 10

    for offset in range(0, 90):
        bytes_subarray = group.base.traffic_bytes[offset]
        if bytes_subarray[0] > 0 or bytes_subarray[1] > 0:
            # Append a new Bytes subarray, offset stored as seconds
            bytes_to_write.append([ int(offset * offset_width), bytes_subarray[0],
                                                                bytes_subarray[1] ])
    object_id = object_ids[slot]
    if not object_id:
        # We need to insert a new group doc
        group_doc = {
            "ip1":group.ip1,
            "b1":int(group.bytes1),
            "ip2":group.ip2,
            "p2":group.port2,
            "b2":int(group.bytes2),
            "tbm":<uint64_t>group.base.tbm,
            "tem":<uint64_t>group.base.tem,
            "ns":int(group.base.ns),
            "ne":int(group.base.ne),
            "b":bytes_to_write
        }

        # Group data should already have cc populated.  Check just in case.
        if group.cc1[0] != 0:
            group_doc["cc1"] = chr(group.cc1[0]) + chr(group.cc1[1])
        else:
            cc1, name1, loc1 = trafcap.geoIpLookupInt(group.ip1)
            if cc1: 
                group_doc["cc1"] = cc1
                group.cc1[0] = ord(cc1[0])
                group.cc1[1] = ord(cc1[1])

        if group.cc2[0] != 0:
            group_doc["cc2"] = chr(group.cc2[0]) + chr(group.cc2[1])
        else:
            cc2, name2, loc2 = trafcap.geoIpLookupInt(group.ip2)
            if cc2: 
                group_doc["cc2"] = cc2
                group.cc2[0] = ord(cc2[0])
                group.cc2[1] = ord(cc2[1])

        if group.vlan_id >= 0: group_doc['vl'] = group.vlan_id

        # Insert the new doc and record the objectid
        if trafcap.options.mongo:
            try:
                object_ids[slot] = group_collection.insert(group_doc)
            except Exception, e:
                # Something went wrong 
                if not trafcap.options.quiet:
                    print e, group_doc, traceback.format_exc()
                trafcap.logException(e, group_doc=group_doc)
            #print info_doc,"at",object_ids[slot]

    else:
        # If we're not inserting a new doc, we're updating an existing one.
        group_update = {
            "$set": {
                "b1": int(group.bytes1),
                "b2": int(group.bytes2),
                "ns": int(group.base.ns),
                "ne": int(group.base.ne),
                "b": bytes_to_write,
                "tem": <uint64_t>group.base.tem
            }
        }

        if trafcap.options.mongo:
            try:
                group_bulk_writer.find({"_id": object_ids[slot]}).update(group_update)
            except Exception, e:
                # Something went wrong 
                if not trafcap.options.quiet:
                    print e, group_update,traceback.format_exc()
                trafcap.logException(e, group_update=group_update)

    # debug
    #if group.port2 == 37:
    #    print 'Writing:  ne:',group.base.ne, 'ns:',group.base.ns

    return 0 


cdef int write_udp_group(object group_bulk_writer, object group_collection, list object_ids, GenericGroup* g_group, int slot, uint8_t group_type) except -1:
    # placeholder
    return 0

cdef int generate_tcp_group(GenericGroup* g_group, GenericSession* g_session, GenericGroup* c_group, uint8_t group_type):
    cdef TCPGroup* group = <TCPGroup*>g_group
    cdef TCPGroup* cap_group = <TCPGroup*>c_group
    cdef TCPSession* session = <TCPSession*>g_session

    group.base.tbm = peg_to_180minute(<uint64_t>session.base.tb) if group_type else peg_to_15minute(<uint64_t>session.base.tb)
    group.base.tem = peg_to_minute(<uint64_t>session.base.te)
    group.base.csldw = 1 
    
    # We need timestamp to be an int to navigate bytes
    cdef uint64_t current_session_second = <uint64_t>session.base.tb
    cdef uint64_t last_session_second = <uint64_t>session.base.te
    cdef uint64_t session_slot_second
    cdef uint64_t group_slot_offset
    cdef uint64_t previous_group_slot_offset = 0
    cdef uint32_t* bytes_subarray

    group.ip1 = session.ip1
    group.cc1[0] = session.cc1[0] 
    group.cc1[1] = session.cc1[1] 

    group.ip2 = session.ip2
    group.port2 = session.port2
    group.cc1[0] = session.cc1[0] 
    group.cc1[1] = session.cc1[1] 

    group.vlan_id = session.vlan_id

    # Zero-out any old data in case group is re-used
    group.base.ns = 0   # number of started sessions
    group.base.ne = 0   # number of existing sessions
    group.bytes1 = 0 
    group.bytes2 = 0 
    for i in range(0,90):
        group.base.traffic_bytes[i][0] = 0 
        group.base.traffic_bytes[i][1] = 0 

    # Move setting of cap_group.base.tbm to init_capture_group function
    ## cap_group may or may-not be new.  If new, other init is already done
    #if cap_group.base.tbm == 0:
    #    cap_group.base.tbm = peg_to_180minute(<uint64_t>session.base.tb) if group_type else \
    #                         peg_to_15minute(<uint64_t>session.base.tb)
    cap_group.base.tem = peg_to_minute(<uint64_t>session.base.te)
    cap_group.base.csldw = 1 

    # Translate session bytes array (1 item = 1 sec, up to 20 items) to:
    #    groups1 bytes array (90 items, 10 sec/item for 15 min window) and
    #    groups2 bytes array (90 items, 120 sec/item for 180 min window)
    for session_slot_second in range(current_session_second, last_session_second+1):
        # Calculate slot offsets in the byte arrays
        group_slot_offset = calc_group2_offset(session_slot_second) if group_type else calc_group1_offset(session_slot_second)
        session_slot_offset = session_slot_second % BYTES_RING_SIZE
        # find bytes in each direction for this session slot
        bytes_subarray = session.base.traffic_bytes[session_slot_offset]
        if group_slot_offset >= previous_group_slot_offset:    # session fits within this group 
            # increment session_group byte counters
            group.base.traffic_bytes[group_slot_offset][0] += bytes_subarray[0] 
            group.bytes1 += bytes_subarray[0] 
            group.base.traffic_bytes[group_slot_offset][1] += bytes_subarray[1] 
            group.bytes2 += bytes_subarray[1]

            # increment capture_group byte counters
            cap_group.base.traffic_bytes[group_slot_offset][0] += bytes_subarray[0] 
            cap_group.bytes1 += bytes_subarray[0] 
            cap_group.base.traffic_bytes[group_slot_offset][1] += bytes_subarray[1] 
            cap_group.bytes2 += bytes_subarray[1]

        else:   # session flows into a new group
            # Adjust session time so new group is created when session is reprocessed.  
            # These are saved_sessions so no need to obtain a lock.  Only groupUpdater,
            # which calls this function, modifies saved_sessions.
            session.base.tb = session_slot_second
            # set end time corresponding to last bytes in group
            group.base.tem = peg_to_minute(session_slot_second - 1)
            return -1

        previous_group_slot_offset = group_slot_offset

    # set end time corresponding to last bytes in group
    group.base.tem = peg_to_minute(session_slot_second)
    # session fit into one group
    return 0
    
cdef int generate_udp_group(GenericGroup* g_group, GenericSession* g_session, GenericGroup* c_group, uint8_t group_type):
    cdef UDPGroup* group = <UDPGroup*>g_group
    cdef UDPSession* session = <UDPSession*>g_session

    group.base.tbm = peg_to_180minute(<uint64_t>session.base.tb) if group_type else peg_to_15minute(<uint64_t>session.base.tb)
    group.base.csldw = 1 
    
    # We need timestamp to be an int to navigate bytes
    cdef uint64_t current_session_second = <uint64_t>session.base.tb
    cdef uint64_t last_session_second = <uint64_t>session.base.te
    cdef uint64_t session_slot_second
    cdef uint64_t group_slot_offset
    cdef uint64_t previous_group_slot_offset = 0
    cdef uint32_t* bytes_subarray

    group.ip1 = session.ip1
    group.cc1[0] = session.cc1[0] 
    group.cc1[1] = session.cc1[1] 

    group.ip2 = session.ip2
    group.port2 = session.port2
    group.cc1[0] = session.cc1[0] 
    group.cc1[1] = session.cc1[1] 

    group.vlan_id = session.vlan_id

    # Handled in calling process
    #group.base.ns = 1   # number of started sessions
    #group.base.ne = 0   # number of existing sessions

    # Translate session bytes array (1 item = 1 sec, up to 20 items) to:
    #    groups1 bytes array (90 items, 1 sec/item for 15 min window) and
    #    groups2 bytes array (90 items, 120 sec/item for 180 min window)
    for session_slot_second in range(current_session_second, last_session_second+1):
        # Calculate slot offsets in the byte arrays
        group_slot_offset = calc_group2_offset(session_slot_second) if group_type else calc_group1_offset(session_slot_second)
        session_slot_offset = session_slot_second % BYTES_RING_SIZE
        # find bytes in each direction for this session slot
        bytes_subarray = session.base.traffic_bytes[session_slot_offset]
        if group_slot_offset >= previous_group_slot_offset:    # session fits within this group 
            # increment byte counters
            group.base.traffic_bytes[group_slot_offset][0] += bytes_subarray[0] 
            group.bytes1 += bytes_subarray[0]
            group.base.traffic_bytes[group_slot_offset][1] += bytes_subarray[1]
            group.bytes2 += bytes_subarray[1] 
        else:   # session flows into a new group
            # Adjust session time so new group is created when session is reprocessed.  
            # These are saved sessions so no need to obtain a lock.  This is the only 
            # case when saved sessions are modified.
            session.base.tb = session_slot_second
            # set end time corresponding to last bytes in group
            group.base.tem = peg_to_minute(session_slot_second - 1)
            return -1

        previous_group_slot_offset = group_slot_offset

    # set end time corresponding to last bytes in group
    group.base.tem = peg_to_minute(session_slot_second)
    # session fit into one group
    return 0

cdef int update_tcp_group(GenericGroup* g_group, GenericSession* g_session, GenericGroup* c_group, uint8_t group_type):
    cdef TCPGroup* group = <TCPGroup*>g_group
    cdef TCPSession* session = <TCPSession*>g_session
    cdef TCPGroup* cap_group = <TCPGroup*>c_group
    
    #group.base.tem = peg_to_minute(<uint64_t>session.base.te)
    group.base.csldw = 1 
     
    # We need timestamp to be an int to navigate bytes
    cdef uint64_t current_session_second = <uint64_t>session.base.tb
    cdef uint64_t last_session_second = <uint64_t>session.base.te
    cdef uint64_t session_slot_second
    cdef uint64_t group_slot_offset
    cdef uint64_t previous_group_slot_offset = 0
    cdef uint32_t* bytes_subarray

    # Handled in calling process
    #group.base.ns = 1   # number of started sessions
    #group.base.ne = 0   # number of existing sessions
    
    cap_group.base.tem = peg_to_minute(<uint64_t>session.base.te)
    cap_group.base.csldw = 1 

    # No need to zero-out group data (as is done in update_session) because 
    # group slots are not ring buffers and are not re-used.

    # Translate session bytes array (1 item = 1 sec, up to 20 items) to:
    #    groups1 bytes array (90 items, 10 sec/item for 15 min window) and
    #    groups2 bytes array (90 items, 120 sec/item for 180 min window)
    for session_slot_second in range(current_session_second, last_session_second+1):
        # Calculate slot offsets in the byte arrays
        group_slot_offset = calc_group2_offset(session_slot_second) if group_type else calc_group1_offset(session_slot_second)
        session_slot_offset = session_slot_second % BYTES_RING_SIZE
        # find bytes in each direction for this session slot
        bytes_subarray = session.base.traffic_bytes[session_slot_offset]
        if group_slot_offset >= previous_group_slot_offset:    # session fits within this group 
            # increment session_group byte counters
            group.base.traffic_bytes[group_slot_offset][0] += bytes_subarray[0] 
            group.bytes1 += bytes_subarray[0]
            group.base.traffic_bytes[group_slot_offset][1] += bytes_subarray[1] 
            group.bytes2 += bytes_subarray[1] 

            # increment session_group byte counters
            cap_group.base.traffic_bytes[group_slot_offset][0] += bytes_subarray[0] 
            cap_group.bytes1 += bytes_subarray[0]
            cap_group.base.traffic_bytes[group_slot_offset][1] += bytes_subarray[1] 
            cap_group.bytes2 += bytes_subarray[1] 

        else:   # session flows into a new group
            # Adjust session time so new group is created when session is reprocessed.  
            # These are saved_sessions so no need to obtain a lock.  Only groupUpdater,
            # which calls this function, modifies saved_sessions.
            session.base.tb = session_slot_second
            # set end time corresponding to last bytes in group
            group.base.tem = peg_to_minute(session_slot_second - 1)
            return -1

        previous_group_slot_offset = group_slot_offset

    # set end time corresponding to last bytes in group
    group.base.tem = peg_to_minute(session_slot_second)
    # session fit into one group
    return 0
    
cdef int update_udp_group(GenericGroup* g_group, GenericSession* g_session, GenericGroup* c_group, uint8_t group_type):
    cdef UDPGroup* group = <UDPGroup*>g_group
    cdef UDPSession* session = <UDPSession*>g_session

    group.base.tem = peg_to_minute(<uint64_t>session.base.te)
    group.base.csldw = 1 
    
    # We need timestamp to be an int to navigate bytes
    cdef uint64_t current_session_second = <uint64_t>session.base.tb
    cdef uint64_t last_session_second = <uint64_t>session.base.te
    cdef uint64_t session_slot_second
    cdef uint64_t group_slot_offset
    cdef uint64_t previous_group_slot_offset = 0
    cdef uint32_t* bytes_subarray

    # Handled in calling process
    #group.base.ns = 1   # number of started sessions
    #group.base.ne = 0   # number of existing sessions

    # Translate session bytes array (1 item = 1 sec, up to 20 items) to:
    #    groups1 bytes array (90 items, 1 sec/item for 15 min window) and
    #    groups2 bytes array (90 items, 120 sec/item for 180 min window)
    for session_slot_second in range(current_session_second, last_session_second+1):
        # Calculate slot offsets in the byte arrays
        group_slot_offset = calc_group2_offset(session_slot_second) if group_type else calc_group1_offset(session_slot_second)
        session_slot_offset = session_slot_second % BYTES_RING_SIZE
        # find bytes in each direction for this session slot
        bytes_subarray = session.base.traffic_bytes[session_slot_offset]
        if group_slot_offset >= previous_group_slot_offset:    # session fits within this group 
            # increment byte counters
            group.base.traffic_bytes[group_slot_offset][0] += bytes_subarray[0] 
            group.bytes1 += bytes_subarray[0] 
            group.base.traffic_bytes[group_slot_offset][1] += bytes_subarray[1] 
            group.bytes2 += bytes_subarray[1] 
        else:   # session flows into a new group
            # Adjust session time so new group is created when session is reprocessed.  
            # These are saved sessions so no need to obtain a lock.  This is the only 
            # case when saved sessions are modified.
            session.base.tb = session_slot_second
            # set end time corresponding to last bytes in group
            group.base.tem = peg_to_minute(session_slot_second - 1)
            return -1

        previous_group_slot_offset = group_slot_offset

    # set end time corresponding to last bytes in group
    group.base.tem = peg_to_minute(session_slot_second)
    # session fit into one group
    return 0

cdef int update_group_counts(object session_key, object session_history, uint8_t group_type, 
                             GenericGroup* group, object counter) except -1:
    # Session accounting needed to properly create group's entries for:
    #   ns: number of sessions started within a group
    #   ne: number of sessions in a group but already started in a previous group
    # Use a set for each group time window.  The set time windows correspond to capture_group
    # time windows.  Set contains session_keys if that session has been accoutned for in 
    # the set's time window.

    cdef bint session_in_current_group = False
    cdef bint session_in_prev_group = False
    cdef uint64_t session_set_tbm
    cdef set session_set

    for session_set_tbm in session_history:
        session_set = session_history[session_set_tbm]
        # Check if this set represents the group time-window a session belongs to
        if session_set_tbm == group.tbm:
            # If session is not counted in a group yet, indicate that for later counting,
            # otherwise, add it to the set for future counting.
            if session_key in session_set:
                session_in_current_group = True
            else:
                session_set.add(session_key)
        # If this set represents a previous group's time-window, check if group was counted
        if session_set_tbm < group.tbm:
            if session_key in session_set:
                session_in_prev_group = True

    if not session_in_current_group:
        if not session_in_prev_group:
            group.ns += 1
            counter.value += 1
        else:
            group.ne += 1

    # debug
    #tcp_group = <TCPGroup *>group
    #if tcp_group.port2 == 37 and group_type == 0:
    #    print 'p2=37: ', 'ne:',group.ne, 'ns:',group.ns, 'prev:',session_in_prev_group, \
    #          'curr:',session_in_current_group, session_set_tbm 

#cdef int share_bytes_doc(GenericBytesDoc* g_doc, object bytes_doc) except -1:
#    cdef TCPBytesDoc* tcp_bytes_doc = <TCPBytesDoc*>g_doc
#
#    tcp_bytes_doc.ip1 = bytes_doc['ip1']
#    tcp_bytes_doc.ip2 = bytes_doc['ip2']
#    tcp_bytes_doc.port1 = bytes_doc['p1']
#    tcp_bytes_doc.port2 = bytes_doc['p2']
#    tcp_bytes_doc.bytes1 = bytes_doc['b1']
#    tcp_bytes_doc.bytes2 = bytes_doc['b2']
#    tcp_bytes_doc.base.sb = bytes_doc['sb']
#    tcp_bytes_doc.base.sbm = bytes_doc['sbm']
#    tcp_bytes_doc.base.se = bytes_doc['se']
#    tcp_bytes_doc.base.sem = bytes_doc['sem']
#    # CC field only created in mongo if needed - check for existance
#    if 'cc1' in bytes_doc:
#        tcp_bytes_doc.cc1[0] = ord(bytes_doc['cc1'][0])
#        tcp_bytes_doc.cc1[1] = ord(bytes_doc['cc1'][1])
#    if 'cc2' in bytes_doc:
#        tcp_bytes_doc.cc2[0] = ord(bytes_doc['cc2'][0])
#        tcp_bytes_doc.cc2[1] = ord(bytes_doc['cc2'][1])
#    # vlan_id field only created in mongo if needed - check for existance
#    if 'vl' in bytes_doc:
#        tcp_bytes_doc.vlan_id = bytes_doc['vl']
#    # base.traffic_bytes
#
#    #print tcp_bytes_doc.cc1, len(tcp_bytes_doc.cc1), tcp_bytes_doc.cc2, len(tcp_bytes_doc.cc2)
#    #print tcp_bytes_doc.cc1[0], tcp_bytes_doc.cc1[1], tcp_bytes_doc.cc2[0], tcp_bytes_doc.cc2[1]

class TcpPacket(IpPacket):
    """
    For handling TCP packets (assumes IPv4)
    """
    def __init__(self):
        return

    # Legend for TCP packet data list returned by the parse method:
    #        data[0]  (ip1)     ,     data[1]   (ip2)       , [2]  , [3]
    #[[(addr),port,bytes,[flag]], [(addr),port,bytes,[flag]],epoch ,proto]
    p_ip1=0; p_ip2=1
    p_addr=0; p_port=1; p_bytes=2; p_flags=3
    p_etime=2
    p_proto=3
    p_vl=4   # vlan_id

    # Legend for how TCP packet data is stored in the Session Info 
    # dictionary and the Capture Info dictionary 
    #   data[0]    (ip1)    ,     data[1]   (ip2)  ,[2],[3],[4],[5],[6], [7]
    #[[(adr),prt,byts,[flg]],[(adr),prt,byts,[flg]], tb, ta, te,pkts, ci,prto]
    i_ip1=0; i_ip2=1
    i_addr=0; i_port=1; i_bytes=2; i_flags=3
    i_tb=2; i_ta=3; i_te=4; i_pkts=5; i_ci=6; i_proto=7
    i_ldwt=8      # last_db_write_time
    i_csldw=9     # changed_since_last_db_write
    i_cc1=10
    i_loc1=11
    i_cc2=12
    i_loc2=13
    i_id=14        # mongo object id
    i_vl=15        # vlan id

    # This function written to retain some functionality from the
    # original parse() function once pf_ring is being used.
    # Leave for now but not used - maybe delete in future.
    @classmethod
    def parse_doc(pc, doc):

        addrs = [trafcap.intToTuple(doc['ip1']),
                 trafcap.intToTuple(doc['ip2'])]
        ports = [doc['p1'], doc['p2']]
        byts = [doc['b1'], doc['b2']]
        flag_list = [doc['f1'], doc['f2']]
        epoch_time = doc['tb']
        proto = doc.get('pr', None)
        try:
            vlan_id = doc['vl'] 
        except KeyError:
            vlan_id = None
        #vlan_pri = None

    @classmethod
    def parse(pc, pkt, doc):

        # tcpdump v 4.1.1
        #        0                     2                    4
        # 1348367532.072244 IP 192.168.168.17.1696 > 204.210.192.2.25566:
        #       6                                           14
        #Flags [P.], seq 30:32, ack 4907, win 65021, length 2
        # Remember that these are strings

        # TCP DNS traffic
        # 1360940004.915082 IP 192.168.168.20.49387 > 192.168.168.1.53: Flags [P.], seq 1:36, ack 1, win 256, length 3556043+ TXT? version.avg.com. (33)
        # 1360940005.089718 IP 192.168.168.1.53 > 192.168.168.20.49387: Flags [P.], seq 2:785, ack 37, win 5840, length 78360289- [256q][|domain]

        # Other TCP DNS traffic examples
        #1363696331.309098 IP 10.10.80.108.53412 > 192.168.1.6.53: Flags [.], seq 1:1461, ack 1, win 256, length 146037477 [1au] TKEY? 1260-ms-7.1-d299.0595eadf-9091-11e2-368c-00216a5974e4. (1458)
        #1363696331.316995 IP 10.10.80.108.53412 > 192.168.1.6.53: Flags [.], seq 1461:2921, ack 1, win 256, length 146035888 YXDomain-| [34976q],[|domain]

        #1363696331.324992 IP 10.10.80.108.53412 > 192.168.1.6.53: Flags [P.], seq 2921:3142, ack 1, win 256, length 22161323 updateMA Resp13-| [25745q][|domain]
        #1363696331.326078 IP 192.168.1.6.53 > 10.10.80.108.53412: Flags [P.], seq 1:455, ack 3142, win 65314, length 45437477- 1/0/1 ANY TKEY (452)


        # ICMP traffic - not sure why the tshark filter allows this to be included with TCP traffic
        # 1362723521.581183 IP 192.168.253.1 > 192.168.253.26: ICMP host 8.8.8.8 unreachable, length 92

        # Parsing for vlan id.  tcpdump version 4.3.0   libpcap version 1.3.0    Sentry 7.0-514
        #
        # Previous format:
        # 1396467169.614347 IP 69.84.41.162.40005 > 10.100.10.244.47671: Flags [P.], seq 145:241 ....
        #
        # New format without vlan tag:
        # 1396467098.199453 70:ca:9b:4b:f7:20 > 00:1b:78:59:e7:c2, 
        #                   ethertype IPv4 (0x0800), length 162: 
        #                   69.84.41.162.40008 > 192.168.5.198.42881: Flags [P.], seq 1441:1537 ....
        #
        # New format with vlan tag:
        # 1396467098.199378 00:23:5e:f4:ee:ff > 00:00:5e:00:01:01, 
        #                   ethertype 802.1Q (0x8100), length 166: vlan 1, p 1, 
        #                   ethertype IPv4, 69.84.41.162.40008 > 192.168.5.198.42881: Flags [P.], seq 1441:1537 ....

        # parse packet off the wire
        if pkt and not doc:
            flag_list = [['_', '_', '_', '_', '_', '_', '_', '_'],
                         ['_', '_', '_', '_', '_', '_', '_', '_']]

            # Handle this:
            # 1424786137.387015 3c:4a:92:2c:c4:00 > 54:75:d0:3e:55:fb, ethertype IPv4 (0x0800), length 63: truncated-ip - 3 bytes missing! 10.200.128.10.3026 > 72.3.209.9.6631: Flags [S], seq 4053698250, win 5840, options [mss 1460,nop,nop,sackOK,nop,[|tcp]>
            # This anamoly seen in bond0 traffic but not in net0 traffic.  Introduced by tap / bonding / cabling ?
            if pkt[9] == 'truncated-ip':
                del pkt[9:14] # deletes items 9 through 13 - does not delete item 14

            # IPv4
            if pkt[6] == '(0x0800),':

                if pkt[12] == 'ICMP':
                    return (),[]

                bytes1 = int(pkt[8].strip(':'))
                vlan_id = None
                #vlan_pri = None
                a1_1,a1_2,a1_3,a1_4,port1 = pkt[9].split(".")
                a2_1,a2_2,a2_3,a2_4,port2 = pkt[11].strip(":").split(".")
                flag_string = pkt[13].strip(",").strip("[").strip("]")

            # 802.1Q (vlan) or 802.1qa (shortest path bridging) 
            #   802.1qa not handled at this time - need sample traffic!
            elif pkt[6] == '(0x8100),':

                if pkt[18] == 'ICMP':
                    return (),[]

                bytes1 = int(pkt[8].strip(':'))
                vlan_id = int(pkt[10].strip(',')) if trafcap.ingest_vlan_id else None 
                #vlan_pri = int(pkt[12].strip(','))
                a1_1,a1_2,a1_3,a1_4,port1 = pkt[15].split(".")
                a2_1,a2_2,a2_3,a2_4,port2 = pkt[17].strip(":").split(".")
                flag_string = pkt[19].strip(",").strip("[").strip("]")

            else:
                # Record packet details for future handling
                # IPv6 handled in Other traffic
                raise Exception('Unexpected ethertype.')

            # Handle these cases:
            # 1398119164.258130 70:ca:9b:4b:f7:20 > 00:23:5e:f4:ee:ff, ethertype IPv4 (0x0800), length 154: 192.168.5.146.1458359471 > 10.59.62.53.2049: 96 getattr fh 0,41/0
            # 1398119164.259488 00:23:5e:f4:ee:ff > 00:00:5e:00:01:01, ethertype 802.1Q (0x8100), length 90: vlan 1, p 1, ethertype IPv4, 10.59.62.53.2049 > 192.168.5.146.1458359471: reply ok 28 getattr ERROR: Stale NFS file handle
            port1_int = int(port1)
            port2_int = int(port2)
            if port1_int > 65535 or port2_int > 65535:
                return (), [] 

            #if pkt[5] == "ICMP":
            #    return (),[]
            # 
            #a1_1,a1_2,a1_3,a1_4,port1 = pkt[2].split(".")
            #a2_1,a2_2,a2_3,a2_4,port2 = pkt[4].strip(":").split(".")
            # 
            #flag_string = pkt[6].strip(",").strip("[").strip("]")

            # Handle case of SYN-ACK flag by changing the flag from S to s
            if (flag_string == "S."):
                flag_string = "s"

            #if (":" in pkt[8]):
            #    # TCP DNS - see traffic samples above
            #    seq_start,seq_end = pkt[8].strip(",").split(":")
            #    bytes1 = int(seq_end) - int(seq_start)
            #    if bytes1 < 0: bytes1 = bytes1 + 4294967296
            #else:
            #    len_index = pkt.index("length")
            #    bytes1_match = pc.leading_num_re.match(pkt[len_index+1])
            #    bytes1 = int(bytes1_match.group(1))
        
            # Handle case of multiple flags
            for index, c in enumerate(flag_string):
                flag_list[0][index] = c
    
            # Represent IP addresses a tuples instead of strings
            addr1 = (int(a1_1), int(a1_2), int(a1_3), int(a1_4))
            addr2 = (int(a2_1), int(a2_2), int(a2_3), int(a2_4))
        
            addrs = [addr1, addr2]

            ports = [port1_int, port2_int]
            byts = [bytes1, 0]
            epoch_time = pkt[0]
            proto = "_"                            # for future use 

        # parse doc from db 
        elif doc and not pkt:
            addrs = [trafcap.intToTuple(doc['ip1']),
                     trafcap.intToTuple(doc['ip2'])]
            ports = [doc['p1'], doc['p2']]
            byts = [doc['b1'], doc['b2']]
            flag_list = [doc['f1'], doc['f2']]
            epoch_time = doc['tb']
            proto = doc.get('pr', None)
            try:
                vlan_id = doc['vl'] 
            except KeyError:
                vlan_id = None
            #vlan_pri = None
                
        else:
            return (), [] 
        
        # Sort to get a consistent key for each TCP session
        data = sorted(zip(addrs, ports, byts, flag_list))
        #[((1,2,3,4), 25254, 0, ['_', '_', '_', '_', '_', '_', '_', '_']),
        # ((9,8,7,6), 22,  140, ['P', '_', '_', '_', '_', '_', '_', '_'])]
    
        # Add packet data - unrelated to any IP
        data.append(epoch_time)
        data.append(proto)
        data.append(vlan_id)
        #data.append(vlan_pri)
    
        #         0            1           2           3
        #        ip1     ,   port1   ,    ip2    ,   port2
        key = (data[pc.p_ip1][pc.p_addr], data[pc.p_ip1][pc.p_port], 
               data[pc.p_ip2][pc.p_addr], data[pc.p_ip2][pc.p_port],
               data[pc.p_vl])

        return key, data


    @classmethod
    def buildInfoDoc(pc, ci, si, a_info):
        tbm=trafcap.secondsToMinute(a_info[pc.i_tb])
        tem=trafcap.secondsToMinute(a_info[pc.i_te])
        info_doc = {"ip1":trafcap.tupleToInt(a_info[ci][pc.i_addr]),
                    "p1":a_info[ci][pc.i_port],
                    "b1":a_info[ci][pc.i_bytes], 
                    "f1":a_info[ci][pc.i_flags], 
                    "ip2":trafcap.tupleToInt(a_info[si][pc.i_addr]),
                    "p2":a_info[si][pc.i_port],
                    "b2":a_info[si][pc.i_bytes],
                    "f2":a_info[si][pc.i_flags],
                    "bt":a_info[si][pc.i_bytes]+a_info[ci][pc.i_bytes],
                    "tbm":tbm,
                    "tem":tem,
                    "tb":a_info[pc.i_tb],
                    "te":a_info[pc.i_te],
                    "pk":a_info[pc.i_pkts],
                    "pr":a_info[pc.i_proto],
                    "cc1":a_info[pc.i_cc1],
                    "loc1":a_info[pc.i_loc1],
                    "cc2":a_info[pc.i_cc2],
                    "loc2":a_info[pc.i_loc2]}
        tdm = tem-tbm
        if tdm >= trafcap.lrs_min_duration: info_doc['tdm'] = tdm
        if a_info[pc.i_vl]: info_doc['vl'] = a_info[pc.i_vl]
        return info_doc

    @classmethod
    def startSniffer(pc):
        filtr = 'ip ' + trafcap.cap_filter + ' and ip[9]==0x06'
        proc = subprocess.Popen(['/usr/sbin/tcpdump', 
                  '-i', trafcap.sniff_interface,
                  '-n', '-e', '-tt', '-B', '40960', '-s', '127',
                  '-f',
                   '('+filtr+') or (vlan and '+filtr+')'],
                   bufsize=-1,
                   stdout=subprocess.PIPE, stderr=sys.stdout.fileno())
        return proc

    @classmethod
    def updateInfoDict(pc, data, a_info):
        # update tcp flags
        if data[pc.p_ip1][pc.p_flags]:
            for index, flag in enumerate(data[pc.p_ip1][pc.p_flags]):
                if flag == "_": break
                if data[pc.p_ip1][pc.p_flags][index] \
                not in a_info[pc.i_ip1][pc.i_flags]:
                    first_mt_flag = a_info[pc.i_ip1][pc.i_flags].index('_')
                    a_info[pc.i_ip1][pc.i_flags][first_mt_flag] = \
                    data[pc.p_ip1][pc.p_flags][index]

        if data[pc.p_ip2][pc.p_flags]:
            for index, flag in enumerate(data[pc.p_ip2][pc.p_flags]):
                if flag == "_": break
                if data[pc.p_ip2][pc.p_flags][index] \
                not in a_info[pc.i_ip2][pc.i_flags]:
                    first_mt_flag = a_info[pc.i_ip2][pc.i_flags].index('_')
                    a_info[pc.i_ip2][pc.i_flags][first_mt_flag] = \
                    data[pc.p_ip2][pc.p_flags][index]

    @classmethod
    def findClient(pc, data, new_info):
        # Determine client ip & store that index (0 or 1) in session_info
        # Check for syn flag - this is the best indicator

        # Flag field changed with pf_ring ingest.  

        #if 'S' in new_info[pc.i_ip1][pc.i_flags]:
        #    new_info[pc.i_ci] = 0
        #elif 'S' in new_info[pc.i_ip2][pc.i_flags]:
        #    new_info[pc.i_ci] = 1
        #elif new_info[pc.i_ip2][pc.i_port] > new_info[pc.i_ip1][pc.i_port]:
        #    # If no syn flag, assume client has largest port number
        #    new_info[pc.i_ci] = 1
        #else:
        #    # Ports are equal, select ip1
        #    new_info[pc.i_ci] = 0

        # First packet observed is the client 
        new_info[pc.i_ci] = 0

    @classmethod
    def buildInfoDictItem(pc, key, data):
        if key == pc.capture_dict_key:
            new_info=[[(0,0,0,0),0,0,[]], [(0,0,0,0),0,0,[]], 
                      float(data[pc.p_etime]), 0, float(data[pc.p_etime]),
                      1, 0, data[pc.p_proto],
                      float(data[pc.p_etime]),True,
                      0, 0, 0, 0, None, None] 
        else:
            cc1, name1, loc1 = trafcap.geoIpLookup(data[pc.p_ip1][pc.p_addr])
            cc2, name2, loc2 = trafcap.geoIpLookup(data[pc.p_ip2][pc.p_addr])

            # Create new dictionary entry.
            # Zip creates tuples, convert to lists so they can be manipulated.
            new_info = [list(data[pc.p_ip1]), list(data[pc.p_ip2]),
                        float(data[pc.p_etime]), 0, float(data[pc.p_etime]),
                        1, 0, data[pc.p_proto],
                        float(data[pc.p_etime]),True,
                        cc1, loc1, cc2, loc2, None, data[pc.p_vl]]

            pc.findClient(data, new_info)
        return new_info

class UdpPacket(IpPacket):
    """
    For handling UDP packets (assumes IPv4)
    """
    def __init__(self):
        return

    # Legend for UDP packet data list returned by the parse method:
    # data[0]    (ip1)  ,    data[1]   (ip2) , [2]  , [3] ,    [4]
    #[(addr),port,bytes], [(addr),port,bytes],epoch ,proto, client_index
    p_ip1=0; p_ip2=1
    p_addr=0; p_port=1; p_bytes=2;
    p_etime=2
    p_proto=3
    p_ci=4
    p_vl=5 # vlan id

    # Legend for how UDP packet data is stored in the Session Info 
    # dictionary and in the Capture Info dictionary 
    #  data[0] (ip1)   ,  data[1]  (ip2)  , [2], [3], [4], [5],  [6]
    #[[(adr),port,byts], [(adr),port,byts], tb , te , pkts,  ci, proto]
    i_ip1=0; i_ip2=1
    i_addr=0; i_port=1; i_bytes=2;
    i_tb=2; i_te=3; i_pkts=4; i_ci=5; i_proto=6
    i_ldwt=7      # last_db_write_time
    i_csldw=8     # changed_since_last_db_write
    i_cc1=9
    i_loc1=10
    i_cc2=11
    i_loc2=12
    i_id=13       # mongo object id
    i_vl=14       # vlan id

    @classmethod
    def parse(pc, pkt, doc):
        if pkt and not doc:
            #pkt = pkt.split()
            pkt_len = len(pkt)
            # Handle IPv6 the leaks through
            if pkt[-1] == 'IPv6': return (), []
            if pkt[-1] == 'ICMPv6': return (), []

            if pkt_len == 5:
                # UDP packet without ports:
                # 1361040136.481161 192.168.168.5  239.255.255.250  996 IPv4
                a1_1,a1_2,a1_3,a1_4 = pkt[1].split(".")
                a2_1,a2_2,a2_3,a2_4 = pkt[2].split(".")
                ports = [0, 0]
                byts = [int(pkt[3]), 0]
                proto = pkt[4]
                vlan_id = None

            elif pkt_len == 6:
                # UDP packet without ports and with vlan id:
                # 1361040136.481161 1 192.168.168.5  239.255.255.250  996 IPv4
                a1_1,a1_2,a1_3,a1_4 = pkt[2].split(".")
                a2_1,a2_2,a2_3,a2_4 = pkt[3].split(".")
                ports = [0, 0]
                byts = [int(pkt[4]), 0]
                proto = pkt[5]
                vlan_id = int(pkt[1]) if trafcap.ingest_vlan_id else None 

            # packets with port numbers with have length 7 or more
            elif '.' in pkt[1]:
                # Typical UDP pkt without vlan id
                #        0               1          2         3         4  5  6 
                # 1341226810.949555 192.168.1.127 32878 193.108.80.124 53 73 DNS
                a1_1,a1_2,a1_3,a1_4 = pkt[1].split(".")
                a2_1,a2_2,a2_3,a2_4 = pkt[3].split(".")
                ports = [int(pkt[2]), int(pkt[4])]
                byts = [int(pkt[5]), 0]
                proto = " ".join(pkt[6:])
                vlan_id = None
            
            else:
                # Typical UDP packet with vlan id
                #        0          1      2          3         4         5  6  7 
                # 1341226810.949555 1 192.168.1.127 32878 193.108.80.124 53 73 DNS
                a1_1,a1_2,a1_3,a1_4 = pkt[2].split(".")
                a2_1,a2_2,a2_3,a2_4 = pkt[4].split(".")
                ports = [int(pkt[3]), int(pkt[5])]
                byts = [int(pkt[6]), 0]
                proto = " ".join(pkt[7:])
                vlan_id = int(pkt[1]) if trafcap.ingest_vlan_id else None 

            # Represent IP addresses a tuples instead of strings
            addr1 = (int(a1_1), int(a1_2), int(a1_3), int(a1_4))
            addr2 = (int(a2_1), int(a2_2), int(a2_3), int(a2_4))
            addrs = [addr1, addr2]
            epoch_time = pkt[0]

        elif doc and not pkt:
            addr1 = trafcap.intToTuple(doc['ip1'])
            addr2 = trafcap.intToTuple(doc['ip2'])
            addrs = [addr1, addr2]
            ports = [doc['p1'], doc['p2']]
            byts = [doc['b1'], doc['b2']]
            epoch_time = doc['tb']
            proto = doc.get('pr', None)
            try:
                vlan_id = doc['vl']
            except KeyError:
                vlan_id = None

        else:
            return (), [] 

        sending_addr = addr1

        # sort to get a consistent key for each session
        data = sorted(zip(addrs, ports, byts))
        # [((192, 43, 172, 30), 53, 0), ((192, 168, 19, 227), 53629, 68)]

        # add the data 
        data.append(epoch_time)
        data.append(proto)

        #          0           1           2           3
        #         ip1    ,   port1   ,    ip2    ,   port2
        key = (data[pc.p_ip1][pc.p_addr], data[pc.p_ip1][pc.p_port], 
               data[pc.p_ip2][pc.p_addr], data[pc.p_ip2][pc.p_port],
               vlan_id)

        # For UDP, client is the first IP to send a packet.  Determine
        # client here since sorting done above may swap IP positions.
        # For the first packet, client_index is subsequently saved.
        if data[pc.p_ip1][pc.p_addr] == sending_addr:
            client_index = 0
        else:
            client_index = 1

        data.append(client_index)
        data.append(vlan_id)

        return key, data


    @classmethod
    def buildInfoDoc(pc, ci, si, a_info):
        tbm=trafcap.secondsToMinute(a_info[pc.i_tb])
        tem=trafcap.secondsToMinute(a_info[pc.i_te])
        info_doc = {"ip1":trafcap.tupleToInt(a_info[ci][pc.i_addr]),
                    "p1":a_info[ci][pc.i_port],
                    "b1":a_info[ci][pc.i_bytes],
                    "ip2":trafcap.tupleToInt(a_info[si][pc.i_addr]),
                    "p2":a_info[si][pc.i_port],
                    "b2":a_info[si][pc.i_bytes],
                    "bt":a_info[si][pc.i_bytes]+a_info[ci][pc.i_bytes],
                    "tbm":tbm,
                    "tem":tem,
                    "tb":a_info[pc.i_tb],
                    "te":a_info[pc.i_te],
                    "pk":a_info[pc.i_pkts],
                    "pr":a_info[pc.i_proto],
                    "cc1":a_info[pc.i_cc1],
                    "loc1":a_info[pc.i_loc1],
                    "cc2":a_info[pc.i_cc2],
                    "loc2":a_info[pc.i_loc2]}
        tdm = tem-tbm
        if tdm >= trafcap.lrs_min_duration: info_doc['tdm'] = tdm
        if a_info[pc.i_vl]: info_doc['vl'] = a_info[pc.i_vl]
        return info_doc

    @classmethod
    def startSniffer(pc):
        filtr = 'ip ' + trafcap.cap_filter + ' and ip[9]==0x11'
        proc = subprocess.Popen(['/usr/bin/tshark', 
               '-i', trafcap.sniff_interface, 
               '-te', '-l', 
               '-b', 'filesize:8192',
               '-b', 'files:5',
               '-w', '/run/trafcap_udp',
               '-P',
               '-o', 
               'column.format:"""time","%t", "vl","%Cus:vlan.id", "src","%s", "sport","%Cus:udp.srcport", "dst","%d", "dprt","%Cus:udp.dstport", "iplen","%Cus:ip.len", "protocol","%p"""',
               '-f',
               '('+filtr+') or (vlan and '+filtr+')'],
               bufsize=-1,
               stdout=subprocess.PIPE, stderr=sys.stdout.fileno())
        return proc
    
    @classmethod
    def updateInfoDict(pc, data, a_info):
        # Nothing to do for UDP
        return

    @classmethod
    def findClient(pc, data, new_info):
        # For the first UDP packet, record the client_index noted by
        # the parse method.
        # For UDP assume IP sending first packet is the client.
        new_info[pc.i_ci] = data[pc.p_ci]

    @classmethod
    def buildInfoDictItem(pc, key, data):
        if key == pc.capture_dict_key:
            new_info=[[(0,0,0,0),0,0], [(0,0,0,0),0,0], 
                      float(data[pc.p_etime]), float(data[pc.p_etime]),
                      1, 0, data[pc.p_proto],
                      float(data[pc.p_etime]),True,
                      0, 0, 0, 0, None, None] 
        else:
            cc1, name1, loc1 = trafcap.geoIpLookup(data[pc.p_ip1][pc.p_addr])
            cc2, name2, loc2 = trafcap.geoIpLookup(data[pc.p_ip2][pc.p_addr])

            # Create new dictionary entry.
            # Zip creates tuples, convert to lists so they can be manipulated.
            new_info = [list(data[pc.p_ip1]), list(data[pc.p_ip2]),
                        float(data[pc.p_etime]), float(data[pc.p_etime]),
                        1, 0, data[pc.p_proto],
                        float(data[pc.p_etime]),True,
                        cc1, loc1, cc2, loc2, None, data[pc.p_vl]]

            pc.findClient(data, new_info)
        return new_info

class IcmpPacket(IpPacket):
    """
    For handling ICMP packets (assumes IPv4)
    """
    def __init__(self):
        return


    # Class attributes
    icmp_req = {}
    last_dict_cleanup_time = 0

    # Legend for ICMP packet data list returned by the parse method:
    # data[0]    (ip1)  ,    data[1]   (ip2) , [2]  , [3] ,    [4]
    #[(addr),type,bytes], [(addr),type,bytes],epoch ,proto, client_index
    p_ip1=0; p_ip2=1
    p_addr=0; p_type=1; p_bytes=2;
    p_etime=2
    p_proto=3
    p_ci=4
    p_vl=5  # vlan id

    # Legend for how packet data is stored in the Session Info 
    # dictionary and in the Capture Info dictionary 
    #  data[0] (ip1)   ,  data[1]  (ip2)  , [2], [3], [4], [5],  [6]
    #[[(adr),type,byts], [(adr),type,byts], tb , te , pkts,  ci, proto]
    i_ip1=0; i_ip2=1
    i_addr=0; i_type=1; i_bytes=2;
    i_tb=2; i_te=3; i_pkts=4; i_ci=5; i_proto=6
    i_ldwt=7      # last_db_write_time
    i_csldw=8     # changed_since_last_db_write
    i_cc1=9
    i_loc1=10
    i_cc2=11
    i_loc2=12
    i_id=13       # mongo object id
    i_vl=14       # vlan id

    # Legend for how data is stored in the Session Bytes dictionary 
    # and the Capture Bytes dictionary 
    #      [0]         [1] [2]               [3]                       [4]
    # ip1,ip2,type             offset                                 pkts 
    #  [list(key)   ,  sb,  se, [[0,   ip1_bytes,  ip2_bytes], [],...],  1]
    b_key=0; b_addr1=0; b_addr2=1; b_type=2; b_vl=3
    b_sb=1; b_se=2; 
    b_array=3; b_offset=0; b_bytes1=1; b_bytes2=2
    b_pkts=4
    b_ldwt=5      # last_db_write_time
    b_csldw=6     # changed_since_last_db_write
    #b_cc1=7
    #b_loc1=8
    #b_cc2=9
    #b_loc1=10
    capture_dict_key = ((0,0,0,0), (0,0,0,0),(), None)

    # Legend for Group dictionary data structure:
    #   0  1   2   3    4   5   6  7  8  9 
    #                                       +------- document window ------+
    #  ip1 ty1 b1 ip2   b2 tbm tem ns ne b[[offset, b1, b2], [...], .....]
    #                                        +--- chunck----+
    # Note that type2 (t2) is not stored in TrafcapContainer dictionary
    g_ip1=0; g_ty1=1; g_b1=2
    g_ip2=3;          g_b2=4
    g_tbm=5; g_tem=6
    g_ns=7; g_ne=8
    g_b=9; g_offset=0; g_1=1; g_2=2
    g_pkts=10
    g_proto=11
    g_cc1=12
    g_loc1=13
    g_cc2=14
    g_loc2=15
    g_id=16        # mongo object id
    g_vl=17        # vlan id

    @classmethod
    def parse(pc, pkt, doc):
        #
        # pkt variable is a list with the following entries:
        #        0               1       2     3    4 5    6      7
        # 1345665298.421280 192.168.1.1 178 8.8.8.8 8 0  51463 (0xc907)
        
        # pkt could also look like this:
        #1357588547.607316 65.36.66.166 56,60 192.168.168.17 3 13 

        # or this
        # 1362723521.580996 192.168.253.1 112,84 192.168.253.26 3,8 1,0 49461 (0xc135) 

        # Adding vlan id
        # 1396523050.738865 192.168.5.198 84 8.8.4.4      8 0 39917 (0x9bed) 1

        if pkt and not doc:
            # May not be a sequence number - if not, append zero for seq number 
            #if len(pkt) == 6:
            #    pkt.append(0)

            a1_1,a1_2,a1_3,a1_4 = pkt[1].split(".")
            a2_1,a2_2,a2_3,a2_4 = pkt[3].split(".")
    
            # Represent IP addresses as tuples instead of strings
            addr1 = (int(a1_1), int(a1_2), int(a1_3), int(a1_4))
            addr2 = (int(a2_1), int(a2_2), int(a2_3), int(a2_4))
            
            # handle various formats of type and code
            i_type = ""
            i_code = ""
    
            # type
            if ',' in pkt[4]:
                i_type = pkt[4].split(',')[0]
            else:
                i_type = pkt[4]
    
            # code
            if ',' in pkt[5]:
                i_code = pkt[5].split(',')[0]
            elif 'x' in pkt[5]:
                i_code = str(int(pkt[5], 16))
            else:
                i_code = pkt[5]
    
            addrs = [addr1, addr2]
            type_and_code = [[i_type+"."+i_code], []]
    
            # handle case of bytes with comma
            byts = pkt[2]
            if ',' in byts: 
                byts = pkt[2].split(',')[0]
            byts = [int(byts), 0]
    
            epoch_time = pkt[0]
            epoch_time_float = float(pkt[0])
            epoch_time_int = int(epoch_time_float)
            proto = 'ICMP' 

            # ICMP types 8 (ping req), 0 (ping rply), 13,14, 17,18 have seq numbers.
            # If other types have a pkt[6], then it must be a vlan_id
            if ('8' in pkt[4] or '0' in pkt[4]) or\
               ('13' in pkt[4] or '14' in pkt[4]) or\
               ('17' in pkt[4] or '18' in pkt[4]):
                # seq in decimal = pkt[6], seq in hex = pkt[7], vlan_id = pkt[8]
                seq = pkt[6]
                if len(pkt) == 9:
                    vlan_id = int(pkt[8]) if trafcap.ingest_vlan_id else None 
                elif len(pkt) == 8:
                    vlan_id = None
                else:
                    raise Exception('Unexpected ICMP packet')
            else:
                seq = 0 
                if len(pkt) == 7:
                    vlan_id = int(pkt[6]) if trafcap.ingest_vlan_id else None 
                elif len(pkt) == 6:
                    vlan_id = None
                else:
                    raise Exception('Unexpected ICMP packet')
                
            type_and_code_for_key = tuple(type_and_code[0])
            # Check if this seq number matches a previous packet
            if seq != 0:
                try:
                    icmp_req_item = pc.icmp_req.pop((seq, addr2, addr1))
                    icmp_request_type_and_code = icmp_req_item[0]
                    # Found request packet in dict, this pkt must be a response
                    type_and_code_for_key = tuple(icmp_request_type_and_code)
                    type_and_code[1]= icmp_request_type_and_code
                except KeyError:
                    # No request packet in the dict
                    # Add packet to the request dictionary 
                    pc.icmp_req[(seq, addr1, addr2)] = [type_and_code[0], \
                                                 epoch_time_int]
                 
                    # clean-out the icmp_req dictionary every minute 
                    list_to_pop=[]
                    if pc.last_dict_cleanup_time < epoch_time_int - 60: 
                        pc.last_dict_cleanup_time = epoch_time_int
                        if not trafcap.options.quiet:
                            print "Clean-up icmp requests...", len(pc.icmp_req)
                        for key in pc.icmp_req:
                            if pc.icmp_req[key][1] < int(epoch_time_float) - \
                                                trafcap.session_expire_timeout:
                                list_to_pop.append(key)    
                        for key in list_to_pop:
                            pc.icmp_req.pop(key)

        elif doc and not pkt:
            addr1 = trafcap.intToTuple(doc['ip1'])
            addr2 = trafcap.intToTuple(doc['ip2'])
            addrs = [addr1, addr2]
            byts = [doc['b1'], doc['b2']]
            type_and_code = [[doc['ty1']], doc['ty2']]
            epoch_time = doc['tb']
            proto = 'ICMP' 
            type_and_code_for_key = (doc['ty1'])
            try:
                vlan_id = doc['vl']
            except KeyError:
                vlan_id = None

        else:
            return (), []

    
        # Three possible cases for this packet:
        #   1. No seq #
        #   2. Seq # match not found in dict 
        #   3. Seq # match found in dict - update type/code list 
    
        sending_addr = addr1
    
        # sort to get a consistent key for each packet
        data = sorted(zip(addrs, type_and_code, byts))
        # [((192,43,172,30), type, bytes), ((192,168,19,227), type, bytes)]

        # add other data 
        data.append(epoch_time)
        data.append(proto)

        #          0           1         2      
        #         ip1     ,   ip2  ,   type 
        key = (data[pc.p_ip1][pc.p_addr], data[pc.p_ip2][pc.p_addr], 
               type_and_code_for_key, vlan_id)

        # For ICMP, client is the first IP to send a packet.  Determine
        # client here since sorting done above may swap IP positions.
        # For the first packet, client_index is subsequently saved.
        if data[pc.p_ip1][pc.p_addr] == sending_addr:
            client_index = 0
        else:
            client_index = 1

        data.append(client_index)
        data.append(vlan_id)

        return key, data

#    @classmethod
#    def buildCriteriaDoc(pc, ci, si, a_info):
#        # Convert type from list to string
#        if len(a_info[ci][pc.i_type]) == 1:
#            ty1 = a_info[ci][pc.i_type][0]
#        else:
#            ty1 = ""
#            
#        session_criteria = {"ip1":trafcap.tupleToInt(a_info[ci][pc.i_addr]),
#                         "ip2":trafcap.tupleToInt(a_info[si][pc.i_addr]),
#                         "ty1":ty1,
#                         "tbm":trafcap.secondsToMinute(a_info[pc.i_tb]),
#                         "tem":{'$gte':trafcap.secondsToMinute(a_info[pc.i_tb])}}
#        return session_criteria

    @classmethod
    def buildInfoDoc(pc, ci, si, a_info):
        # Convert type from list to string
        if len(a_info[ci][pc.i_type]) == 1:
            ty1 = a_info[ci][pc.i_type][0]
        else:
            ty1 = ""
            
        tbm=trafcap.secondsToMinute(a_info[pc.i_tb])
        tem=trafcap.secondsToMinute(a_info[pc.i_te])
        info_doc = {"ip1":trafcap.tupleToInt(a_info[ci][pc.i_addr]),
                    "b1":a_info[ci][pc.i_bytes],
                    "ty1":ty1,
                    "ip2":trafcap.tupleToInt(a_info[si][pc.i_addr]),
                    "b2":a_info[si][pc.i_bytes],
                    "ty2":a_info[si][pc.i_type],
                    "bt":a_info[si][pc.i_bytes]+a_info[ci][pc.i_bytes], 
                    "tbm":tbm,
                    "tem":tem,
                    "tb":a_info[pc.i_tb],
                    "te":a_info[pc.i_te],
                    "pk":a_info[pc.i_pkts],
                    "cc1":a_info[pc.i_cc1],
                    "loc1":a_info[pc.i_loc1],
                    "cc2":a_info[pc.i_cc2],
                    "loc2":a_info[pc.i_loc2]}
        tdm = tem-tbm
        if tdm >= trafcap.lrs_min_duration: info_doc['tdm'] = tdm
        if a_info[pc.i_vl]: info_doc['vl'] = a_info[pc.i_vl]
        return info_doc

    @classmethod
    def buildBytesDoc(pc, ci, si, a_info, a_bytes):
        if len(a_info[ci][pc.i_type]) == 1:
            ty1 = a_info[ci][pc.i_type][0]
        else:
            ty1 = ""

        session_bytes = {"ip1":trafcap.tupleToInt(a_info[ci][pc.i_addr]),
                         "ty1":ty1,
                         "ip2":trafcap.tupleToInt(a_info[si][pc.i_addr]),
                         "ty2":a_info[si][pc.i_type],
                         "sb":a_bytes[pc.b_sb],
                         "se":a_bytes[pc.b_se],
                         "sbm":trafcap.secondsToMinute(a_bytes[pc.b_sb]),
                         "sem":trafcap.secondsToMinute(a_bytes[pc.b_se]),
                         "pk":a_bytes[pc.b_pkts],
                         "pr":a_info[pc.i_proto],
                         "b":a_bytes[pc.b_array],
                         "cc1":a_info[pc.i_cc1],
                         "loc1":a_info[pc.i_loc1],
                         "cc2":a_info[pc.i_cc2],
                         "loc2":a_info[pc.i_loc2]}
        if a_info[pc.i_vl]: session_bytes['vl'] = a_info[pc.i_vl]
        return session_bytes

    @classmethod
    def buildGroupsDoc(pc, a_group):
        group_bytes = []
        for item in a_group[pc.g_b]:
            if item[pc.g_1] != 0 or item[pc.g_2] != 0:
                group_bytes.append(item)

        group_data = {"ip1":a_group[pc.g_ip1],
                      "ty1":a_group[pc.g_ty1],
                      "b1":a_group[pc.g_b1],
                      "ip2":a_group[pc.g_ip2],
                      "b2":a_group[pc.g_b2],
                      "tbm":a_group[pc.g_tbm],
                      "tem":a_group[pc.g_tem],
                      "ns":a_group[pc.g_ns],
                      "ne":a_group[pc.g_ne],
                      #"pk":a_group[pc.g_pkts],
                      "pr":a_group[pc.g_proto],
                      "b":group_bytes,
                      "cc1":a_group[pc.g_cc1],
                      "loc1":a_group[pc.g_loc1],
                      "cc2":a_group[pc.g_cc2],
                      "loc2":a_group[pc.g_loc2]}
        if a_group[pc.g_vl]: group_data['vl'] = a_group[pc.g_vl]
        return group_data

    @classmethod
    def startSniffer(pc):
        filtr = 'ip ' + trafcap.cap_filter + ' and ip[9]==0x01'
        proc = subprocess.Popen(['/usr/bin/tshark', 
               '-i', trafcap.sniff_interface, 
               '-te', '-n', '-l',
               '-b', 'filesize:8192',
               '-b', 'files:5',
               '-w', '/run/trafcap_icmp',
               '-P',
               '-o', 
               'column.format:"""time","%t", "src","%s", "iplen","%Cus:ip.len", "dst","%d", "type","%Cus:icmp.type", "code","%Cus:icmp.code", "seq","%Cus:icmp.seq", "vl","%Cus:vlan.id"""',
               '-f',
                '('+filtr+') or (vlan and '+filtr+')'],
               bufsize=-1,
               stdout=subprocess.PIPE, stderr=sys.stdout.fileno())
        return proc
    
    @classmethod
    def getSessionKey(pc, a_bytes):
        # If no vlan_id, set it to None so key is valid.  Happens at startup
        # when reading docs in from mongo to create session_history
        if not 'vl' in a_bytes: a_bytes['vl'] = None
        return (a_bytes['ip1'], tuple(a_bytes['ty1']), 
                a_bytes['ip2'], tuple(a_bytes['ty2']), a_bytes['vl'])

    @classmethod
    def getGroupKey(pc, a_bytes):
        return (a_bytes['ip1'], a_bytes['ty1'], a_bytes['ip2'])

    @classmethod
    def updateGroupsDict(pc, a_bytes, chunck_size, doc_win_start):
        tmp_array = []
        for a_index in range(0, 90, 1):
            tmp_array.append([a_index*chunck_size, 0, 0])

        a_group =[a_bytes['ip1'], a_bytes['ty1'], 0,
                  a_bytes['ip2'], 0,
                  doc_win_start, trafcap.secondsToMinute(a_bytes['se']),
                  0, 0,
                  tmp_array, 0, a_bytes.get('pr', None),
                  a_bytes['cc1'], a_bytes['loc1'], 
                  a_bytes['cc2'], a_bytes['loc2'], None, a_bytes['vl']]
        return a_group

    @classmethod
    def updateInfoDict(pc, data, a_info):
        # Type and code for client_index IP is part of key & is unchanged.
        # Update type and code for server_index if needed
        si = abs(a_info[pc.i_ci] - 1)
        stored_si_type_list = a_info[si][pc.i_type]
        if len(data[si][pc.p_type]) > 0:
            new_si_type = data[si][pc.p_type][0]
            if new_si_type not in stored_si_type_list:
                stored_si_type_list.append(new_si_type)

    @classmethod
    def findClient(pc, data, new_info):
        # For the first ICMP packet, record the client_index noted by
        # the parse method.
        # For ICMP assume IP sending first packet is the client.
        new_info[pc.i_ci] = data[pc.p_ci]

    @classmethod
    def buildInfoDictItem(pc, key, data):
        if key == pc.capture_dict_key:
            new_info=[[(0,0,0,0),[],0], [(0,0,0,0),[],0], 
                      float(data[pc.p_etime]), float(data[pc.p_etime]),
                      1, 0, data[pc.p_proto],
                      float(data[pc.p_etime]),True,
                      0, 0, 0, 0, None, None] 
        else:
            cc1, name1, loc1 = trafcap.geoIpLookup(data[pc.p_ip1][pc.p_addr])
            cc2, name2, loc2 = trafcap.geoIpLookup(data[pc.p_ip2][pc.p_addr])

            # Create new dictionary entry.
            # Zip creates tuples, convert to lists so they can be manipulated.
            new_info = [list(data[pc.p_ip1]), list(data[pc.p_ip2]),
                        float(data[pc.p_etime]), float(data[pc.p_etime]),
                        1, 0, data[pc.p_proto],
                        float(data[pc.p_etime]),True,
                        cc1, loc1, cc2, loc2, None, data[pc.p_vl]]

            pc.findClient(data, new_info)
        return new_info


class RtpPacket(IpPacket):
    """
    For handling RTP packets (assumes IPv4)
    """
    def __init__(self):
        return

    sampling_freq = 8000                           # Hz
    sample_size = 1./sampling_freq                 # seconds
    jitter_ts_units_to_msec_conv = 1000./ \
                                   sampling_freq   # ms / rpt_ts_unit
    bytes_per_sample = 1                           # 8 bits
    rtp_bytes_per_packet = 160                     # 20 ip + 8 udp + 12 rtp +
                                                   #       + 160 pyld =200
    audio_per_packet = rtp_bytes_per_packet * \
                       sample_size                 # 20 ms
    circ_bufr_duration = .1                         # seconds 
    circ_bufr_len = int(circ_bufr_duration / \
                        audio_per_packet)          # items in array 

    jitr_bufr_len = 15                             # 15 * 20ms = 300 ms 
    jitr_bufr_dict = {}                         # Used to calculate packet loss
    # need to specify ports to listen on
    

    # Legend for UDP packet data list returned by the parse method:
    # data[0]    (ip1)  ,    data[1]   (ip2) , [2]  , [3] ,    [4]
    #[(addr),port,bytes], [(addr),port,bytes],epoch ,proto, client_index
    p_ip1=0; p_ip2=1
    p_addr=0; p_port=1; p_bytes=2;
    p_ssrc=2
    p_etime=3
    p_proto=4
    p_seq=5
    p_smpl_time=6
    p_ci=7
    p_vl=8

    # Legend for how UDP packet data is stored in the Session Info 
    # dictionary and in the Capture Info dictionary 
    #  data[0] (ip1)   ,  data[1]  (ip2)  , [2], [3], [4], [5],  [6]
    #[[(adr),port,byts], [(adr),port,byts], tb , te , pkts,  ci, proto]
    i_ip1=0; i_ip2=1
    i_addr=0; i_port=1; i_bytes=2;
    i_tb=2; i_te=3; i_pkts=4; i_ci=5; i_proto=6
    i_ssrc=7
    i_ini_seq=8
    i_ldwt=9      # last_db_write_time
    i_csldw=10    # changed_since_last_db_write
    i_cc1=11
    i_loc1=12
    i_cc2=13
    i_loc2=14
    i_id=15       # mongo object id
    i_circ_bufr=16; i_arvl_time=0; i_seq=1; i_smpl_time=2
    i_vl=17       # vlan id

    # Legend for how data is stored in the Session Bytes dictionary 
    # and the Capture Bytes dictionary 
    b_key=0; b_addr1=0; b_port1=1; b_addr2=2; b_port2=3; b_ssrc=4; b_vl=5
    b_sb=1; b_se=2; 
    b_array=3; b_offset=0; b_bytes1=1; b_bytes2=2
    b_lpj_array=4; b_offset=0; b_ltnc=1; b_pkt_loss=2; b_jitr=3
    b_pkts_lost=5
    b_pkts_totl=6
    b_r_sub_i=7
    b_s_sub_i=8
    b_prev_jitr=9   # used in jitter calculation
    b_prev_seq=10   # used in packet loss calculation
    b_pkts=11
    b_ldwt=12       # last_db_write_time
    b_csldw=13      # changed_since_last_db_write
    #b_cc1=10
    #b_loc1=11
    #b_cc2=12
    #b_loc2=13

    capture_dict_key = ((0,0,0,0),0, (0,0,0,0),0, '', None)

    @classmethod
    def parse(pc, pkt, doc):
        if pkt and not doc:

            pkt_len = len(pkt)

            # Handle this:
            # 1457555571.447479  10.10.20.45 10533 10.10.48.41  10299 104     UDP
            if pkt_len <= 7:
                #print 'Invalid RTP packet length: ', pkt
                return (), []

            else:
# typical packet
# 1457556004.797061  10.10.20.46 10498 10.200.1.218 10000 360 0xc2c14587 (3267446151) 24200 828152408 99,127,127,0 RTP
# 1457556004.815568 10.200.1.218 10000 10.10.20.46  10498 360 0x52ae122e (1387139630) 33190 1365478476 99,0 RTP

                a1_1,a1_2,a1_3,a1_4 = pkt[1].split(".")
                a2_1,a2_2,a2_3,a2_4 = pkt[3].split(".")
    
                ports = [int(pkt[2]), int(pkt[4])]
                byts = [int(pkt[5]), 0]
                
                ssrc = pkt[6][2:10]
                # Tshark removes leading zeros in ssrc.  
                # Prepend zeros if ssrc < 8 chars
                zeros_needed = 8 - len(ssrc)
                ssrc = '0'*zeros_needed + ssrc
                # ssrc also available as an int
                #ssrc = int(pkt[7][1:-1])
    
                sequence = int(pkt[8])
                sample_time = int(pkt[9])
                payload_type = pkt[10]
                proto = pkt[11]
    
                # Represent IP addresses a tuples instead of strings
                addr1 = (int(a1_1), int(a1_2), int(a1_3), int(a1_4))
                addr2 = (int(a2_1), int(a2_2), int(a2_3), int(a2_4))
                addrs = [addr1, addr2]
                epoch_time = pkt[0]
    
        elif doc and not pkt:
            addr1 = trafcap.intToTuple(doc['ip1'])
            addr2 = trafcap.intToTuple(doc['ip2'])
            addrs = [addr1, addr2]
            ports = [doc['p1'], doc['p2']]
            byts = [doc['b1'], doc['b2']]
            epoch_time = doc['tb']
            proto = doc.get('pr', None)
            ssrc = doc['ssrc']
            sequence = 0            # Need to add!
            sample_time = 0         #  Need to add!
            pass

        else:
            return (), [] 

        sending_addr = addr1

        # sort to get a consistent key for each session
        data = sorted(zip(addrs, ports, byts))
        # [((192, 43, 172, 30), 53, 0), ((192, 168, 19, 227), 53629, 68)]

        # add the data 
        data.append(ssrc)
        data.append(epoch_time)
        data.append(proto)
        data.append(sequence)
        data.append(sample_time)

        vlan_id = None
        #          0           1           2           3
        #         ip1    ,   port1   ,    ip2    ,   port2
        key = (data[pc.p_ip1][pc.p_addr], data[pc.p_ip1][pc.p_port], 
               data[pc.p_ip2][pc.p_addr], data[pc.p_ip2][pc.p_port], 
               data[pc.p_ssrc], vlan_id)

        # For UDP, client is the first IP to send a packet.  Determine
        # client here since sorting done above may swap IP positions.
        # For the first packet, client_index is subsequently saved.
        if data[pc.p_ip1][pc.p_addr] == sending_addr:
            client_index = 0
        else:
            client_index = 1

        data.append(client_index)
        data.append(vlan_id)
        #print data
        return key, data

    @classmethod
    def buildInfoDoc(pc, ci, si, a_info):
        tbm=trafcap.secondsToMinute(a_info[pc.i_tb])
        tem=trafcap.secondsToMinute(a_info[pc.i_te])
        info_doc = {"ip1":trafcap.tupleToInt(a_info[ci][pc.i_addr]),
                    "p1":a_info[ci][pc.i_port],
                    "b1":a_info[ci][pc.i_bytes],
                    "ip2":trafcap.tupleToInt(a_info[si][pc.i_addr]),
                    "p2":a_info[si][pc.i_port],
                    "b2":a_info[si][pc.i_bytes],
                    "bt":a_info[si][pc.i_bytes]+a_info[ci][pc.i_bytes],
                    "tbm":tbm,
                    "tem":tem,
                    "tb":a_info[pc.i_tb],
                    "te":a_info[pc.i_te],
                    "pk":a_info[pc.i_pkts],
                    "pr":a_info[pc.i_proto],
                    #"cc1":a_info[pc.i_cc1],
                    #"loc1":a_info[pc.i_loc1],
                    #"cc2":a_info[pc.i_cc2],
                    #"loc2":a_info[pc.i_loc2],
                    "ssrc":a_info[pc.i_ssrc]}
        tdm = tem-tbm
        if tdm >= trafcap.lrs_min_duration: info_doc['tdm'] = tdm
        if a_info[pc.i_vl]: info_doc['vl'] = a_info[pc.i_vl]
        return info_doc

    @classmethod
    def buildBytesDoc(pc, ci, si, a_info, a_bytes):
        session_bytes = {"ip1":trafcap.tupleToInt(a_info[ci][pc.i_addr]),
                         "p1":a_info[ci][pc.i_port],
                         "ip2":trafcap.tupleToInt(a_info[si][pc.i_addr]),
                         "p2":a_info[si][pc.i_port],
                         "sb":a_bytes[pc.b_sb],
                         "se":a_bytes[pc.b_se],
                         "sbm":trafcap.secondsToMinute(a_bytes[pc.b_sb]),
                         "sem":trafcap.secondsToMinute(a_bytes[pc.b_se]),
                         "pk":a_bytes[pc.b_pkts],
                         "pr":a_info[pc.i_proto],
                         #"cc1":a_info[pc.i_cc1],
                         #"loc1":a_info[pc.i_loc1],
                         #"cc2":a_info[pc.i_cc2],
                         #"loc2":a_info[pc.i_loc2],
                         "b":a_bytes[pc.b_array],
                         "ssrc":a_info[pc.i_ssrc],
                         "lpj":a_bytes[pc.b_lpj_array]}
        if a_info[pc.i_vl]: session_bytes['vl'] = a_info[pc.i_vl]

# Not using cir_bufr for packet_loss calculation at this time
#        # Use circ_bufr data (indexed by rtp seq #) to calculate packet loss
#        # for each item in lpj_array (indexed by epoch time seq #)
#        for item in a_bytes[pc.b_lpj_array]:
#            epoch_seq = a_bytes[pc.b_sb] + item[pc.b_offset]
#            # find first circ_bufr item with arrival_time >= epoch_seq
#            start_index = bisect_left(circ_bufr[:,0:1],[a_bytes[pc.b_sb]])
#
#            # roll buffer backward to eliminate wrap-around problem
#            rolled_circ_bufr = numpy.roll(circ_bufr, -start_index)
#
#            # take one-second slice of array  
#            one_sec_offset = circ_bufr_len / circ_bufr_duration
#            rolled_circ_bufr_slice = rolled_circ_bufr[0:one_sec_offset]
#             
#            # find number of items with arrival_time < epoch_seq
#            drop_pkts_array = numpy.where(rolled_circ_bufr_slice[:0,1] < 
#                                          a_bytes[pc.b_sb])
#
#            # insert answer into lpj array
#            print 'pkt_loss = ', len(drop_pkts_array)
#            #item[pc.b_pkt_loss] = len(drop_pkts_array)
            
        return session_bytes

    @classmethod
    def startSniffer(pc):
        filtr = 'ip ' + trafcap.cap_filter + ' and ip[9]==0x11 and ' + \
                'udp portrange '+trafcap.rtp_portrange

        param_list = ['/usr/bin/tshark',                        
               '-i', trafcap.sniff_interface,
               '-te', '-l',
               '-b', 'filesize:8192',
               '-b', 'files:5',
               '-w', '/run/trafcap_rtp',
               '-P',
               '-o',
               'column.format:"""time","%t", "src","%s", "sport","%Cus:udp.srcport", "dst","%d", "dprt","%Cus:udp.dstport", "iplen","%Cus:ip.len", "ssrc","%Cus:rtp.ssrc","seq","%Cus:rtp.seq","ts","%Cus:rtp.timestamp","pt","%Cus:rtp.p_type","proto","%p"""',
               '-f',
               '('+filtr+') or (vlan and '+filtr+')']

               # Unpredictable output
               #'column.format:"""time","%t", "src","%s", "sport","%Cus:udp.srcport", "dst","%d", "dprt","%Cus:udp.dstport", "iplen","%Cus:ip.len", "protocol","%p","i","%i"""',

        # add protocol decode for rtp ports
        insert_index = 14
        # port_range from config file is a string, convert to ints
        first_port, last_port = trafcap.rtp_portrange.split('-')
        first_port = int(first_port)
        last_port = int(last_port)

        a_port = first_port
        while (a_port >= first_port and a_port <= last_port):
            param_list.insert(insert_index, '-d')
            param_list.insert(insert_index+1, 'udp.port=='+str(a_port)+',rtp')
            insert_index+=2
            a_port+=2

        proc = subprocess.Popen(param_list, bufsize=-1,
                          stdout=subprocess.PIPE, stderr=sys.stdout.fileno())
        return proc
    
    @classmethod
    def updateInfoDict(pc, data, a_info):
        # update circular buffer 
        offset = (data[pc.p_seq] - a_info[pc.i_ini_seq])%pc.circ_bufr_len
        a_info[pc.i_circ_bufr][offset][pc.i_arvl_time] = data[pc.p_etime]
        a_info[pc.i_circ_bufr][offset][pc.i_seq] = data[pc.p_seq]
        a_info[pc.i_circ_bufr][offset][pc.i_smpl_time] = data[pc.p_smpl_time]
        return

    @classmethod
    def findClient(pc, data, new_info):
        # For the first UDP packet, record the client_index noted by
        # the parse method.
        # For UDP assume IP sending first packet is the client.
        new_info[pc.i_ci] = data[pc.p_ci]


    #@classmethod
    #def initializeCaptureBytes(pc):
    #    key = list(pc.capture_dict_key)
    #    capture_bytes_list = [key, 0, 0, 
    #                          [[0,0,0]], [[0,0.,0,0.]],
    #                          0, 0 ,0., 0, 0., 0, 0, 0, False]
    #    return capture_bytes_list

    @classmethod
    def buildInfoDictItem(pc, key, data):
        if key == pc.capture_dict_key:
            new_info = [[(0,0,0,0),0,0], [(0,0,0,0),0,0], 
                        float(data[pc.p_etime]), float(data[pc.p_etime]),
                        1, 0, '', '', 0,
                        float(data[pc.p_etime]), True, 
                        0, 0, 0, 0, None, None, None] 
        else:
            # Skip country lookup - VoIP traffic usually intenral
            #cc1, name1, loc1 = trafcap.geoIpLookup(data[pc.p_ip1][pc.p_addr])
            #cc2, name2, loc2 = trafcap.geoIpLookup(data[pc.p_ip2][pc.p_addr])
            cc1 = loc1 = cc2 = loc2 = None

            # build circular buffer
            circ_bufr = []
            for offset in range(0,pc.circ_bufr_len):
               circ_bufr.append([0., 0, 0]) 
            #circ_bufr = numpy.zeros(shape=(pc.circ_bufr_len,3))

            # Create new dictionary entry.
            # Zip creates tuples, convert to lists so they can be manipulated.
            new_info = [list(data[pc.p_ip1]), list(data[pc.p_ip2]),
                        float(data[pc.p_etime]), float(data[pc.p_etime]),
                        1, 0, data[pc.p_proto], data[pc.p_ssrc], data[pc.p_seq],
                        float(data[pc.p_etime]), True, 
                        cc1, loc1, cc2, loc2, None, circ_bufr, data[pc.p_vl]]

            pc.findClient(data, new_info)
        return new_info

    @classmethod
    def buildBytesDictItem(pc, key, data, curr_seq, ip1_bytes, ip2_bytes):
        if key == pc.capture_dict_key:
            new_bytes = [key, curr_seq, curr_seq, 
                        [[0,0,0]], 
                        [[0, 0., 0, 0.]],
                        0, 0 ,
                        float(data[pc.p_etime]), data[pc.p_smpl_time], 
                        0., 0, 1, float(data[pc.p_etime]), True]
        else:
            new_bytes = [list(key), curr_seq, curr_seq,
                        [[0, ip1_bytes, ip2_bytes]], 
                        [[0, 0., 0., 0.]], 
                        0, 0,
                        float(data[pc.p_etime]), data[pc.p_smpl_time], 
                        0., 0, 1, float(data[pc.p_etime]) ,True]
        return new_bytes

    @classmethod
    def updateBytesDict(pc, key, data, curr_seq, a_bytes):
        # Update jitter 

        # From RFC 3550
        #   If Si is the RTP timestamp from packet i, and Ri is the time of
        #   arrival in RTP timestamp units for packet i, then for two packets
        #   i and j, D may be expressed as
        #
        #      D(i,j) = (Rj - Ri) - (Sj - Si) = (Rj - Sj) - (Ri - Si)
        #
        #   The interarrival jitter SHOULD be calculated continuously as each
        #   data packet i is received from source SSRC_n, using this
        #   difference D for that packet and the previous packet i-1 in order
        #   of arrival (not necessarily in sequence), according to the formula
        #
        #      J(i) = J(i-1) + (|D(i-1,i)| - J(i-1))/16
        
        # Arrival time difference in RTP timestamp units.  Is a float
        delta_r = (float(data[pc.p_etime]) - a_bytes[pc.b_r_sub_i]) / \
                  pc.sample_size

        # Should delta_r be converted to an int ?
        delta_s = (data[pc.p_smpl_time] - a_bytes[pc.b_s_sub_i])    # int
        d = delta_r - delta_s
        #print 'delta_r: ', delta_r, '   delta_s: ', delta_s, '   d:', d

        j = a_bytes[pc.b_prev_jitr] + \
            ( abs(d) - a_bytes[pc.b_prev_jitr] ) / 16.

        # If container's updateBytesDict method added item to bytes array,
        # then also add item to lpj array
        diff = len(a_bytes[pc.b_array]) - len(a_bytes[pc.b_lpj_array]) 
        if diff == 0:
            pass
        elif diff == 1:
            offset = a_bytes[pc.b_array][-1][0] 
            a_bytes[pc.b_lpj_array].append([offset, 0., 0., 0.])
            a_bytes[pc.b_pkts_lost] = 0
            a_bytes[pc.b_pkts_totl] = 0
        else:
            print 'Problem with bytes arrays...'
            print a_bytes

        a_bytes[pc.b_lpj_array][-1][pc.b_jitr] = \
                                    round(j*pc.jitter_ts_units_to_msec_conv, 1)
                                    #round(j, 1)
         
        a_bytes[pc.b_r_sub_i] = float(data[pc.p_etime])
        a_bytes[pc.b_s_sub_i] = data[pc.p_smpl_time]
        a_bytes[pc.b_prev_jitr] = j

        # update packet loss
        try:
            jitr_bufr = pc.jitr_bufr_dict[key]
        except KeyError:
            jitr_bufr = []
            pc.jitr_bufr_dict[key] = jitr_bufr

        # update total packet count in this smallest interval
        a_bytes[pc.b_pkts_totl] += 1

        # If seq of current packet < seq of last packet converted from digital
        # to analog, then packet is already counted as lost.
        if data[pc.p_seq] <= a_bytes[pc.b_prev_seq]:
            return

        insort(jitr_bufr, data[pc.p_seq])
        if len(jitr_bufr) >= pc.jitr_bufr_len:
            # remove the seq# that would be converted from digital to analog
            seq_d2a = jitr_bufr.pop(0)    
            if a_bytes[pc.b_prev_seq] != 0:
                # Lost packets are between seq_d2a and prev_seq_d2a
                a_bytes[pc.b_pkts_lost] += seq_d2a - 1 - a_bytes[pc.b_prev_seq]
            a_bytes[pc.b_prev_seq] = seq_d2a

        a_bytes[pc.b_lpj_array][-1][pc.b_pkt_loss] = \
                float(a_bytes[pc.b_pkts_lost]) / float(a_bytes[pc.b_pkts_totl])
        return

class TcpInjPacket(IpPacket):
    """
    For handling injection of TCP packets (assumes IPv4)
    """
    def __init__(self):
        return

    # Legend for TCP packet data list returned by the parse method:
    #        data[0]  (ip1)     ,     data[1]   (ip2)       , [2]  , [3]
    #[[(addr),port,bytes,[flag]], [(addr),port,bytes,[flag]],epoch ,proto]
    #p_ip1=0; p_ip2=1
    p_addr=0; p_port=1; p_bytes=2; p_flags=3
    p_etime=4
    p_proto=5
    p_seq=6
    p_ack=7

    # Legend for how TCP packet data is stored in the blocked_info dict 
    i_ip1=0; i_ip2=1     # must be 0 and 1 for i_bi index to work
    i_port1=2; i_port2=3 
    i_bi=4        # index of IP that caused block (0 or 1)
    i_tb=5; i_te=6; i_pkts=7
    i_ldwt=8      # last_db_write_time
    i_csldw=9     # changed_since_last_db_write
    i_cc=10
    i_loc=11
    i_id=12        # mongo object id

    @classmethod
    def parse(pc, pkt, doc):

        # only handle case where pkt is provided
        if doc: return (), [] 

        # ['1410363194.655211', 'IP', '172.16.254.61.443', '>', '134.228.162.229.65453:', 'Flags', '[.],', 'seq', '4164627753:4164629133,', 'ack', '2912381136,', 'win', '64135,', 'length', '1380']
        # ['1410363194.672410', 'IP', '134.228.162.229.65453', '>', '172.16.254.61.443:', 'Flags', '[.],', 'ack', '4164638793,', 'win', '64860,', 'length', '0']

        # parse packet off the wire
        if pkt:
            # IPv4

            # Misc data sometimes appended to length.  For example:
            #  length 1[|SMB]
            #  length 1380SMB-over-TCP packet:(raw data or continuation?)
            #bytes1 = int(pkt[-1].strip(':'))
            a1_1,a1_2,a1_3,a1_4,port1 = pkt[2].split(".")
            a2_1,a2_2,a2_3,a2_4,port2 = pkt[4].strip(":").split(".")
            flag1_string = pkt[6].strip(",").strip("[").strip("]")
            if pkt[7] == 'ack':
                ack = int(pkt[8].strip(','))
                seq1 = None
                bytes1 = 0
            elif pkt[7] == 'seq':
                if ':' in pkt[8]:
                   seq1,seq2 = pkt[8].strip(',').split(':')
                   seq1=int(seq1)
                   seq2=int(seq2)
                   bytes1 = seq2-seq1
                else:
                   seq1 = int(pkt[8].strip(','))
                   bytes1 = 0
                if pkt[9] == 'ack':
                    ack = int(pkt[10].strip(','))
                else:
                    ack = None
            else:
                raise Exception('Unexpected ethertype.')
                
        else:
            # Record packet details for future handling
            # IPv6 handled in Other traffic
            raise Exception('Unexpected ethertype.')

        port1_int = int(port1)
        port2_int = int(port2)
        if port1_int > 65535 or port2_int > 65535:
            return (), [] 

        # Handle case of SYN-ACK flag by changing the flag from S to s
        if (flag1_string == "S."):
            flag1_string = "s"

        # Represent IP addresses a tuples instead of strings
        addr1 = (int(a1_1), int(a1_2), int(a1_3), int(a1_4))
        addr2 = (int(a2_1), int(a2_2), int(a2_3), int(a2_4))
        
        # Not needed since zip/sort is not done below
        addrs = [addr1, addr2]
        ports = [port1_int, port2_int]
        #byts = [bytes1, 0]
        epoch_time = float(pkt[0])
        proto = "_"                            # for future use 

        # Sort to get a consistent key for each TCP session
        #data = sorted(zip(addrs, ports, byts, flag_list))
        #[((1,2,3,4), 25254, 0, 's'),
        # ((9,8,7,6), 22,  140, '')]

        # do not sort - need to preserve IP order for inject decisions
        data = [addrs, ports, bytes1, flag1_string, epoch_time, proto, seq1, ack]

        # Add packet data - unrelated to any IP
        #data.append(epoch_time)
        #data.append(proto)
        #data.append(seq1)
        #data.append(ack)
    
        #         0            1           2           3
        #        ip1     ,   port1   ,    ip2    ,   port2
        #key = (data[pc.p_ip1][pc.p_addr], data[pc.p_ip1][pc.p_port], 
        #       data[pc.p_ip2][pc.p_addr], data[pc.p_ip2][pc.p_port])
        #       data[pc.p_vl])

        # Unlike tcp ingest, data IP order may not match key IP order.
        # Need to know src/dst IP for data inject.  Also need
        # to have consistent key for each pkt in conversation.
        # Key order may be swapped later when inject decisions are made.
        key = ((addr1, port1_int), (addr2, port2_int))

        return key, data

    @classmethod
    def startSniffer(pc):
        filtr = 'ip ' + trafcap.inj_filter + ' and ip[9]==0x06'
        proc = subprocess.Popen(['/usr/sbin/tcpdump', 
                  '-i', trafcap.sniff_interface,
                  '-n', '-tt', '-B', '40960', '-s', '127',
                  '-K', '-U', '-S', '-f',
                   '('+filtr+') or (vlan and '+filtr+')'],
                   bufsize=-1,
                   stdout=subprocess.PIPE, stderr=sys.stdout.fileno())
        return proc

    @classmethod
    def injectB2G(pc, data, s):

        # Create a new IP packet and set its source and destination addresses.
        #ip.set_ip_id(1)         # increments by default
        #ip.set_ip_ttl(128)      # ff by default
        #tcp.set_th_ack(0)         # 0 by default
        #tcp.set_th_win(8192)      # 0 by default
        #tcp.contains(ImpactPacket.Data( "lalala"))
        #tcp.auto_checksum=1

        ip = ImpactPacket.IP()
        tcp = ImpactPacket.TCP()
        tcp.set_th_off(5)
 
        if 'S' in data[pc.p_flags]:
            ip.set_ip_src(trafcap.tupleToString(data[pc.p_addr][0]))
            ip.set_ip_dst(trafcap.tupleToString(data[pc.p_addr][1]))
            tcp.set_th_sport(data[pc.p_port][0])
            tcp.set_th_dport(data[pc.p_port][1])
            #             ACK RST
            #           CWR | | FIN 
            #             | | | |
            flags = int('00000100',2)
            #            | | | |
            #          ECE | | SYN
            #            URG PSH
            tcp.set_th_flags(flags)
            tcp.set_th_seq(data[pc.p_seq]+1) 
            #tcp.set_th_seq(data[pc.p_seq]+data[pc.p_bytes[0]]) 
            tcp.set_th_ack(0)         # 0 by default
            ip.contains(tcp)
            s.sendto(ip.get_packet(), 
                     (trafcap.tupleToString(data[pc.p_addr][1]), 
                     data[pc.p_port][1]))
        elif 'R' in data[pc.p_flags] or 'F' in data[pc.p_flags]:
            # This prevents a loop of an inj pkt triggering another inj pkt
            return
        else:
            if data[pc.p_seq]:   
                ip.set_ip_src(trafcap.tupleToString(data[pc.p_addr][0]))
                ip.set_ip_dst(trafcap.tupleToString(data[pc.p_addr][1]))
                tcp.set_th_sport(data[pc.p_port][0])
                tcp.set_th_dport(data[pc.p_port][1])
                tcp.set_th_seq(data[pc.p_seq]+data[pc.p_bytes]) 
                if data[pc.p_ack]:
                    tcp.set_th_ack(data[pc.p_ack])
                    #             ACK RST
                    #           CWR | | FIN 
                    #             | | | |
                    flags = int('00010101',2)
                    #            | | | |
                    #          ECE | | SYN
                    #            URG PSH
                else:
                    tcp.set_th_ack(0)
                    flags = int('00000101',2)
                tcp.set_th_flags(flags)
                ip.contains(tcp)
                s.sendto(ip.get_packet(), 
                         (trafcap.tupleToString(data[pc.p_addr][1]), 
                         data[pc.p_port][1]))

        #print 'B2G', data
 

    @classmethod
    def injectG2B(pc, data, s):

        # Create a new IP packet and set its source and destination addresses.
        #ip.set_ip_id(1)         # increments by default
        #ip.set_ip_ttl(128)      # ff by default
        #tcp.set_th_ack(0)         # 0 by default
        #tcp.set_th_win(8192)      # 0 by default
        #tcp.contains(ImpactPacket.Data( "lalala"))
        #tcp.auto_checksum=1
 
        ip = ImpactPacket.IP()
        tcp = ImpactPacket.TCP()
        tcp.set_th_off(5)
 
        if data[pc.p_flags] == 's':
            ip.set_ip_src(trafcap.tupleToString(data[pc.p_addr][1]))
            ip.set_ip_dst(trafcap.tupleToString(data[pc.p_addr][0]))
            tcp.set_th_sport(data[pc.p_port][1])
            tcp.set_th_dport(data[pc.p_port][0])
            #             ACK RST
            #           CWR | | FIN 
            #             | | | |
            flags = int('00010101',2)
            #            | | | |
            #          ECE | | SYN
            #            URG PSH
            tcp.set_th_flags(flags)
            tcp.set_th_seq(data[pc.p_ack]) 
            tcp.set_th_ack(data[pc.p_seq]+1) 
            ip.contains(tcp)
            s.sendto(ip.get_packet(), 
                     (trafcap.tupleToString(data[pc.p_addr][0]), 
                     data[pc.p_port][0]))
        elif 'R' in data[pc.p_flags] or 'F' in data[pc.p_flags]:
            # This prevents a loop of an inj pkt triggering another inj pkt
            return
        else:
            ip.set_ip_src(trafcap.tupleToString(data[pc.p_addr][1]))
            ip.set_ip_dst(trafcap.tupleToString(data[pc.p_addr][0]))
            tcp.set_th_sport(data[pc.p_port][1])
            tcp.set_th_dport(data[pc.p_port][0])
            #             ACK RST
            #           CWR | | FIN 
            #             | | | |
            flags = int('00000101',2)
            #            | | | |
            #          ECE | | SYN
            #            URG PSH

            # Sometimes ack is None, in that case do not use it 
            if data[pc.p_ack]: tcp.set_th_seq(data[pc.p_ack]) 

            if data[pc.p_seq]:   
                # defaults to zero
                flags = int('00010101',2)
                tcp.set_th_ack(data[pc.p_seq]+data[pc.p_bytes]) 
            tcp.set_th_flags(flags)
            ip.contains(tcp)
            s.sendto(ip.get_packet(), 
                     (trafcap.tupleToString(data[pc.p_addr][0]), 
                     data[pc.p_port][0]))

        # Randomly send packet to attacker.  4 bits selected randomly.  
        # If all 4 are 0 (1/16 of the time), then a packet is sent.
        if data[pc.p_seq] and not bool(random.getrandbits(3)):   
            # Send RST packet to bad IP
            ip = ImpactPacket.IP()
            tcp = ImpactPacket.TCP()
            tcp.set_th_off(5)
     
            ip.set_ip_src(trafcap.tupleToString(data[pc.p_addr][0]))
            ip.set_ip_dst(trafcap.tupleToString(data[pc.p_addr][1]))
            tcp.set_th_sport(data[pc.p_port][0])
            tcp.set_th_dport(data[pc.p_port][1])
            #             ACK RST
            #           CWR | | FIN 
            #             | | | |
            flags = int('00000100',2)
            #            | | | |
            #          ECE | | SYN
            #            URG PSH
            tcp.set_th_flags(flags)
            tcp.set_th_seq(data[pc.p_seq]+data[pc.p_bytes]) 
            #tcp.set_th_ack(data[pc.p_seq]+1) 
            ip.contains(tcp)
            s.sendto(ip.get_packet(), 
                     (trafcap.tupleToString(data[pc.p_addr][0]), 
                      data[pc.p_port][0]))

    @classmethod
    def buildInfoDoc(pc, a_info):
        tbm=trafcap.secondsToMinute(a_info[pc.i_tb])
        tem=trafcap.secondsToMinute(a_info[pc.i_te])
        #bi = a_info[pc.i_bi]
        #not_bi = abs(bi - 1)  # This IP did not cause the block
        if a_info[pc.i_cc] == None:
            cc, name, loc = trafcap.geoIpLookup(a_info[a_info[pc.i_bi]])
            a_info[pc.i_cc] = cc
            a_info[pc.i_loc] = loc 
            
        info_doc = {"ip1":trafcap.tupleToInt(a_info[pc.i_ip1]),
                    "p1":a_info[pc.i_port1],
                    "ip2":trafcap.tupleToInt(a_info[pc.i_ip2]),
                    "p2":a_info[pc.i_port2],
                    "tbm":tbm,
                    "tem":tem,
                    "tb":a_info[pc.i_tb],
                    "te":a_info[pc.i_te],
                    "cc":a_info[pc.i_cc],
                    "loc":a_info[pc.i_loc],
                    "pk":a_info[pc.i_pkts]}
        tdm = tem-tbm
        if tdm >= trafcap.lrs_min_duration: info_doc['tdm'] = tdm
        #if a_info[pc.i_vl]: info_doc['vl'] = a_info[pc.i_vl]
        return info_doc
