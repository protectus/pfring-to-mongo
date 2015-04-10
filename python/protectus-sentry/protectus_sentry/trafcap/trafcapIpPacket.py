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
                  tmp_array, 0, a_bytes['pr'],
                  a_bytes['cc1'], a_bytes['loc1'], 
                  a_bytes['cc2'], a_bytes['loc2'], None, a_bytes['vl']]
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
                vlan_id = int(pkt[10].strip(','))
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
            proto = doc['pr']
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
                   bufsize=-1, stdout=subprocess.PIPE)
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
        if 'S' in new_info[pc.i_ip1][pc.i_flags]:
            new_info[pc.i_ci] = 0
        elif 'S' in new_info[pc.i_ip2][pc.i_flags]:
            new_info[pc.i_ci] = 1
        elif new_info[pc.i_ip2][pc.i_port] > new_info[pc.i_ip1][pc.i_port]:
            # If no syn flag, assume client has largest port number
            new_info[pc.i_ci] = 1
        else:
            # Ports are equal, select ip1
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
            pkt_len = len(pkt)
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
                vlan_id = int(pkt[1])

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
                vlan_id = int(pkt[1])

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
            proto = doc['pr']
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
               bufsize=-1, stdout=subprocess.PIPE)
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
                    vlan_id = int(pkt[8])
                elif len(pkt) == 8:
                    vlan_id = None
                else:
                    raise Exception('Unexpected ICMP packet')
            else:
                seq = 0 
                if len(pkt) == 7:
                    vlan_id = int(pkt[6])
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
               bufsize=-1, stdout=subprocess.PIPE)
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
                  tmp_array, 0, a_bytes['pr'],
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

# Need to handle:
#Error parsing rtp packet:  ['1378211937.721699', '192.168.153.61', '10000', '192.168.154.206', '10090', '44', 'RTP', 'PT=DynamicRTP-Type-102,', 'SSRC=0x1FFD08E5,', 'Seq=10898,', 'Time=329132955']

    @classmethod
    def parse(pc, pkt, doc):
        if pkt and not doc:
            if len(pkt) > 14:
# Handle this:
#['1377962613.764819', '192.168.245.2', '10001', '192.168.154.2', '55329', '236', 'RTP', 'PT=Reserved', 'for', 'RTCP', 'conflict', 'avoidance,', 'SSRC=0x2EE032,', 'Seq=6,', 'Time=1248342066,', 'Mark']
                #print 'Invalid RTP packet length: ', pkt
                return (), []
            elif len(pkt) >= 13:
# First packet len = 14
#1377793619.734068 192.168.153.60 10002 192.168.154.206 10462 200 RTP PT=ITU-T G.711 PCMU, SSRC=0x776E7820, Seq=46573, Time=1802996531 Mark

# Subsequent packets have len = 13
#1377793619.743568 192.168.154.206 10462 192.168.153.60 10002 200 RTP PT=ITU-T G.711 PCMU, SSRC=0xFF26B81B, Seq=43613, Time=1751818640
#1377793619.743571 192.168.153.60 10002 192.168.154.206 10462 200 RTP PT=ITU-T G.711 PCMU, SSRC=0x776E7820, Seq=46574, Time=1802996691
#1377793619.763564 192.168.154.206 10462 192.168.153.60 10002 200 RTP PT=ITU-T G.711 PCMU, SSRC=0xFF26B81B, Seq=43614, Time=1751818800

                #
                # pkt variable is a list with the following entries:
                #        0               1          2         3         4  5  6 
                # 1341226810.949555 192.168.1.127 32878 193.108.80.124 53 73 DNS
    
                a1_1,a1_2,a1_3,a1_4 = pkt[1].split(".")
                a2_1,a2_2,a2_3,a2_4 = pkt[3].split(".")

                ports = [int(pkt[2]), int(pkt[4])]
                byts = [int(pkt[5]), 0]
                proto = pkt[6]
# Handle this:
#['1378148886.165730', '192.168.154.206', '10009', '192.168.245.2', '10001', '36', 'UDP', 'Source', 'port:', 'swdtp-sv', 'Destination', 'port:', 'scp-config[Malformed', 'Packet]']
                if proto != 'RTP':
                    print 'Proto not rtp: ', pkt
                    return (), [] 
            
                ssrc = pkt[10][7:15].strip(',')
                # Tshark removes leading zeros in ssrc.  
                # Prepend zeros if ssrc < 8 chars
                zeros_needed = 8 - len(ssrc)
                ssrc = '0'*zeros_needed + ssrc

                sequence = int(pkt[11][4:-1])
                sample_time = int(pkt[12][5:].strip(','))

            else:
                print 'Error parsing rtp packet: ', pkt 
                return (), [] 

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
            proto = doc['pr']
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
        print data
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
               'column.format:"""time","%t", "src","%s", "sport","%Cus:udp.srcport", "dst","%d", "dprt","%Cus:udp.dstport", "iplen","%Cus:ip.len", "protocol","%p","i","%i"""',
               '-f',
               '('+filtr+') or (vlan and '+filtr+')']

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

        proc = subprocess.Popen(param_list, bufsize=-1, stdout=subprocess.PIPE)
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
                   bufsize=-1, stdout=subprocess.PIPE)
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
            tcp.set_th_seq(data[pc.p_ack]) 
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
        bi = a_info[pc.i_bi]
        not_bi = abs(bi - 1)  # This IP did not cause the block
        if a_info[pc.i_cc] == None:
            cc, name, loc = trafcap.geoIpLookup(a_info[a_info[pc.i_bi]])
            a_info[pc.i_cc] = cc
            a_info[pc.i_loc] = loc 
            
        info_doc = {"ip1":trafcap.tupleToInt(a_info[bi]),
                    "p1":a_info[bi+2],
                    "ip2":trafcap.tupleToInt(a_info[not_bi]),
                    "p2":a_info[not_bi+2],
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
