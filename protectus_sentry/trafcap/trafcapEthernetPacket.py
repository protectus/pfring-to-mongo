# trafcapEthernetPacket.py
#
# Copyright (c) 2013 Protectus,LLC.  All Rights Reserved.
#
# Classes to help pull data off the wire and update mongo
import subprocess
import time
from protectus_sentry.trafcap import trafcap
from datetime import datetime
import traceback
import sys

class EthernetPacket(object):
    """
    Parent class for handling non-IP packets 
    """
    def __init__(self):
        return

    @classmethod
    def parse(pc, pkt):
        return

    # Legend for how packet data is stored in Info dictionaries
    #     src            dst
    # [addr, bytes], [addr, bytes]
    i_src=0; i_dst=1
    i_addr=0; i_bytes=1; i_pkt=2
    i_tb=2; i_te=3; i_pkts=4; i_ci=5; i_proto=6
    i_msg=7
    i_ldwt=8      # last_db_write_time
    i_csldw=9     # changed_since_last_db_write
    i_id=10       # mongo object id
    i_vl=11       # vlan id

    # Legend for how data is stored in the Session Bytes dictionary 
    # and the Capture Bytes dictionary 
    b_key=0; b_src=0; b_dst=1; b_msg=2; b_vl=3
    b_sb=1; b_se=2; 
    b_array=3; b_offset=0; b_bytes1=1; b_bytes2=2
    b_pkts=4
    b_ldwt=5      # last_db_write_time
    b_csldw=6     # changed_since_last_db_write

    #                   src,  dst, msg,  ??
    capture_dict_key = ('0', b'0', b'', None)

    # Legend for Group dictionary data structure:
    g_src=0; g_b1=1
    g_dst=2; g_b2=3
    g_msg=4
    g_tbm=5; g_tem=6
    g_ns=7; g_ne=8
    g_b=9; g_offset=0; g_1=1; g_2=2
    g_pkts=10
    g_proto=11
    g_id=12
    g_vl=13       # vlan id

    #@classmethod
    #def buildCriteriaDoc(pc, ci, si, a_info):
    #    session_criteria = {"s":a_info[ci][pc.i_addr],
    #                     "d":a_info[si][pc.i_addr],
    #                     "m":a_info[pc.i_msg],
    #                     "tbm":trafcap.secondsToMinute(a_info[pc.i_tb]),
    #                     "tem":{'$gte':trafcap.secondsToMinute(a_info[pc.i_tb])}}
    #    return session_criteria

    #@classmethod
    #def buildInfoDoc(pc, ci, si, a_info):
    #    return

    @classmethod
    def buildBytesDoc(pc, ci, si, a_info, a_bytes):
        session_bytes = {"s":a_info[ci][pc.i_addr].decode('ascii', 'ignore'),
                         "d":a_info[si][pc.i_addr].decode('ascii', 'ignore'),
                         "m":a_info[pc.i_msg].decode('utf-8', 'backslashreplace'),
                         "sb":a_bytes[pc.b_sb],
                         "se":a_bytes[pc.b_se],
                         "sbm":trafcap.secondsToMinute(a_bytes[pc.b_sb]),
                         "sem":trafcap.secondsToMinute(a_bytes[pc.b_se]),
                         #"pk":a_bytes[pc.b_pkts],
                         "pr":a_info[pc.i_proto].decode('ascii','ignore'),
                         "b":a_bytes[pc.b_array]}
        if a_info[pc.i_vl]: session_bytes['vl'] = a_info[pc.i_vl]
        return session_bytes

    @classmethod
    def buildInfoDoc(pc, ci, si, a_info):
        tbm=trafcap.secondsToMinute(a_info[pc.i_tb])
        tem=trafcap.secondsToMinute(a_info[pc.i_te])
        info_doc = {"s":a_info[ci][pc.i_addr].decode('ascii', 'ignore'),
                    "b1":a_info[ci][pc.i_bytes],
                    "d":a_info[si][pc.i_addr].decode('ascii', 'ignore'),
                    "b2":a_info[si][pc.i_bytes],
                    "m":a_info[pc.i_msg].decode('utf-8', 'backslashreplace'),
                    "bt":a_info[si][pc.i_bytes]+a_info[ci][pc.i_bytes],
                    "tbm":tbm,
                    "tem":tem,
                    "tb":a_info[pc.i_tb],
                    "te":a_info[pc.i_te],
                    "pk":a_info[pc.i_pkts],
                    "pk1":a_info[ci][pc.i_pkt],
                    "pk2":a_info[si][pc.i_pkt],
                    "pr":a_info[pc.i_proto].decode('ascii', 'ignore')}
        tdm = tem-tbm
        if tdm >= trafcap.lrs_min_duration: info_doc['tdm'] = tdm
        if a_info[pc.i_vl]: info_doc['vl'] = a_info[pc.i_vl]
        return info_doc

    @classmethod
    def buildGroupsDoc(pc, a_group):
        #group_criteria = {"s":a_group[pc.g_src],
        #                  "d":a_group[pc.g_dst],
        #                  "m":a_group[pc.g_msg],
        #                  "tbm":a_group[pc.g_tbm]}

        group_bytes = []
        for item in a_group[pc.g_b]:
            if item[pc.g_1] != 0 or item[pc.g_2] != 0:
                group_bytes.append(item)

        group_data = {"s":a_group[pc.g_src],
                      "b1":a_group[pc.g_b1],
                      "d":a_group[pc.g_dst],
                      "m":a_group[pc.g_msg],
                      "tbm":a_group[pc.g_tbm],
                      "tem":a_group[pc.g_tem],
                      "ns":a_group[pc.g_ns],
                      "ne":a_group[pc.g_ne],
                      #"pk":a_group[pc.g_pkts],
                      "pr":a_group[pc.g_proto],
                      "b":group_bytes}
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
        return (a_bytes['s'], a_bytes['d'], a_bytes['m'], a_bytes['vl'])

    @classmethod
    def getGroupKey(pc, a_bytes):
        return (a_bytes['s'], a_bytes['d'], a_bytes['m'], a_bytes['vl'])

    @classmethod
    def updateGroupsDict(pc, a_bytes, chunck_size, doc_win_start):
        tmp_array = []
        for a_index in range(0, 90, 1):
            tmp_array.append([a_index*chunck_size, 0, 0])

        # temporary hack
        #try:
        #    proto = a_bytes['pr']
        #except:
        #    proto = "_"

        a_group =[a_bytes['s'], 0,
                  a_bytes['d'], 0, a_bytes['m'], 
                  doc_win_start, trafcap.secondsToMinute(a_bytes['se']),
                  0, 0,
                  tmp_array, 0, a_bytes['pr'], None, a_bytes['vl']]
        return a_group

    @classmethod
    def updateInfoDict(pc, data, a_info):
        print('Override TrafcapEthernetPacket.updateInfoDict() in subclass')
        return

    @classmethod
    def buildInfoDictItem(pc, key, data):
        if key == pc.capture_dict_key:
            new_info = [[b'0',0,0], [b'0',0,0], 
                        float(data[pc.p_etime]), float(data[pc.p_etime]),
                        1, 0, b'', b'',
                        float(data[pc.p_etime]), True, None, None] 
        else:
            # Create new dictionary entry.
            # Zip creates tuples, convert to lists so they can be manipulated.
            new_info = [list(data[pc.p_src]), list(data[pc.p_dst]),
                        float(data[pc.p_etime]), float(data[pc.p_etime]),
                        1, 0, data[pc.p_proto], data[pc.p_msg], 
                        float(data[pc.p_etime]), True, None, data[pc.p_vl]]
        return new_info

    @classmethod
    def buildBytesDictItem(pc, key, data, curr_seq, src_bytes, dst_bytes):
        if key == pc.capture_dict_key:
            new_bytes = [list(key), curr_seq, curr_seq, 
                         [[0, src_bytes, dst_bytes]], 1, 
                         float(data[pc.p_etime]), True]

        else:
            new_bytes = [list(key), curr_seq, curr_seq,
                         [[0, src_bytes, dst_bytes]], 1, 
                         float(data[pc.p_etime]), True]
        return new_bytes
 

    @classmethod
    def findClient(pc, data, new_info):
        return

    @classmethod
    def findInOutBytes(pc, data):
        return data[pc.p_src][pc.p_bytes], data[pc.p_dst][pc.p_bytes]

    #@classmethod
    #def initializeCaptureInfo(pc):
    #    return

class OtherPacket(EthernetPacket):
    """
    For handling Other packets
    """
    def __init__(self):
        return


    # Legend for Other packet data list returned by the parse method:
    p_src=0; p_dst=1
    p_addr=0; p_bytes=1; p_pkts=2
    p_etime=2
    p_proto=3
    p_msg=4
    p_ci=5
    p_vl=6

    # TCP & UDP based protocols that should not appear in Other traffic
    leaked_protos_to_ignore = [ 
                                'BROWSER',
                                'CLDAP',
                                'DHCP',
                                'DNS',
                                'HTTP',
                                'ICMP',
                                'IPv4',
                                'LLMNR',
                                'MDNS',
                                'NBNS',
                                'NTP',
                                'OCSP',
                                'SSDP',
                                'SSL',
                                'SSLv2',
                                'TCP',
                                'TLSv1',
                                'TLSv1.2',
                                'UDP',
                                'QUIC',
                              ]

    @classmethod
    def parse(pc, pkt, doc):
        #
        # pkt variable is a list with the following entries:
        #        0                       1            2           3      
        #['1349186609.961972', '00:09:0f:50:aa:fc', '60', 'ff:ff:ff:ff:ff:ff', 
        #   4      5      6        7 ...........
        # 'ARP', 'Who', 'has', '192.168.2.2?', 'Tell', '192.168.1.1']

        # Adding vlan id - PFG - April 2014
        # No way of knowing how long the packet is so add vlan id after timestamp.
        # If field after timestamp contains dots or colons, then it is a src (mac or ip).
        # Otherwise, it must be a vlan id.
         
        if pkt and not doc:
            # If no vlan id present
            if b'.' in pkt[1] or b':' in pkt[1]:
                if pkt[4] in pc.leaked_protos_to_ignore: return (), []
                msg = pkt[5]
                for i in range(6, len(pkt), 1):
                    msg = msg + b" " + pkt[i]
                    # Ensure msg length does not exceed Mongo's Index Key Limit
                    if len(msg) > 512: 
                        msg = msg[:512] + b'...'
                        break
    
                data = [(pkt[1], int(pkt[2]), 1), (pkt[3], 0, 0), pkt[0], pkt[4], msg]
    
                vlan_id = None
                #        0      1       2      
                #       src  ,  dst  , msg
                key = (pkt[1], pkt[3], msg, vlan_id)

            # Vlan id is present - increment array indexes by one
            else:
                if pkt[5] in pc.leaked_protos_to_ignore: return (), []
                msg = pkt[6]
                for i in range(7, len(pkt), 1):
                    msg = msg + b" " + pkt[i]
                    # Ensure msg length does not exceed Mongo's Index Key Limit
                    if len(msg) > 512:
                        msg = msg[:512] + b'...'
                        break
    
                vlan_id = int(pkt[1]) if trafcap.ingest_vlan_id else 0
                data = [(pkt[2], int(pkt[3]), 1), (pkt[4], 0, 0), pkt[0], pkt[5], msg]
                #        0      1       2      
                #       src  ,  dst  , msg
                key = (pkt[2], pkt[4], msg, vlan_id)
    
        elif doc and not pkt:
            try:
                pkts = [doc['pk1'],doc['pk2']]
            except KeyError:
                # Arbitrary packet count if doc is in old format without pk1 and pk2
                pkts = [0, 0]

            data = [(doc['s'], doc['b1'], pkts[0]), (doc['d'], doc['b2'], pkts[1]), 
                     doc['tb'], doc['pr'], doc['m']]

            try:
                vlan_id = doc['vl']
            except KeyError:
                vlan_id = None

            key = (doc['s'], doc['d'], doc['m'], vlan_id)

        else:
            return (), []

        # Client index not used for Other traffic
        client_index = 0
        data.append(client_index)
        data.append(vlan_id)

        return key, data

    @classmethod
    def startSniffer(pc):
        # ether proto ox86dd == IPv6
        filter = 'not ip proto (1 or 6 or 17 or 41) and not ether proto 0x86dd ' +\
                  trafcap.cap_filter
        proc = subprocess.Popen(['/usr/bin/tshark', 
               '-i', trafcap.sniff_interface, 
               '-te', '-n', '-l',
               '-b', 'filesize:8192',
               '-b', 'files:5',
               '-w', '/run/trafcap_oth',
               '-P',
               '-o', 
               'column.format:"""time","%t", "vl","%Cus:vlan.id", "src","%s", "len","%Cus:frame.len", "dst","%d", "proto","%p", "i","%i"""',
               '-f',
               '('+filter+') or (vlan and '+filter+')'],
               bufsize=-1,
               stdout=subprocess.PIPE, stderr=sys.stdout.fileno())
        return proc
    
    @classmethod
    def updateInfoDict(pc, data, a_info):
        # Nothing to do for other packets 
        return

