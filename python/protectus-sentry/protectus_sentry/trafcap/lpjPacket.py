# lpjPacket.py
#
# Copyright (c) 2013 Protectus,LLC.  All Rights Reserved.
#
# Classes to aquire latetency, packet loss, jitter data 
import subprocess
import time
import trafcap
from datetime import datetime
import traceback
import re
import lpj
import copy

#global targets
class IpLpjPacket(object):
    """
    Parent class 
    """
    def __init__(self):
        return

    @classmethod
    def parse(pc, pkt):
        return

    #@classmethod
    #def buildCriteriaDoc(pc, ci, si, a_info):
    #    c_id = a_info[pc.i_c_id] 
    #    session_criteria = {"c_id":c_id,
    #                        "tbm":trafcap.secondsToMinute(a_info[pc.i_tb])}
    #    return session_criteria

    @classmethod
    def getId(pc, pkt):
        # addr is a tuple in the info dictionary, convert to string
        a = pkt[pc.p_ip2][pc.p_addr]
        addr_str = str(a[0])+"."+str(a[1])+"."+str(a[2])+"."+str(a[3])
        proto = pkt[pc.p_proto]

        for target_obj in lpj.targets:
            target_info = target_obj.target_info
            if (addr_str == target_info[lpj.t_ip] or \
                addr_str == target_info[lpj.t_prev_ip]) and \
               proto == target_info[lpj.t_protocol]:
                if proto == 'tcp':
                    if int(pkt[pc.p_ip2][pc.p_port]) == target_info[lpj.t_port]:
                        c_id = target_info[lpj.t_c_id] 
                elif proto == 'icmp':
                    if pkt[pc.p_ip1][pc.p_type][0] == target_info[lpj.t_type]:
                        c_id = target_info[lpj.t_c_id] 
                else:   
                    print "Invalid protocol when building criteria..."
                    return None
        return c_id

    @classmethod
    def buildDataDoc(pc, ci, si, a_data):
        return

    @staticmethod
    def startSniffer():
        proc1 = subprocess.Popen(['/usr/sbin/tcpdump',
               '-i', trafcap.network_interface,
               '-tt', '-n', '-l',
               '-f',
               '((icmp or (tcp[tcpflags] & (tcp-syn) != 0)) or (vlan and (icmp or (tcp[tcpflags] & (tcp-syn) != 0))))'],
               bufsize=-1, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return proc1

    @classmethod
    def updateInfoDict(pc, data, a_info):
        return

class TcpLpjPacket(IpLpjPacket):
    def __init__(self):
        return

    # Legend for how data is stored in the Data dictionary 
    #d_key=0; d_addr1=0; d_port1=1; d_addr2=2; d_port2=3
    d_key=0; d_addr1=0; d_addr2=1; d_port2=2
    d_sb=1; d_se=2 
    d_rtl_list=3; d_offset=0; d_rtl=1 
    d_pl_list=4; d_offset=0; d_pl=1 
    d_lmin=5; d_lmax=6; d_req=7; d_rply=8
    d_proto=9
    d_ldwt=10      # last_db_write_time
    d_csldw=11     # changed_since_last_db_write
    d_c_id=12
    d_id=13
    d_curr_ptr=14

    # Legend for TCP packet data list returned by the parse method:
    p_ip1=0; p_ip2=1
    p_addr=0; p_port=1; p_flags=2
    p_etime=2
    p_seq=3
    p_proto=4
    p_ci=5

    # Legend for how TCP packet data is stored in the Session Info 
    i_ip1=0; i_ip2=1
    i_addr=0; i_port=1; i_flags=2
    i_tb=2; i_te=3; i_ci=4; i_proto=5
    i_lmin=6; i_lmax=7; i_req=8; i_rply=9; 
    i_ldwt=10      # last_db_write_time
    i_csldw=11     # changed_since_last_db_write
    i_c_id=12
    i_id=13

    # Legend for Group dictionary data structure:
    g_proto=0     # must be first element!
    g_ip1=1
    g_ip2=2; g_p2=3
    g_tbm=4; g_tem=5
    g_rtl_list=6; g_offset=0; g_rtl=1; g_count=2
    g_pl_list=7; g_offset=0; g_pl=1; g_count=2
    g_lmin=8; g_lmax=9; g_req=10; g_rply=11
    g_c_id=12
    g_eol=13
    g_id=14

    requests = {}

    @classmethod
    def parse(pc, pkt):
        # ['1354757081.121964', 'IP', '192.168.1.86.37006', '>', 
        # '206.180.172.130.80:', 'Flags', '[S],', 'seq', '351505191,', 'win', 
        # '14600,', 'options', '[mss', '1460,sackOK,TS', 'val', '26655221', 
        # 'ecr', '0,nop,wscale', '6],', 'length', '0']

        # ['1354757081.148308', 'IP', '206.180.172.130.80', '>', 
        # '192.168.1.86.37006:', 'Flags', '[S.],', 'seq', '3695356776,', 'ack',
        # '351505192,', 'win', '5792,', 'options', '[mss', '1460,sackOK,TS', 
        # 'val', '2058673365', 'ecr', '26655221,nop,wscale','3],','length','0']

        try:
            a1_1,a1_2,a1_3,a1_4,src_port = pkt[2].split(".")
            a2_1,a2_2,a2_3,a2_4,dst_port = pkt[4].split(".")
            dst_port = dst_port.strip(':')

            src_ip = (int(a1_1), int(a1_2), int(a1_3), int(a1_4))
            dst_ip = (int(a2_1), int(a2_2), int(a2_3), int(a2_4))

            etime = float(pkt[0])
            flags = pkt[6].strip(",")
            proto = 'tcp'

            if flags == '[S.]':
                ack = int(pkt[10].strip(','))
                seq = ack - 1
                client_index = 1
                request_key = (dst_ip, src_ip, src_port, seq)
                session_key = (dst_ip, src_ip, src_port)
            elif flags == '[S]':
                seq = int(pkt[8].strip(','))
                client_index = 0
                request_key = (src_ip, dst_ip, dst_port, seq)
                session_key = (src_ip, dst_ip, dst_port)

            else:
                raise Exception("Syn or syn-ack not found in TCP traffic." )

        except Exception, e:
            print(e.__str__())
            raise Exception("Unable to parse TCP traffic." )

        data = [(src_ip, src_port, flags), (dst_ip, dst_port, '[]'), 
                 etime, seq, proto, client_index]
        
        return request_key, session_key, data

    @classmethod
    def buildInfoDoc(pc, ci, si, a_info):
        c_id = a_info[pc.i_c_id] 
        if c_id:
            info_doc = {"ip1":trafcap.tupleToInt(a_info[ci][pc.i_addr]),
                        "f1":a_info[ci][pc.i_flags],
                        "ip2":trafcap.tupleToInt(a_info[si][pc.i_addr]),
                        "p2":a_info[si][pc.i_port],
                        "f2":a_info[si][pc.i_flags],
                        "tbm":trafcap.secondsToMinute(a_info[pc.i_tb]),
                        "tem":trafcap.secondsToMinute(a_info[pc.i_te]),
                        "tb":a_info[pc.i_tb],
                        "te":a_info[pc.i_te],
                        "pr":a_info[pc.i_proto],
                        "lmin":a_info[pc.i_lmin],
                        "lmax":a_info[pc.i_lmax],
                        "req":a_info[pc.i_req],
                        "rply":a_info[pc.i_rply],
                        "c_id":c_id}
            return info_doc
        return None 

    @classmethod
    def buildDataDoc(pc, ci, si, a_data):
        c_id = a_data[pc.i_c_id] 
        if c_id:
            rtl_list = list(a_data[pc.d_rtl_list])
            rtl_list[:] = (val for val in rtl_list if val[1] != 0)
            pl_list = list(a_data[pc.d_pl_list])
            pl_list[:] = (val for val in pl_list if val[1] != 0)
            session_data = {"ip1":trafcap.tupleToInt(a_data[pc.d_key][pc.d_addr1]),
                        "ip2":trafcap.tupleToInt(a_data[pc.d_key][pc.d_addr2]),
                        "p2":a_data[pc.d_key][pc.d_port2],
                        "sb":a_data[pc.d_sb],
                        "se":a_data[pc.d_se],
                        "sbm":trafcap.secondsToMinute(a_data[pc.d_sb]),
                        "sem":trafcap.secondsToMinute(a_data[pc.d_se]),
                        "rtl":rtl_list,
                        "pl":pl_list,
                        "pr":a_data[pc.d_proto],
                        "lmin":a_data[pc.d_lmin],
                        "lmax":a_data[pc.d_lmax],
                        "req":a_data[pc.d_req],
                        "rply":a_data[pc.d_rply],
                        "c_id":c_id}
            return session_data
        return None 

    @classmethod
    def buildGroupsDoc(pc, a_group, eol):
        #group_criteria = {"c_id":a_group[pc.g_c_id],
        #                  "tbm":a_group[pc.g_tbm]}

        rtl = []
        for item in a_group[pc.g_rtl_list]:
            if item[pc.g_rtl] != 0:
                rtl.append([item[0], item[pc.g_rtl]])

        pl = []
        for item in a_group[pc.g_pl_list]:
            if item[pc.g_pl] != 0:
                pl.append([item[0], item[pc.g_pl]])

        group_data = {"ip1":a_group[pc.g_ip1],
                      "ip2":a_group[pc.g_ip2],
                      "p2":a_group[pc.g_p2],
                      "tbm":a_group[pc.g_tbm],
                      "tem":a_group[pc.g_tem],
                      "rtl":rtl,
                      "pl":pl,
                      "lmin":a_group[pc.g_lmin],
                      "lmax":a_group[pc.g_lmax],
                      "req":a_group[pc.g_req],
                      "rply":a_group[pc.g_rply],
                      "pr":a_group[pc.g_proto],
                      "c_id":a_group[pc.g_c_id]}

        return group_data

    @classmethod
    def getSessionKey(pc, a_data):
        #return (a_data['ip1'], a_data['ip2'], a_data['p2'])
        return (a_data['c_id'])

    @classmethod
    def getGroupKey(pc, a_data):
        #return (a_data['ip1'], a_data['ip2'], a_data['p2'])
        return (a_data['c_id'])

    @classmethod
    def updateGroupsDict(pc, a_data, chunck_size, doc_win_start):
        tmp_array = []
        for a_index in range(0, 90, 1):
            tmp_array.append([a_index*chunck_size, 0, 0])

        a_group =[a_data['pr'], 
                  a_data['ip1'], a_data['ip2'], a_data['p2'],
                  doc_win_start, 0,
                  tmp_array, copy.deepcopy(tmp_array), 
                  a_data['lmin'], a_data['lmax'], 0, 0,
                  a_data['c_id'],0, None]
        return a_group

class MtrPacketError(Exception):
   def __init__(self, arg):
         self.args = arg

class IcmpLpjPacket(IpLpjPacket):
    def __init__(self):
        return

    #capture_dict_key = ((0,0,0,0), (0,0,0,0),())

    # Class attribute
    #requests = {}

    # Legend for ICMP packet data list returned by the parse method:
    p_ip1=0; p_ip2=1
    p_addr=0; p_type=1
    p_etime=2
    p_id=3
    p_seq=4
    p_proto=5
    p_ci=6

    # Legend for how packet data is stored in the Session Dict 
    i_ip1=0; i_ip2=1
    i_addr=0; i_type=1
    i_tb=2; i_te=3; i_ci=4; i_proto=5
    i_lmin=6; i_lmax=7; i_req=8; i_rply=9; 
    i_ldwt=10      # last_db_write_time
    i_csldw=11     # changed_since_last_db_write
    i_c_id=12
    i_id=13

    # Legend for how data is stored in the Data dictionary 
    d_key=0; d_addr1=0; d_addr2=1; d_type=2; d_iden=3
    d_sb=1; d_se=2; 
    d_rtl_list=3; d_offset=0; d_rtl=1
    d_pl_list=4; d_offset=0; d_pl=1
    d_lmin=5; d_lmax=6; d_req=7; d_rply=8 
    d_proto=9
    d_ldwt=10     # last_db_write_time
    d_csldw=11     # changed_since_last_db_write
    d_c_id=12
    d_id=13
    d_curr_ptr=14

    # Legend for Group dictionary data structure:
    #   0  1   2   3    4   5   6  7  8  9 
    #                                       +------- document window ------+
    #  ip1 ty1 b1 ip2   b2 tbm tem ns ne b[[offset, b1, b2], [...], .....]
    #                                        +--- chunck----+
    # Note that type2 (t2) is not stored in TrafcapContainer dictionary
    g_proto=0     # must be first element!
    g_ip1=1; g_ty1=2
    g_ip2=3
    g_tbm=4; g_tem=5
    g_rtl_list=6; g_offset=0; g_rtl=1; g_count=2
    g_pl_list=7; g_offset=0; g_pl=1; g_count=2
    g_lmin=8; g_lmax=9; g_req=10; g_rply=11
    g_c_id=12
    g_eol=13     # end-of-list marker, write to db up to this list offset
    g_id=14


    @classmethod
    def parse(pc, pkt):

        # ['1354654680.292987', 'IP', '192.168.1.86', '>', '74.125.227.105:',
        # 'ICMP', 'echo', 'request,', 'id', '22315,', 'seq', '298,', 'length',
        # '64']

        # ['1354654680.343814', 'IP', '74.125.227.105', '>', '192.168.1.86:',
        # 'ICMP', 'echo', 'reply,', 'id', '22315,', 'seq', '298,', 'length',
        # '64']

        try:
            if pkt[6] != 'echo':
                raise Exception("Echo not found in ICMP traffic.")
    
            length = pkt[13]
            # Exclude shorter packets from mtr (My Traceroute) tool
            # which are 44 bytes long by default
            if int(length) < 64:
                raise MtrPacketError("Dropping mtr packet")

            a1_1,a1_2,a1_3,a1_4 = pkt[2].split(".")
            a2_1,a2_2,a2_3,a2_4 = pkt[4].strip(":").split(".")
    
            # Represent IP addresses as tuples instead of strings
            src_ip = (int(a1_1), int(a1_2), int(a1_3), int(a1_4))
            dst_ip = (int(a2_1), int(a2_2), int(a2_3), int(a2_4))
    
            etime = float(pkt[0])
            iden = pkt[9].strip(',') 
            seq = pkt[11].strip(',')
            proto = 'icmp'

            if pkt[7] == 'reply,':
                i_type = [0]       # Echo reply
                client_index = 1
                request_key = (dst_ip, src_ip, tuple([8]), iden, seq)
                session_key = (dst_ip, src_ip, tuple([8]), iden)
            elif pkt[7] == 'request,':
                i_type = [8]       # Echo request
                client_index = 0
                request_key = (src_ip, dst_ip, tuple(i_type), iden, seq)
                session_key = (src_ip, dst_ip, tuple(i_type), iden)
            else:
                raise Exception("Request / reply not found in ICMP traffic.")
    
        except MtrPacketError, e:
            raise MtrPacketError("Dropping mtr packet")
        except Exception, e:
            raise Exception("Unable to parse ICMP traffic.")
            
        data = [(src_ip, i_type), (dst_ip, []), etime, iden, seq, proto,
                client_index]

        return request_key, session_key, data

    @classmethod
    def buildInfoDoc(pc, ci, si, a_info):
        c_id = a_info[pc.i_c_id] 
        if c_id:
            info_doc = {"ip1":trafcap.tupleToInt(a_info[ci][pc.i_addr]),
                        "ip2":trafcap.tupleToInt(a_info[si][pc.i_addr]),
                        "type":a_info[ci][pc.i_type][0],
                        "tb":a_info[pc.i_tb],
                        "te":a_info[pc.i_te],
                        "tbm":trafcap.secondsToMinute(a_info[pc.i_tb]),
                        "tem":trafcap.secondsToMinute(a_info[pc.i_te]),
                        "lmin":a_info[pc.i_lmin], 
                        "lmax":a_info[pc.i_lmax], 
                        "req":a_info[pc.i_req], 
                        "rply":a_info[pc.i_rply], 
                        "pr":a_info[pc.i_proto], 
                        "c_id":c_id}
            return info_doc
        return None 

    @classmethod
    def buildDataDoc(pc, ci, si, a_data):
        c_id = a_data[pc.i_c_id] 
        if c_id:
            rtl_list = list(a_data[pc.d_rtl_list])
            rtl_list[:] = (val for val in rtl_list if val[1] != 0)
            pl_list = list(a_data[pc.d_pl_list])
            pl_list[:] = (val for val in pl_list if val[1] != 0)
            session_data = {"ip1":trafcap.tupleToInt(a_data[pc.d_key][pc.d_addr1]),
                         "ip2":trafcap.tupleToInt(a_data[pc.d_key][pc.d_addr2]),
                         "type":a_data[pc.d_key][pc.d_type][0],
                         "sb":a_data[pc.d_sb],
                         "se":a_data[pc.d_se],
                         "sbm":trafcap.secondsToMinute(a_data[pc.d_sb]),
                         "sem":trafcap.secondsToMinute(a_data[pc.d_se]),
                         "rtl":rtl_list,
                         "pl":pl_list,
                         "lmin":a_data[pc.d_lmin],
                         "lmax":a_data[pc.d_lmax],
                         "req":a_data[pc.d_req],
                         "rply":a_data[pc.d_rply],
                         "pr":a_data[pc.d_proto],
                         "c_id":c_id}
            return session_data
        return None

    @classmethod
    def buildGroupsDoc(pc, a_group, eol):
        #group_criteria = {"c_id":a_group[pc.g_c_id],
        #                  "tbm":a_group[pc.g_tbm]}

        rtl = []
        for item in a_group[pc.g_rtl_list]:
            if item[pc.g_rtl] != 0:
                rtl.append([item[0], item[pc.g_rtl]])

        pl = []
        for item in a_group[pc.g_pl_list]:
            if item[pc.g_pl] != 0:
                pl.append([item[0], item[pc.g_pl]])

        group_data = {"ip1":a_group[pc.g_ip1],
                      "ty1":a_group[pc.g_ty1],
                      "ip2":a_group[pc.g_ip2],
                      "tbm":a_group[pc.g_tbm],
                      "tem":a_group[pc.g_tem],
                      "rtl":rtl,
                      "pl":pl,
                      "lmin":a_group[pc.g_lmin],
                      "lmax":a_group[pc.g_lmax],
                      "req":a_group[pc.g_req],
                      "rply":a_group[pc.g_rply],
                      "pr":a_group[pc.g_proto],
                      "c_id":a_group[pc.g_c_id]}
        return group_data

    @classmethod
    def getSessionKey(pc, a_data):
        #return (a_data['ip1'], a_data['type'], a_data['ip2'])
        return (a_data['c_id'])

    @classmethod
    def getGroupKey(pc, a_data):
        #return (a_data['ip1'], a_data['type'], a_data['ip2'])
        return (a_data['c_id'])

    @classmethod
    def updateGroupsDict(pc, a_data, chunck_size, doc_win_start):
        tmp_array = []
        for a_index in range(0, 90, 1):
            tmp_array.append([a_index*chunck_size, 0, 0])

        a_group =[a_data['pr'], 
                  a_data['ip1'], a_data['type'], a_data['ip2'],
                  doc_win_start, 0,
                  tmp_array, copy.deepcopy(tmp_array), 
                  a_data['lmin'], a_data['lmax'], 0, 0,
                  a_data['c_id'], 0, None]
        return a_group

