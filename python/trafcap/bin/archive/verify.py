#!/usr/bin/python

import sys, time, os, signal
from select import select
import socket
import traceback
from datetime import datetime
import subprocess
from optparse import OptionParser
import math
import ConfigParser
import trafcap
from trafcapIpPacket import *
from trafcapEthernetPacket import *
from trafcapContainer import *

#pymongo bindings
sys.path.append('/opt/sentry/trafcap/lib')
import pymongo

def parseOptions():
    usage = "usage: %prog (-t|-u|-i|-o) (-s|-c) [-bgmq]"
    parser = OptionParser(usage)
    parser.add_option("-b", "--bytes", dest="bytes",
                      action="store_true", default=False,
                      help="bytes debug info")
    parser.add_option("-g", "--groups", dest="groups",
                      action="store_true", default=False,
                      help="groups debug info")
    parser.add_option("-q", "--quiet", dest="quiet",
                      action="store_true", default=False,
                      help="don't print status to stdout")
    parser.add_option("-t", "--tcp", dest="tcp",
                      action="store_true", default=False,
                      help="process tcp session groups")
    parser.add_option("-u", "--udp", dest="udp",
                      action="store_true", default=False,
                      help="process udp session groups")
    parser.add_option("-i", "--icmp", dest="icmp",
                      action="store_true", default=False,
                      help="process icmp session groups")
    parser.add_option("-o", "--other", dest="other",
                      action="store_true", default=False,
                      help="process other session groups")
    parser.add_option("-s", "--session", dest="session",
                      action="store_true", default=False,
                      help="process session bytes")
    parser.add_option("-c", "--capture", dest="capture",
                      action="store_true", default=False,
                      help="process capture bytes")
    (options, args) = parser.parse_args()
    return options, args
 

options,args = parseOptions()     # Could combine this line with next line
trafcap.options = options      
option_check_counter = 0
if options.tcp: option_check_counter += 1
if options.udp: option_check_counter += 1
if options.icmp: option_check_counter += 1
if options.other: option_check_counter += 1
if option_check_counter != 1:
    sys.exit("Must use one of -t, -u, -i, or -o specify a protocol.")

if (not options.session and not options.capture) or \
   (options.session and options.capture):
    sys.exit("Must select either -s to group session bytes" +  
              " or -c to group capture bytes")

if options.tcp:
    packet_type = "TcpPacket"
    collection_prefix = "tcp_"
elif options.udp:
    packet_type = "UdpPacket"
    collection_prefix = "udp_"
elif options.icmp:
    packet_type = "IcmpPacket"
    collection_prefix = "icmp_"
elif options.other:
    packet_type = "OtherPacket"
    collection_prefix = "oth_"
else:
    sys.exit('Invalid protocol')

pc = eval(packet_type)

if options.session:
    info_collection_name = collection_prefix + "sessionInfo"
    bytes_collection_name = collection_prefix + "sessionBytes"
    groups1_collection_name = collection_prefix + "sessionGroups"
    groups2_collection_name = collection_prefix + "sessionGroups2"
elif options.capture:
    info_collection_name = collection_prefix + "captureInfo"
    bytes_collection_name = collection_prefix + "captureBytes"
    groups1_collection_name = collection_prefix + "captureGroups"
    groups2_collection_name = collection_prefix + "captureGroups2"
else:
    sys.exit('Invalid command line options')

if len(args) == 3:
    info_criteria = {"ip1":trafcap.stringToInt(args[0]),
                     "ip2":trafcap.stringToInt(args[1]),
                     "p2":int(args[2])}
    groups_criteria = info_criteria
elif len(args) == 4:
    info_criteria = {"ip1":trafcap.stringToInt(args[0]),
                     "ip2":trafcap.stringToInt(args[1]),
                     "p2":int(args[2]),
                     "tb":{'$gte':int(args[3])}}
    groups_criteria = {"ip1":trafcap.stringToInt(args[0]),
                       "ip2":trafcap.stringToInt(args[1]),
                       "p2":int(args[2]),
                       "tbm":{'$gte':int(trafcap.secondsToMinute(float(args[3])))}}


db = trafcap.mongoSetup()

info_cursor = db[info_collection_name].find(spec = info_criteria,
                                            sort = [('tb',pymongo.ASCENDING)])

#print info_criteria
#print info_cursor.count()
#print groups_criteria
print ""
info_tb_total=9999999999; info_te_total=0

info_b1_total = 0; info_b2_total = 0
info_pkt_total = 0

bytes_b1_total = 0; bytes_b2_total = 0
bytes_pkt_total = 0
bytes_sb_total = 9999999999; bytes_se_total = 0

for i in info_cursor:

    print i['tb'], "->", i['te'], "   ", \
        trafcap.intToString(i['ip1']),":",i['p1'],"(",i['b1'],")","=>", \
        trafcap.intToString(i['ip2']),":",i['p2'],"(",i['b2'],") ", i['pk']

    if i['te'] > info_te_total: info_te_total = i['te']
    if i['tb'] < info_tb_total: info_tb_total = i['tb']
    info_b1_total += i['b1']
    info_b2_total += i['b2']
    info_pkt_total += i['pk']

    # Accumulate bytes
    bytes_b1_docs = 0; bytes_b2_docs = 0
    bytes_sb=9999999999; bytes_se=0
    bytes_criteria = {"ip1":i['ip1'],
                      "p1":i['p1'],
                      "ip2":i['ip2'],
                      "p2":i['p2'],
                      "sb":{'$gte':int(i['tb'])},
                      "se":{'$lte':int(i['te'])}}

    bytes_cursor = db[bytes_collection_name].find(spec = bytes_criteria, 
                                             sort = [('sb',pymongo.ASCENDING)])
    for b in bytes_cursor:
        if options.bytes: print b
        if b['se'] > bytes_se: bytes_se = b['se']
        if b['sb'] < bytes_sb: bytes_sb = b['sb']

        if b['se'] > bytes_se_total: bytes_se_total = b['se']
        if b['sb'] < bytes_sb_total: bytes_sb_total = b['sb']
        
        bb1_doc = 0; bb2_doc = 0

        for item in b['b']:
            time = b['sb'] + item[0]
            bytes_b1_total += item[1]
            bytes_b2_total += item[2]
            bytes_b1_docs += item[1]
            bytes_b2_docs += item[2]
            bb1_doc += item[1]
            bb2_doc += item[2]

        print " b ", b['sb'], "->", b['se'], "   ", \
            trafcap.intToString(b['ip1']),":",b['p1'],"(",bb1_doc,")","=>", \
            trafcap.intToString(b['ip2']),":",b['p2'],"(",bb2_doc,")", \
            b['pk']

    bytes_pkt_total += b['pk']

    print "   ", bytes_sb, "->", bytes_se, "   ", "(",bytes_b1_docs,")", "(",bytes_b2_docs,")"
    print ""


# Accumulate groups1
grp1_tbm=9999999999; grp1_tem=0
grp1_b1_total = 0; grp1_b2_total = 0

groups1_cursor = db[groups1_collection_name].find(spec = groups_criteria,
                                        sort = [('tbm',pymongo.ASCENDING)])
for g in groups1_cursor:
    if options.groups: print g
    if g['tem'] > grp1_tem: grp1_tem = g['tem']
    if g['tbm'] < grp1_tbm: grp1_tbm = g['tbm']
        
    grp1_b1_doc = 0; grp1_b2_doc = 0

    for item in g['b']:
        time = g['tbm'] + item[0]

        grp1_b1_total += item[1]
        grp1_b2_total += item[2]
        grp1_b1_doc += item[1]
        grp1_b2_doc += item[2]

    print " g1", g['tbm'], "->", g['tem'], "   ", \
        trafcap.intToString(g['ip1']),"(",grp1_b1_doc,")","=>", \
        trafcap.intToString(g['ip2']),":",g['p2'],"(",grp1_b2_doc,")", \
        "  ne=",g['ne'], "  ns=",g['ns']

print "   ", grp1_tbm, "->", grp1_tem, "   ", "(",grp1_b1_total,")", "(",grp1_b2_total,")"
print ""

# Accumulate groups2
grp2_tbm=9999999999; grp2_tem=0
grp2_b1_total = 0; grp2_b2_total = 0

groups2_cursor = db[groups2_collection_name].find(spec = groups_criteria,
                                        sort = [('tbm',pymongo.ASCENDING)])
for g in groups2_cursor:
    if options.groups: print g
    if g['tem'] > grp2_tem: grp2_tem = g['tem']
    if g['tbm'] < grp2_tbm: grp2_tbm = g['tbm']
        
    grp2_b1_doc = 0; grp2_b2_doc = 0

    for item in g['b']:
        time = g['tbm'] + item[0]
        
        grp2_b1_total += item[1]
        grp2_b2_total += item[2]
        grp2_b1_doc += item[1]
        grp2_b2_doc += item[2]

    print " g2", g['tbm'], "->", g['tem'], "   ", \
        trafcap.intToString(g['ip1']),"(",grp2_b1_doc,")","=>", \
        trafcap.intToString(g['ip2']),":",g['p2'],"(",grp2_b2_doc,")", \
        "  ne=",g['ne'], "  ns=",g['ns']

print "   ", grp2_tbm, "->", grp2_tem, "   ", "(",grp2_b1_total,")", "(",grp2_b2_total,")"
print ""

 
print " I ", info_tb_total, "->", info_te_total, "   ", "(",info_b1_total,")", "(",info_b2_total,")", info_pkt_total
print " B ", bytes_sb_total, "->", bytes_se_total, "   ", "(",bytes_b1_total,")", "(",bytes_b2_total,")", bytes_pkt_total
print " G1", grp1_tbm, "->", grp1_tem, "   ", "(",grp1_b1_total,")", "(",grp1_b2_total,")"
print " G2", grp2_tbm, "->", grp2_tem, "   ", "(",grp2_b1_total,")", "(",grp2_b2_total,")"

sys.exit()
