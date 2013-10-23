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
import pymongo

def parseOptions():
    usage = "usage: %prog (-t|-u|-i|-o) [-mq]"
    parser = OptionParser(usage)
    parser.add_option("-m", "--mongo", dest="mongo",
                      action="store_true", default=False,
                      help="write to mongo")
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
    (options, args) = parser.parse_args()
    return options, args


options, args = parseOptions()     # Could combine this line with next line
trafcap.options = options
option_check_counter = 0
if options.tcp: option_check_counter += 1
if options.udp: option_check_counter += 1
if options.icmp: option_check_counter += 1
if options.other: option_check_counter += 1
if option_check_counter != 1:
    sys.exit("Must use one of -t, -u, -i, or -o specify a protocol.")

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

collection_name = collection_prefix + "sessionInfo"

def catchSignal1(signum, stack):
    #num_sessions = len(session1.groups_dict)
    #print "\n", num_sessions, " active sessions_group entries:"
    #for k in session1.groups_dict:
    #    print "   ",
    #    print "\033[31m", k, "\t", session1.groups_dict[k], "\033[0m"
    #if num_sessions >= 1: print num_sessions, \
    #                            " active session_group entries displayed."
    return

def catchSignal2(signum, stack):
    #num_sessions = len(session2.groups_dict)
    #print "\n", num_sessions, " active sessions_group entries:"
    #for k in session2.groups_dict:
    #    print "   ",
    #    print "\033[31m", k, "\t", session2.groups_dict[k], "\033[0m"
    #if num_sessions >= 1: print num_sessions, \
    #                            " active session_group entries displayed."
    return

def catchCntlC(signum, stack):
    sys.exit()

signal.signal(signal.SIGUSR1, catchSignal1)
signal.signal(signal.SIGUSR2, catchSignal2)
signal.signal(signal.SIGINT, catchCntlC)
signal.signal(signal.SIGTERM, catchCntlC)

db = trafcap.mongoSetup()

sess_info = db[collection_name].find()
               #   spec = {'sb':{'$lt':mbp},
               #           'se':{'$gte':mbp - trafcap.session_expire_timeout}},
               #  sort = [('sb',pymongo.ASCENDING)])

for a_info in sess_info:
    #print a_info
    #session_key = pc.getSessionKey(a_bytes)
    #session_history[session_key] = [a_bytes['sb'], a_bytes['se'], False, False]
    try:
        bytes_total = a_info['bt']

    except KeyError:
        print "Updating: ", a_info['_id']

        bytes_total = a_info['b1'] + a_info['b2']
        criteria = {'_id':a_info['_id']}
        field = {'$set':{'bt':bytes_total}}

        db[collection_name].update(criteria, field)

        # for testing
        #new_sess_info = db[collection_name].find(criteria)
        #for new_a_info in new_sess_info:
        #    print "Updated: ", new_a_info
        #sys.exit()

sys.exit()
