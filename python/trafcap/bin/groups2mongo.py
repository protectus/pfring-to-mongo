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

# doc_win_start                   mbp
#   |                            |    |
#   |............................|....|.....|


def parseOptions():
    usage = "usage: %prog (-t|-u|-i|-o) (-s|-c) [-bgmq]"
    parser = OptionParser(usage)
    parser.add_option("-b", "--bytes", dest="bytes",
                      action="store_true", default=False,
                      help="bytes debug info")
    parser.add_option("-g", "--groups", dest="groups",
                      action="store_true", default=False,
                      help="groups debug info")
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
    parser.add_option("-s", "--session", dest="session",
                      action="store_true", default=False,
                      help="process session bytes")
    parser.add_option("-c", "--capture", dest="capture",
                      action="store_true", default=False,
                      help="process capture bytes")
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
    
# Define input colleciton field names for time start and time end
chunck_size1 = 10     # seconds
chunck_len1 = chunck_size1 - 1  
window_size1 = 15     # minutes

chunck_size2 = 120    # seconds
chunck_len2 = chunck_size2 - 1
window_size2 = 180    # minutes

if options.session:
    bytes_collection_name = collection_prefix + "sessionBytes"
    groups1_collection_name = collection_prefix + "sessionGroups"
    groups2_collection_name = collection_prefix + "sessionGroups2"
elif options.capture:
    bytes_collection_name = collection_prefix + "captureBytes"
    groups1_collection_name = collection_prefix + "captureGroups"
    groups2_collection_name = collection_prefix + "captureGroups2"
else:
    sys.exit('Invalid command line options')

# Holds the group data
session1 = TrafcapGroupContainer(pc,
                                 bytes_collection_name,
                                 groups1_collection_name)

# Holds the groups2 data
session2 = TrafcapGroupContainer(pc,
                                 bytes_collection_name,
                                 groups2_collection_name)

def catchSignal1(signum, stack):
    num_sessions = len(session1.groups_dict)
    print "\n", num_sessions, " active sessions_group entries:"
    for k in session1.groups_dict:
        print "   ",
        print "\033[31m", k, "\t", session1.groups_dict[k], "\033[0m"
    if num_sessions >= 1: print num_sessions, \
                                " active session_group entries displayed."

def catchSignal2(signum, stack):
    num_sessions = len(session2.groups_dict)
    print "\n", num_sessions, " active sessions_group entries:"
    for k in session2.groups_dict:
        print "   ",
        print "\033[31m", k, "\t", session2.groups_dict[k], "\033[0m"
    if num_sessions >= 1: print num_sessions, \
                                " active session_group entries displayed."

def catchCntlC(signum, stack):
    sys.exit()

signal.signal(signal.SIGUSR1, catchSignal1)
signal.signal(signal.SIGUSR2, catchSignal2)
signal.signal(signal.SIGINT, catchCntlC)
signal.signal(signal.SIGTERM, catchCntlC)

def findStartingPoint(session):
    sg = session.db[session.groups_collection].find_one()
    if not sg:
        if not options.quiet:
            print "Session Groups collection not found..."
        # sessionGroups collection does not exist. Check for bytes collection 
        bytes_collection_exists = False
        sb_cursor = None
        while not bytes_collection_exists:
            sb_cursor = session.db[session.bytes_collection].find( \
                                   spec = {}, fields = {'sb':1}, 
                                   sort = [('_id',1)], limit = 1)

            if sb_cursor.count() > 0:
                bytes_collection_exists = True 
            else:
                print "Session bytes collection not found. Sleeping..."
                time.sleep(2) 
    
        oldest_sessionBytes_sb = sb_cursor[0]['sb']
        result = oldest_sessionBytes_sb
    else:
        if not options.quiet:
            print "Session groups collection found..."
        # sessionGroups exists, return most recent tbm in sessionGroups
        sg_cursor = session.db[session.groups_collection].find( \
                               spec = {}, fields = {'tbm':1}, 
                               sort = [('tem',-1)], limit = 1)
        result = sg_cursor[0]['tbm']
    return result

# Find the starting point for consolidating sessionInfo and sessionBytes
# into sessionGroups
#if not options.quiet:
print "Searching for starting time..."

newest_group1_time = findStartingPoint(session1)
newest_group2_time = findStartingPoint(session2)
# Used to decide between inserting (faster) and updating (needed at first) db
insert_to_group1 = False
insert_to_group2 = False

# Find beginning of session document window 
doc_win_start1 = trafcap.findWindowBoundary(newest_group1_time, window_size1)
doc_win_start2 = trafcap.findWindowBoundary(newest_group2_time, window_size2)
#if not options.quiet:
print "Most recent groups 1 doc window start time = ", doc_win_start1
print "Most recent groups 2 doc window start time = ", doc_win_start2

mbp = min(doc_win_start1, doc_win_start2)
doc_win_start1 = mbp
doc_win_start2 = mbp
max_doc_duration = 3600 * 24 * 5       # 5 days

#if not options.quiet:
print "Minute being processed = ", mbp 

# Create dictionary with session byte history - used later to determine
# if a session is new or existing.  Find all sessions from:
#   (mbp - session_expire_timeout) ===> mbp
#
# Counted flags indicate if a session has been counted in the corresponding
# group's ns and ne fields for the current doc_window
#
# [session_key] ==> [ sb, se, counted1, counted2 ]
h_sb=0; h_se=1; h_counted1=2; h_counted2=3

if not options.quiet:
    print "Building session_bytes history..."
session_history = {}

sess_bytes = session1.db[session1.bytes_collection].find( \
                  spec = {'sbm':{'$lt':mbp},
                          'sem':{'$gte':mbp - trafcap.session_expire_timeout}}) 
                 # Sort not needed
                 #sort = [('sb',pymongo.ASCENDING)])

for a_bytes in sess_bytes:
    session_key = pc.getSessionKey(a_bytes)
    session_history[session_key] = [a_bytes['sb'], a_bytes['se'], False, False] 

# Remove docs from group collecitons that have tbm >= mbp
# This prevents duplication of data
session1.db[session1.groups_collection].remove(spec_or_id={'tbm':{'$gte':mbp}}) 
session2.db[session2.groups_collection].remove(spec_or_id={'tbm':{'$gte':mbp}}) 

#
# Begin main loop
#
while True:
    # Sleep if mbp is still being written to the input collection 
    most_recent_doc = session1.db[session1.bytes_collection].find( \
                                 spec = {}, 
                                 fields = {'se':1},
                                 #sort = [('$natural',-1)],
                                 sort = [('sem', pymongo.DESCENDING)],
                                 limit = 1)

    if mbp >= (trafcap.secondsToMinute(most_recent_doc[0]['se'] - 30) - 60):
        if not options.quiet:
            print ""
            print "\r\033[33m", "mbp: ", mbp, \
                  " is close to most_recent_doc: ", most_recent_doc[0]['se'], \
                  ",  sleeping.......", "\033[0m",
            sys.stdout.flush()
        time.sleep(60)
        continue

    # Find all docs in sessionBytes with tb <= mbp <= te
    if options.bytes:
        print "Querying sessionBytes for mbp = ", mbp

    a_spec = {'sbm':{'$lte':mbp+59,'$gt':mbp - max_doc_duration},'sem':{'$gte':mbp, '$lt':mbp + max_doc_duration}}
    a_sort = [('sb',pymongo.ASCENDING)]
    sess_bytes = session1.db[session1.bytes_collection].find( \
                             spec = a_spec)
                             # Sort not needed
                             #spec = a_spec, sort = a_sort)

    if options.bytes:
        print "Found ", sess_bytes.count(),  \
              " matching sessionBytes documents in mbp ", mbp

    # For the sess_bytes array element with data, 
    # add data to the session_group arrays
    for a_bytes in sess_bytes:
        # hack to weed-out bad data from early code
        try:
            # ty field no longer used
            junk = a_bytes['ty']
            continue
        except:
            pass

        # for debug
        #matched_ip = False
        #ip_qry = trafcap.stringToInt(args[0])
        #if options.bytes and \
        #  (ip_qry == a_bytes['ip1'] or ip_qry == a_bytes['ip2']):
        #    matched_ip = True
        #    print a_bytes 

        group_key = pc.getGroupKey(a_bytes)
        session_key = pc.getSessionKey(a_bytes) 

        session1.updateGroupsDict(group_key, a_bytes, chunck_size1, 
                                  doc_win_start1)

        session2.updateGroupsDict(group_key, a_bytes, chunck_size2, 
                                  doc_win_start2)

        # Determine ns and ne for each session and store resutls in group dicts 
        try:
            a_session = session_history[session_key]
            # If no exception from the line above, then session is in history
            # Count session as existing in the corresponging groups
            if a_session[h_counted1] == False:
                a_session[h_counted1] = True
                session1.groups_dict[group_key][pc.g_ne] += 1

            if a_session[h_counted2] == False:
                a_session[h_counted2] = True
                session2.groups_dict[group_key][pc.g_ne] += 1

            # Update session end time in the history
            a_session[h_se] = a_bytes['se'] 

        except:
            # Session is not in history, add it and count is as started 
            session_history[session_key] = [ a_bytes['sb'], a_bytes['se'], \
                                             True, True]
            session1.groups_dict[group_key][pc.g_ns] += 1
            session2.groups_dict[group_key][pc.g_ns] += 1
             
        # Pull bytes data from sessionBytes and sum into groups dict 
        for item in a_bytes['b']:
            # Sum sessionBytes into groups1 
            byte_time = a_bytes['sb'] + item[0]
            if byte_time >= mbp and byte_time <= mbp+59: 
                offset = (byte_time - doc_win_start1) / 10
                session1.groups_dict[group_key][pc.g_b][offset][pc.g_1] \
                                                               += item[1] 
                session1.groups_dict[group_key][pc.g_b][offset][pc.g_2] \
                                                               += item[2]
                session1.groups_dict[group_key][pc.g_b1] += item[1]
                session1.groups_dict[group_key][pc.g_b2] += item[2]

                offset = (byte_time - doc_win_start2) / 120
                session2.groups_dict[group_key][pc.g_b][offset][pc.g_1] \
                                                               += item[1] 
                session2.groups_dict[group_key][pc.g_b][offset][pc.g_2] \
                                                               += item[2] 
                session2.groups_dict[group_key][pc.g_b1] += item[1]
                session2.groups_dict[group_key][pc.g_b2] += item[2]

        if not options.quiet: 
            print "\rmbp: ", mbp, ", ", \
                  "groups1: ", str(len(session1.groups_dict)).rjust(5), ", ",\
                  "groups2: ", str(len(session2.groups_dict)).rjust(5), "  ",\
                  "(", time.asctime(time.gmtime(mbp)), ")\r",
        sys.stdout.flush()

    # End looping through all sess_bytes documents in a chunck 
     
    # Expire old sessions from session_history dictinary
    keys_to_pop = []
    for session_key in session_history:
        if session_history[session_key][h_se] < mbp - trafcap.session_expire_timeout:
            keys_to_pop.append(session_key)

    for session_key in keys_to_pop:
        session_history.pop(session_key)
         
    # Increment mbp
    mbp += 60 

    # write to group db's
    if options.mongo:
        session1.updateDb()
        # update groups2 every 4 minutes
        if mbp%240 == 0:
            session2.updateDb()

    # If on 15 min boundary, write to groups1 and clean-up dictionary
    if mbp == trafcap.secondsTo15Minute(mbp):
        if options.groups: print "At 15 minute interval..."
        #if options.mongo:
        #    if not insert_to_group1 and \
        #    trafcap.secondsTo15Minute(mbp-60) > newest_group1_time:
        #        insert_to_group1 = True
        #    if options.groups: print "insert_to_group1 = ", insert_to_group1
        #    session1.updateDb(insert_to_group1) 

        session1.groups_dict.clear()
        doc_win_start1 = mbp
        for session_key in session_history:
            session_history[session_key][h_counted1] = False

    # If on 3 hour boundary, write to groups2 and clean-up dictionary 
    if mbp == trafcap.secondsTo3Hour(mbp):
        if options.groups: print "At 3 hour interval..."
        #if options.mongo:
        #    if not insert_to_group2 and \
        #    trafcap.secondsTo3Hour(mbp-60) > newest_group2_time:
        #        insert_to_group2 = True
        #    if options.groups: print "insert_to_group2 = ", insert_to_group2
        #    session2.updateDb(insert_to_group2) 

        session2.groups_dict.clear()
        doc_win_start2 = mbp
        for session_key in session_history:
            session_history[session_key][h_counted2] = False

    continue

sys.exit()

