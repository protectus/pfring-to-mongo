#!/usr/bin/python

import sys, time, os, signal
import socket
import traceback
from datetime import datetime
import subprocess
from optparse import OptionParser
import math
import ConfigParser
import trafcap
from kwEvent import *
from kwEventContainer import *
import pymongo

# doc_win_start                   mbp
#   |                            |    |
#   |............................|....|.....|


def parseOptions():
    usage = "usage: %prog -i (-e|-c) [-gmq]"
    parser = OptionParser(usage)
    parser.add_option("-g", "--groups", dest="groups",
                      action="store_true", default=False,
                      help="groups debug info")
    parser.add_option("-m", "--mongo", dest="mongo",
                      action="store_true", default=False,
                      help="write to mongo")
    parser.add_option("-q", "--quiet", dest="quiet",
                      action="store_true", default=False,
                      help="don't print status to stdout")
    parser.add_option("-i", "--ids", dest="ids",
                      action="store_true", default=False,
                      help="process ids groups")
    parser.add_option("-e", "--events", dest="events",
                      action="store_true", default=False,
                      help="process event count")
    parser.add_option("-c", "--capture", dest="capture",
                      action="store_true", default=False,
                      help="process capture count")
    (options, args) = parser.parse_args()
    return options, args
 

options, args = parseOptions()     # Could combine this line with next line
trafcap.options = options      
option_check_counter = 0
if options.ids: option_check_counter += 1
if option_check_counter != 1:
    sys.exit("Must use one of -i or ... specify an event type.")

if (not options.events and not options.capture) or \
   (options.events and options.capture):
    sys.exit("Must select either -e to group event count" +  
              " or -c to group capture count")

if options.ids:
    event_type = "IdsEvent"
    collection_prefix = "ids_"
else:
    sys.exit('Invalid protocol')

pc = eval(event_type)
    
# Define input colleciton field names for time start and time end
chunck_size1 = 10     # seconds
chunck_len1 = chunck_size1 - 1  
window_size1 = 15     # minutes

chunck_size2 = 120    # seconds
chunck_len2 = chunck_size2 - 1
window_size2 = 180    # minutes

if options.events:
    count_collection_name = collection_prefix + "eventCount"
    groups1_collection_name = collection_prefix + "eventGroups"
    groups2_collection_name = collection_prefix + "eventGroups2"
elif options.capture:
    count_collection_name = collection_prefix + "captureCount"
    groups1_collection_name = collection_prefix + "captureGroups"
    groups2_collection_name = collection_prefix + "captureGroups2"
else:
    sys.exit('Invalid command line options')

# Holds the group data
event1 = KwEventGroupContainer(pc,
                               count_collection_name,
                               groups1_collection_name)

# Holds the groups2 data
event2 = KwEventGroupContainer(pc,
                               count_collection_name,
                               groups2_collection_name)

def catchSignal1(signum, stack):
    #num_sessions = len(session1.groups_dict)
    #print "\n", num_sessions, " active sessions_group entries:"
    #for k in session1.groups_dict:
    #    print "   ",
    #    print "\033[31m", k, "\t", session1.groups_dict[k], "\033[0m"
    #if num_sessions >= 1: print num_sessions, \
    #                            " active session_group entries displayed."
    pass

def catchSignal2(signum, stack):
    #num_sessions = len(session2.groups_dict)
    #print "\n", num_sessions, " active sessions_group entries:"
    #for k in session2.groups_dict:
    #    print "   ",
    #    print "\033[31m", k, "\t", session2.groups_dict[k], "\033[0m"
    #if num_sessions >= 1: print num_sessions, \
    #                            " active session_group entries displayed."
    pass

def catchCntlC(signum, stack):
    sys.exit()

signal.signal(signal.SIGUSR1, catchSignal1)
signal.signal(signal.SIGUSR2, catchSignal2)
signal.signal(signal.SIGINT, catchCntlC)
signal.signal(signal.SIGTERM, catchCntlC)

def findStartingPoint(events):
    eg = events.db[events.groups_collection].find_one()
    if not eg:
        if not options.quiet:
            print "Event Groups collection not found..."
        # eventGroups collection does not exist. Check for event collection 
        count_collection_exists = False
        ec_cursor = None
        while not count_collection_exists:
            ec_cursor = events.db[events.count_collection].find( \
                                   spec = {}, fields = {'sb':1}, 
                                   sort = [('_id',1)], limit = 1)

            if ec_cursor.count() > 0:
                print "Event count collection found..."
                count_collection_exists = True 
            else:
                print "Event count collection not found. Sleeping..."
                time.sleep(2) 
    
        oldest_eventCount_sb = ec_cursor[0]['sb']
        result = oldest_eventCount_sb
    else:
        if not options.quiet:
            print "Event groups collection found..."
        # sessionGroups exists, return most recent tbm in sessionGroups
        eg_cursor = events.db[events.groups_collection].find( \
                               spec = {}, fields = {'tbm':1}, 
                               sort = [('tem',-1)], limit = 1)
        result = eg_cursor[0]['tbm']
    return result

# Find the starting point for consolidating sessionInfo and sessionBytes
# into sessionGroups
print "Searching for starting time..."

newest_group1_time = findStartingPoint(event1)
newest_group2_time = findStartingPoint(event2)

print newest_group1_time
print newest_group2_time

# Find beginning of session document window 
doc_win_start1 = trafcap.findWindowBoundary(newest_group1_time, window_size1)
doc_win_start2 = trafcap.findWindowBoundary(newest_group2_time, window_size2)
mbp = min(doc_win_start1, doc_win_start2)
doc_win_start1 = mbp
doc_win_start2 = mbp
max_doc_duration = 3600 * 24 * 5       # 5 days

#if not options.quiet:
print "Most recent groups 1 doc window start time = ", doc_win_start1
print "Most recent groups 2 doc window start time = ", doc_win_start2
print "Minute being processed = ", mbp 

#
# Begin main loop
#
while True:
    # Sleep if mbp is still being written to the input collection 
    most_recent_doc = event1.db[event1.count_collection].find( \
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

    # Find all docs in eventCount with tb <= mbp <= te
    if not options.quiet:
        print "Querying eventCount for mbp = ", mbp

    a_spec = {'sbm':{'$lte':mbp+59,'$gt':mbp - max_doc_duration},'sem':{'$gte':mbp, '$lt':mbp + max_doc_duration}}
    a_sort = [('sb',pymongo.ASCENDING)]
    evnt_count = event1.db[event1.count_collection].find( \
                          spec = a_spec, sort = a_sort)

    if not options.quiet:
        print "Found ", evnt_count.count(),  \
              " matching eventCount documents in mbp ", mbp
        print a_spec
        print a_sort

    # For the evnt_count array element with data, 
    # add data to the event_group arrays
    for a_count in evnt_count:

        group_key = pc.getGroupKey(a_count)

        event1.updateGroupsDict(group_key, a_count, chunck_size1, 
                                doc_win_start1)

        event2.updateGroupsDict(group_key, a_count, chunck_size2, 
                                doc_win_start2)
                
        # Pull count from doc and sum into groups dict 
        for item in a_count['e']:
            # Sum eventCounts into groups 
            count_time = a_count['sb'] + item[0]
            if count_time >= mbp and count_time <= mbp+59: 
                offset = (count_time - doc_win_start1) / 10
                event1.groups_dict[group_key][pc.g_e][offset][pc.g_cnt]+=item[1]
                event1.groups_dict[group_key][pc.g_e_cnt] += item[1]

                offset = (count_time - doc_win_start2) / 120
                event2.groups_dict[group_key][pc.g_e][offset][pc.g_cnt]+=item[1]
                event2.groups_dict[group_key][pc.g_e_cnt] += item[1]

        if not options.quiet: 
            print "\rmbp: ", mbp, ", ", \
                  "groups1: ", str(len(event1.groups_dict)).rjust(5), ", ",\
                  "groups2: ", str(len(event2.groups_dict)).rjust(5), "  ",\
                  "(", time.asctime(time.gmtime(mbp)), ")\r",
        sys.stdout.flush()

    # End looping through all sess_bytes documents in a chunck 
     
    # Increment mbp
    mbp += 60 

    # write to group db's
    if options.mongo:
        event1.updateDb()
        # update groups2 every 8 minutes
        if mbp%240 == 0:
            event2.updateDb()

    # If on 15 min boundary, write to groups1 and clean-up dictionary
    if mbp == trafcap.secondsTo15Minute(mbp):
        if options.groups: print "At 15 minute interval..."

        event1.groups_dict.clear()
        doc_win_start1 = mbp

    # If on 3 hour boundary, write to groups2 and clean-up dictionary 
    if mbp == trafcap.secondsTo3Hour(mbp):
        if options.groups: print "At 3 hour interval..."

        event2.groups_dict.clear()
        doc_win_start2 = mbp

    continue

sys.exit()

