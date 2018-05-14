#!/usr/bin/python
#
# Copyright (c) 2013 Protectus,LLC.  All Rights Reserved.
#

import sys, time, os, signal
from select import select
import socket
import traceback
from datetime import datetime
import subprocess
from optparse import OptionParser
import math
import configparser
from protectus_sentry.trafcap import trafcap
from protectus_sentry.trafcap.lpjPacket import IpLpjPacket, IcmpLpjPacket
from protectus_sentry.trafcap import lpjContainer 
import pymongo

def parseOptions():
    usage = "usage: %prog [-dgmq]"
    parser = OptionParser(usage)
    parser.add_option("-d", "--data", dest="data",
                      action="store_true", default=False,
                      help="data debug info")
    parser.add_option("-g", "--groups", dest="groups",
                      action="store_true", default=False,
                      help="groups debug info")
    parser.add_option("-m", "--mongo", dest="mongo",
                      action="store_true", default=False,
                      help="write to mongo")
    parser.add_option("-q", "--quiet", dest="quiet",
                      action="store_true", default=False,
                      help="don't print status to stdout")
    (options, args) = parser.parse_args()
    return options, args
 
def main():
    options, args = parseOptions()     # Could combine this line with next line
    trafcap.options = options      

    packet_type = "IpLpjPacket"
    collection_prefix = "lpj_"

    pc = eval(packet_type)
        
    # Define input colleciton field names for time start and time end
    chunck_size1 = 10     # seconds
    chunck_len1 = chunck_size1 - 1  
    window_size1 = 15     # minutes

    chunck_size2 = 120    # seconds
    chunck_len2 = chunck_size2 - 1
    window_size2 = 180    # minutes

    data_collection_name = collection_prefix + "data"
    groups1_collection_name = collection_prefix + "groups"
    groups2_collection_name = collection_prefix + "groups2"

    # Holds the group data
    session1 = lpjContainer.LpjGroupContainer(pc, data_collection_name, groups1_collection_name)

    # Holds the groups2 data
    session2 = lpjContainer.LpjGroupContainer(pc, data_collection_name, groups2_collection_name)

    def catchSignal1(signum, stack):
        num_sessions = len(session1.groups_dict)
        print("\n", num_sessions, " active lpj_group entries:")
        for k in session1.groups_dict:
            print("   ", end=' ')
            print("\033[31m", k, "\t", session1.groups_dict[k], "\033[0m")
        if num_sessions >= 1: print(num_sessions, \
                                    " active lpj_group entries displayed.")

    def catchSignal2(signum, stack):
        num_sessions = len(session2.groups_dict)
        print("\n", num_sessions, " active sessions_group2 entries:")
        for k in session2.groups_dict:
            print("   ", end=' ')
            print("\033[31m", k, "\t", session2.groups_dict[k], "\033[0m")
        if num_sessions >= 1: print(num_sessions, \
                                    " active session_group2 entries displayed.")

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
                print("Session Groups collection not found...")
            # sessionGroups collection does not exist.  Check for bytes collection 
            bytes_collection_exists = False
            sb_cursor = None
            while not bytes_collection_exists:
                sb_cursor = session.db[session.data_collection].find( \
                                       {}, projection = {'sb':True}, 
                                       sort = [('_id',1)], limit = 1)

                if sb_cursor.count() > 0:
                    bytes_collection_exists = True
                else:
                    print("Session data collection not found. Sleeping...")
                    time.sleep(2)
        
            oldest_sessionData_sb = sb_cursor[0]['sb']
            result = oldest_sessionData_sb
        else:
            if not options.quiet:
                print("Session Groups collection found...")
            # sessionGroups exists, return most recent tbm in sessionGroups
            sg_cursor = session.db[session.groups_collection].find( \
                                   {}, projection = {'tbm':True}, 
                                   sort = [('tem',-1)], limit = 1)
            result = sg_cursor[0]['tbm']
        return result

    # Find the starting point for consolidating sessionInfo and sessionBytes
    # into sessionGroups
    if not options.quiet:
        print("Searching for starting time...")

    newest_group1_time = findStartingPoint(session1)
    newest_group2_time = findStartingPoint(session2)
    # Used to decide between inserting (faster) and updating (needed at first) db
    insert_to_group1 = False
    insert_to_group2 = False

    print(newest_group1_time)
    print(newest_group2_time)

    # Find beginning of session document window 
    doc_win_start1 = trafcap.findWindowBoundary(newest_group1_time, window_size1)
    doc_win_start2 = trafcap.findWindowBoundary(newest_group2_time, window_size2)
    mbp = min(doc_win_start1, doc_win_start2)
    doc_win_start1 = mbp
    doc_win_start2 = mbp
    #max_doc_duration = 3600 * 24 * 5       # 5 days

    if not options.quiet:
        print("Most recent groups 1 doc window start time = ", doc_win_start1)
        print("Most recent groups 2 doc window start time = ", doc_win_start2)
        print("Minute being processed = ", mbp) 

    # Create dictionary with session byte history - used later to determine
    # if a session is new or existing.  Find all sessions from:
    #   (mbp - session_expire_timeout) ===> mbp
    #
    # Counted flags indicate if a session has been counted in the corresponding
    # group's ns and ne fields for the current doc_window
    #
    # [session_key] ==> [ sb, se, counted1, counted2 ]
    h_sb=0; h_se=1; h_counted1=2; h_counted2=3

    write_to_groups2 = False

    #
    # Begin main loop
    #
    while True:
        # Sleep if mbp is still being written to the input collection 
        most_recent_doc = session1.db[session1.data_collection].find( \
                                     {}, 
                                     projection = {'se':True},
                                     #sort = [('$natural',-1)],
                                     sort = [('sem', pymongo.DESCENDING)],
                                     limit = 1)

        if mbp >= (trafcap.secondsToMinute(most_recent_doc[0]['se'] - 60)):
            if not options.quiet:
                print("")
                print("\r\033[33m", "mbp: ", mbp, \
                      " is close to most_recent_doc: ", most_recent_doc[0]['se'], \
                      ",  sleeping.......", "\033[0m", end=' ')
                sys.stdout.flush()
            time.sleep(60)
            continue

        if options.data:
            print("Querying lpj_data for mbp = ", mbp)

        # Want to find sbm==mbp, but for lpj_data sbm=sem=sb.  So a search for
        # sem===mbp is equivalent and allows consitent use of end times for indexes.
        a_spec = {'sem':mbp}
        a_sort = [('sb',pymongo.ASCENDING)]
        sess_data = session1.db[session1.data_collection].find( \
                                 a_spec, sort = a_sort)

        if options.data:
            print("Found ", sess_data.count(),  \
                  " matching documents in mbp ", mbp)

        for a_data in sess_data:

            pc = eval(a_data['pr'].capitalize() + "LpjPacket")

            group_key = pc.getGroupKey(a_data)
            session_key = pc.getSessionKey(a_data) 

            session1.updateGroupsDict(group_key, a_data, chunck_size1, 
                                      doc_win_start1)

            session2.updateGroupsDict(group_key, a_data, chunck_size2, 
                                      doc_win_start2)

            rtl_list1 = session1.groups_dict[group_key][pc.g_rtl_list]
            rtl_list2 = session2.groups_dict[group_key][pc.g_rtl_list]
            pl_list1 = session1.groups_dict[group_key][pc.g_pl_list]
            pl_list2 = session2.groups_dict[group_key][pc.g_pl_list]

            # Pull from lpj_data and consolidate in to groups 
            for item in a_data['rtl']:
                data_time = a_data['sb'] + item[pc.d_offset]
                if data_time >= mbp and data_time <= mbp+59: 
                    chunck_start1 = trafcap.secondsTo10Seconds(data_time)
                    rtl_offset1 = (chunck_start1 - doc_win_start1) // chunck_size1
                    rtl_list1[rtl_offset1][pc.g_rtl] += item[pc.d_rtl]
                    rtl_list1[rtl_offset1][pc.g_count] += 1 
                    pl_list1[rtl_offset1][pc.g_count] += 1 

                    chunck_start2 = trafcap.secondsTo2Minute(data_time)
                    rtl_offset2 = (chunck_start2 - doc_win_start2) // chunck_size2
                    rtl_list2[rtl_offset2][pc.g_rtl] += item[pc.d_rtl]
                    rtl_list2[rtl_offset2][pc.g_count] += 1 
                    pl_list2[rtl_offset2][pc.g_count] += 1 

            for item in a_data['pl']:
                data_time = a_data['sb'] + item[pc.d_offset]
                if data_time >= mbp and data_time <= mbp+59: 
                    chunck_start1 = trafcap.secondsTo10Seconds(data_time)
                    pl_offset1 = (chunck_start1 - doc_win_start1) // chunck_size1
                    pl_list1[pl_offset1][pc.g_pl] += item[pc.d_pl]
                
                    chunck_start2 = trafcap.secondsTo2Minute(data_time)
                    pl_offset2 = (chunck_start2 - doc_win_start2) // chunck_size2
                    pl_list2[pl_offset2][pc.g_pl] += item[pc.d_pl]

        # End looping through all sess_data documents in a chunck 

        # Loop through group dictionary to average results in MBP
        for group_key in session1.groups_dict:    
            a_group = session1.groups_dict[group_key]
            pc = eval(a_group[0].capitalize() + "LpjPacket")
            rtl_list1 = session1.groups_dict[group_key][pc.g_rtl_list]
            pl_list1 = session1.groups_dict[group_key][pc.g_pl_list]

            # average data for six new, 10 second entries in groups1
            a_group1 = session1.groups_dict[group_key]
            grp_offset1 = (mbp - a_group1[pc.g_tbm]) // chunck_size1
            for i in range(grp_offset1, grp_offset1+6):
                rtl_total = rtl_list1[i][pc.g_rtl] 
                rtl_count = rtl_list1[i][pc.g_count] 
                if rtl_count != 0:
                    rtl_list1[i][pc.g_rtl] = round(rtl_total / rtl_count, 3)
                session1.groups_dict[group_key][pc.g_eol] = i 

                pl_total = float(pl_list1[i][pc.g_pl])
                pl_count = pl_list1[i][pc.g_count] 
                if pl_count != 0:
                    pl_list1[i][pc.g_pl] = round(pl_total / pl_count, 3)

        for group_key in session2.groups_dict:
            a_group = session2.groups_dict[group_key]
            pc = eval(a_group[0].capitalize() + "LpjPacket")
            rtl_list2 = session2.groups_dict[group_key][pc.g_rtl_list]
            pl_list2 = session2.groups_dict[group_key][pc.g_pl_list]

            # if mbp in second half of two minute groups2 chunck, average data
            a_group2 = session2.groups_dict[group_key]
            grp_offset2 = int((mbp - a_group2[pc.g_tbm]) / chunck_size2)
            if a_group2[pc.g_tbm] + \
               a_group2[pc.g_rtl_list][grp_offset2][pc.g_offset] + 60 == mbp:
                rtl_total = rtl_list2[grp_offset2][pc.g_rtl] 
                rtl_count = rtl_list2[grp_offset2][pc.g_count] 
                if rtl_count != 0:
                    rtl_list2[grp_offset2][pc.g_rtl]=round(rtl_total/rtl_count, 3)
                session2.groups_dict[group_key][pc.g_eol] = grp_offset2
                write_to_groups2 = True

                pl_total = float(pl_list2[grp_offset2][pc.g_pl])
                pl_count = pl_list2[grp_offset2][pc.g_count] 
                if pl_count != 0:
                    pl_list2[grp_offset2][pc.g_pl] = round(pl_total / pl_count, 3)

        if not options.quiet: 
            print("\rmbp: ", mbp, ", ", \
                  "groups1: ", str(len(session1.groups_dict)).rjust(5), ", ",\
                  "groups2: ", str(len(session2.groups_dict)).rjust(5), "  ",\
                  "(", time.asctime(time.gmtime(mbp)), ")\r", end=' ')
        sys.stdout.flush()

        # Increment mbp
        mbp += 60 

        # write to groups1
        if options.mongo:
            session1.updateDb() 
            if write_to_groups2:
                session2.updateDb() 
                write_to_groups2 = False

        # If on 15 min boundary, clean-up groups1 dictionary
        if mbp == trafcap.secondsTo15Minute(mbp):
            if options.groups: print("At 15 minute interval...")
            session1.groups_dict.clear()
            doc_win_start1 = mbp

        # If on 3 hour boundary, clean-up groups2 dictionary 
        if mbp == trafcap.secondsTo3Hour(mbp):
            if options.groups: print("At 3 hour interval...")
            session2.groups_dict.clear()
            doc_win_start2 = mbp

        continue

    sys.exit()

if __name__ == "__main__":
    main()

