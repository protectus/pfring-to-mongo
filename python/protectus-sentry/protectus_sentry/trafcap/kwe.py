#!/usr/bin/python
#
# Copyright (c) 2013 Protectus,LLC.  All Rights Reserved
#

import sys, time, os, signal
import traceback
from optparse import OptionParser
import ConfigParser

import locale
locale.setlocale(locale.LC_ALL, 'en_US.utf8')

import trafcap
import pymongo

start_bold = "\033[1m"
end_bold = "\033[0;0m"

def parseOptions():
    usage = "usage: %prog -tuionlber || -a  [-v] [-p || d] [-s seconds]"
    parser = OptionParser(usage)
    parser.add_option("-t", "--tcp", dest="tcp",
                      action="store_true", default=False,
                      help="expire tcp data")
    parser.add_option("-u", "--udp", dest="udp",
                      action="store_true", default=False,
                      help="expire udp data")
    parser.add_option("-i", "--icmp", dest="icmp",
                      action="store_true", default=False,
                      help="expire icmp data")
    parser.add_option("-o", "--oth", dest="oth",
                      action="store_true", default=False,
                      help="expire other data")
    parser.add_option("-n", "--nmi", dest="nmi",
                      action="store_true", default=False,
                      help="expire nmi data")
    parser.add_option("-l", "--lpj", dest="lpj",
                      action="store_true", default=False,
                      help="expire lpj data")
    parser.add_option("-b", "--block", dest="block",
                      action="store_true", default=False,
                      help="block or inject event data")
    parser.add_option("-e", "--event", dest="event",
                      action="store_true", default=False,
                      help="expire event data")
    parser.add_option("-r", "--rtp", dest="rtp",
                      action="store_true", default=False,
                      help="expire rtp data")
    parser.add_option("-a", "--all", dest="alldata",
                      action="store_true", default=False,
                      help="expire all types of data")
    parser.add_option("-v", "--verbose", dest="verbose",
                      action="store_true", default=False,
                      help="verbose output")
    parser.add_option("-p", "--prompt", dest="prompt",
                      action="store_true", default=False,
                      help="prompt for confirmation before deleting data")
    parser.add_option("-d", "--dryrun", dest="dryrun",
                      action="store_true", default=False,
                      help="dry run; show what would be deleted, do not delete")
    parser.add_option("-s", "--seconds", dest="seconds",
                      type="int",
                      help="ttl override in seconds")
    (options, args) = parser.parse_args()
    return options

def main():
    options = parseOptions()     # Could combine this line with next line
    trafcap.options = options
    if ((not (options.tcp or options.udp or options.icmp or options.oth or
            options.lpj or options.nmi or options.event or options.rtp or
            options.block)) \
            and not options.alldata) or \
       ((options.tcp or options.udp or options.icmp or options.oth or
            options.lpj or options.nmi or options.event or options.rtp or
            options.block) \
            and options.alldata):
        sys.exit("Must select at least one data type [tuioln] or all data [a] ...")

    if options.dryrun and options.prompt:
        sys.exit("Cannot specify both dry run (-d) and prompt (-p) ...")

    if options.alldata:
        options.tcp = True
        options.udp = True
        options.icmp = True
        options.oth = True
        options.nmi = True
        options.lpj = True
        options.event = True
        options.rtp = True
        options.block = True

    if options.dryrun:
        options.verbose = True

    c_name = 0
    c_begin_name = 1
    c_begin_time = 2
    c_end_name = 3
    c_end_time = 4
    c_num_docs = 5
    c_days = 6
    c_size = 7
    c_size = 8
    c_storage_size = 9
    c_last_extent_size = 10
    c_total_index_size = 11
    c_pct = 12
    c_index = 13

    db = trafcap.mongoSetup()
    coll_names = db.collection_names()

    collections = []
    for coll_name in coll_names:
        if coll_name == 'config': continue
        if coll_name == 'system.indexes': continue
        if coll_name == 'user_annotations': continue
        # Active Defense collections
        if 'injConfig' in coll_name: continue  
        if 'injIp' in coll_name: continue  # maintained by inject code 
        
        if 'tcp' in coll_name and not options.tcp:
            if 'inj' in coll_name: pass
            else: continue
        if 'udp' in coll_name and not options.udp: continue
        if 'icmp' in coll_name and not options.icmp: continue
        if 'oth' in coll_name and not options.oth: continue
        if 'nmi' in coll_name and not options.nmi: continue
        if 'lpj' in coll_name and not options.lpj: continue
        if 'ids' in coll_name and not options.event: continue
        if 'http' in coll_name and not options.event: continue
        if 'rtp' in coll_name and not options.rtp: continue
        if 'inj' in coll_name and not options.block: continue

        if "Bytes" in coll_name:
            begin_name = 'sbm'
            end_name = 'sem'
        elif "_data" in coll_name:
            begin_name = 'sbm'
            end_name = 'sem'
        elif "Count" in coll_name:
            begin_name = 'sbm'
            end_name = 'sem'
        elif "captureInfo" in coll_name:
            begin_name = 'tb'
            end_name = 'te'
        elif "nmi" in coll_name:
            begin_name = 'tm'
            end_name = 'tm'
        elif "eventInfo" in coll_name:
            begin_name = 'tm'
            end_name = 'tm'
        else:
            begin_name = 'tbm'
            end_name = 'tem'

        collections.append([coll_name, begin_name, 0, end_name, 0,
                            0, 0, 0, 0, 0, 0, 0, 0, {}])

    if options.seconds:
       ttl = options.seconds
    else:
        ttl = int(trafcap.traffic_ttl)

    exp_time = int(time.time()) - ttl

    if options.verbose:
        print "Current local time is: ", time.asctime(time.localtime())
        print "TTL configured for: ", ttl, " seconds  == ", \
                                      ttl/3600, " hours == ", \
                                      ttl/3600/24, " days"
        print "Expire data before: ", time.asctime(time.localtime(exp_time))
        print ""

    yes = set(['yes','y',''])
    no = set(['no','n'])
    db = trafcap.mongoSetup()

    # check for remove operation already running
    a_dict = db.current_op() 
    for operation in a_dict['inprog']:
        if operation['op'] == 'remove':
            print 'Remove already in progress.....exiting.'
            sys.exit()

    for coll in collections:

        collection_name = coll[c_name]

        if options.verbose:
            print "Checking ", collection_name,"..... \r",
            sys.stdout.flush()

        if options.verbose or options.prompt:
            # First index in lpj collections is c_id, not time, so handle lpj differently
            if 'lpj_' in collection_name:
                c_id_list = db[collection_name].distinct('c_id')
                for c_id_item in c_id_list:
                    cursor = db[collection_name].find({'c_id':c_id_item, coll[c_end_name]:{'$lt':exp_time}})
                    coll[c_num_docs] += cursor.count()
            else:
                cursor = db[collection_name].find({coll[c_end_name]:{'$lt':exp_time}})
                coll[c_num_docs] = cursor.count()

        if options.prompt:
            question = "Remove " + str(coll[c_num_docs]) + \
                  " docs from " + collection_name + " ?   [Y/n]"
            answer = " "
            while answer not in yes and answer not in no:
                answer = raw_input(question).lower()

            if answer in no:
                continue

        if options.verbose:
            if options.dryrun:
                print "   Could remove ",
            else:
                print "   Removing ",
            print coll[c_num_docs], " docs from ", collection_name 

        if not options.dryrun:
            # First index in lpj collections is c_id, not time, so handle lpj differently
            if 'lpj_' in collection_name:
                c_id_list = db[collection_name].distinct('c_id')
                for c_id_item in c_id_list:
                    db[collection_name].delete_many({'c_id':c_id_item, coll[c_end_name]:{'$lt':exp_time}})
            else:
                db[collection_name].delete_many({coll[c_end_name]:{'$lt':exp_time}})

    sys.exit()

if __name__ == "__main__":
    main()
