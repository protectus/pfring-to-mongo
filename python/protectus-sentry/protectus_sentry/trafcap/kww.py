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
import ConfigParser
from datetime import timedelta
from operator import itemgetter

import locale
locale.setlocale(locale.LC_ALL, 'en_US.utf8')

import trafcap
import pymongo

start_bold = "\033[1m"
end_bold = "\033[0;0m"

def parseOptions():
    usage = "usage: %prog [cbdezsainx]"
    parser = OptionParser(usage)
    parser.add_option("-c", "--collection", dest="collection",
                      action="store_true", default=False,
                      help="sort by collection name")
    parser.add_option("-b", "--begin", dest="begin",
                      action="store_true", default=False,
                      help="sort by begin time")
    parser.add_option("-d", "--days", dest="days",
                      action="store_true", default=False,
                      help="sort by days in collection")
    parser.add_option("-e", "--end", dest="end",
                      action="store_true", default=False,
                      help="sort by end time")
    parser.add_option("-z", "--dsize", dest="dsize",
                      action="store_true", default=False,
                      help="sort by data size")
    parser.add_option("-s", "--ssize", dest="ssize",
                      action="store_true", default=False,
                      help="sort by storage size")
    parser.add_option("-a", "--aosiz", dest="aosiz",
                      action="store_true", default=False,
                      help="last extent size")
    parser.add_option("-i", "--isize", dest="isize",
                      action="store_true", default=False,
                      help="index size")
    parser.add_option("-n", "--num", dest="num",
                      action="store_true", default=False,
                      help="sort by number of docs")
    parser.add_option("-x", "--index", dest="index",
                      action="store_true", default=False,
                      help="show indexes")
    (options, args) = parser.parse_args()
    return options

def sizeof_readable(num):
    for x in [' ','K','M','G']:
        if num < 1000.0:
            return "%3.0f%s" % (num, x)
            #return "%3.1f%s" % (num, x)
        num /= 1000.0
    return "%3.1f%s" % (num, 'TB')

def sizeof_readable_bytes(num):
    for x in ['.B','KB','MB','GB']:
        if num < 1024.0:
            return "%3.0f%s" % (num, x)
            #return "%3.1f%s" % (num, x)
        num /= 1024.0
    return "%3.1f%s" % (num, 'TB')

def main():
    options = parseOptions()     # Could combine this line with next line
    trafcap.options = options
    #if (not options.group1 and not options.group2) or \
    #   (options.group1 and options.group2):
    #    sys.exit("Must select either -1 for first session groups" +
    #              " or -2 for second session groups")

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
    c_avg_obj_size = 10
    c_total_index_size = 11
    c_pct = 12
    c_index = 13

    db = trafcap.mongoSetup()
    coll_names = db.collection_names()
    coll_names.sort()

    collections = []
    for coll_name in coll_names:
        if coll_name == 'config': continue
        if coll_name == 'system.indexes': continue

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
        elif "annotations" in coll_name:
            begin_name = 't'
            end_name = 't'
        elif "_injIp" in coll_name:
            begin_name = 'tb'
            end_name = 'texp'
        else:
            begin_name = 'tbm'
            end_name = 'tem'

        collections.append([coll_name, begin_name, 0, end_name, 0, 
                            0, 0, 0, 0, 0, 0, 0, 0, {}])

    print ""
    print time.asctime(time.localtime()).center(80)


    for coll in collections:

        collection_name = coll[c_name]

        print "Checking.....", collection_name,".....begin time                \r",
        sys.stdout.flush()

        cursor = db[collection_name].find( \
                    projection = {coll[c_begin_name]:1},
                    sort = [('_id',1)], limit = 1)

        # Check if the collection exists
        coll[c_num_docs] = cursor.count()
        if coll[c_num_docs] == 0:
            # Handle empty or non-existant collections
            try:
                stats = db.command('collstats', collection_name)
            except:
                # collection does not exist
                continue
            # collection is allocated but empty
            coll[c_storage_size] = stats['storageSize']
            continue

        coll[c_begin_time] = cursor[0][coll[c_begin_name]]

        # Find begin time (oldest)
        print "Checking.....", collection_name,".....end time                  \r",
        sys.stdout.flush()

        # Find end time (most recent)
        cursor = db[collection_name].find( \
                    projection = {coll[c_end_name]:1},
                    sort = [('_id',-1)], limit = 1)

        coll[c_end_time] = cursor[0][coll[c_end_name]]


        #delta = coll[c_end_time] - coll[c_begin_time]
        #coll[c_days] = int(round(delta/(60*60*24)))

        begin = datetime.fromtimestamp(coll[c_begin_time])
        end = datetime.fromtimestamp(coll[c_end_time])
        delta = end - begin
        coll[c_days] = delta.days


        print "Checking.....", collection_name,".....stats                     \r",
        sys.stdout.flush()
        stats = db.command('collstats', collection_name)

        coll[c_size] = stats['size']
        coll[c_storage_size] = stats['storageSize']
        coll[c_avg_obj_size] = stats['avgObjSize']
        coll[c_total_index_size] = stats['totalIndexSize']

        coll[c_index] = stats['indexSizes']

        # Add 1 to demonminator to prevent divide by 0
        coll[c_pct] = float(coll[c_size]) / float(coll[c_storage_size]+1)*100

    # Sort
    if options.collection:
        sorted_collections = sorted(collections, key=itemgetter(c_name))
        sorted_collections.reverse()
    elif options.begin:
        sorted_collections = sorted(collections, key=itemgetter(c_begin_time))
        sorted_collections.reverse()
    elif options.days:
        sorted_collections = sorted(collections, key=itemgetter(c_days))
        sorted_collections.reverse()
    elif options.end:
        sorted_collections = sorted(collections, key=itemgetter(c_end_time))
        sorted_collections.reverse()
    elif options.dsize:
        sorted_collections = sorted(collections, key=itemgetter(c_size))
        sorted_collections.reverse()
    elif options.ssize:
        sorted_collections = sorted(collections, key=itemgetter(c_storage_size))
        sorted_collections.reverse()
    elif options.aosiz:
        sorted_collections = sorted(collections, key=itemgetter(c_avg_obj_size))
        sorted_collections.reverse()
    elif options.isize:
        sorted_collections = sorted(collections, key=itemgetter(c_total_index_size))
        sorted_collections.reverse()
    elif options.num:
        sorted_collections = sorted(collections, key=itemgetter(c_num_docs))
        sorted_collections.reverse()
    else:
        sorted_collections = collections

    rows = 0
    if not options.index:
        a_list =  [ "Collection".center(19),
                    "Begin".center(11),
                    ' ',
                    "Days".rjust(3),
                    "End".center(11), '  ',
                    "dsiZe", ' sSize', " Aosiz", " Isize", "   Ndoc"]
        header = "".join(a_list)
        print start_bold, header, end_bold

        for coll in sorted_collections:
            a_list=[coll[c_name].ljust(19), ' ',
                    time.strftime("%H:%M-%d%b",time.localtime(coll[c_begin_time])),
                    ' ',
                    str(coll[c_days]).rjust(3),
                    ' ',
                    time.strftime("%H:%M-%d%b",time.localtime(coll[c_end_time])),
                    '  ',
                    sizeof_readable_bytes(coll[c_size]).rjust(5),
                    ' ',
                    sizeof_readable_bytes(coll[c_storage_size]).rjust(5),
                    ' ',
                    sizeof_readable_bytes(coll[c_avg_obj_size]).rjust(5),
                    ' ',
                    sizeof_readable_bytes(coll[c_total_index_size]).rjust(5),
                    '  ',
                    sizeof_readable(coll[c_num_docs]).rjust(5)]

            if coll[c_begin_time] == 0: a_list[2] = " ".rjust(11)
            if coll[c_end_time] == 0: a_list[6] = " ".rjust(11)

            txt_out = "".join(a_list)
            print txt_out
            rows += 1

    else:
        a_list =  [ "Collection".center(18), '  ',
                    'Index'.center(34),
                    'Size'.center(5)]
        header = "".join(a_list)
        print start_bold, header, end_bold

        for coll in sorted_collections:
            print coll[c_name].ljust(18),
            rows = 1
            for key in coll[c_index]:
                if rows > 1:
                    print " ".rjust(18),
                print key.rjust(34),  sizeof_readable_bytes(coll[c_index][key]).rjust(6)
                rows +=1

            if len(coll[c_index]) == 0:
                print ""

    if not options.index:
        total_size = 0
        total_storage_size = 0
        total_avg_obj_size = 0
        total_total_index_size = 0
        total_docs = 0
        for coll in sorted_collections:
            total_size = total_size + coll[c_size]
            total_storage_size = total_storage_size + coll[c_storage_size]
            total_avg_obj_size = total_avg_obj_size + coll[c_avg_obj_size]
            total_total_index_size = total_total_index_size + coll[c_total_index_size]
            total_docs = total_docs + coll[c_num_docs]

        a_list = ['                                                 ',
                  '-----',
                  ' ',
                  '-----',
                  ' ',
                  '-----',
                  ' ',
                  '-----',
                  '   ',
                  '----']
        txt_out = "".join(a_list)
        print txt_out

        a_list = ['                                                 ',
                  sizeof_readable_bytes(total_size),
                  ' ',
                  sizeof_readable_bytes(total_storage_size),
                  ' ',
                  sizeof_readable_bytes(total_avg_obj_size/rows),
                  ' ',
                  sizeof_readable_bytes(total_total_index_size),
                  '   ',
                  sizeof_readable(total_docs)]
        txt_out = "".join(a_list)
        print txt_out

    sys.exit()

if __name__ == "__main__":
    main()

