#!/usr/bin/python
#
# Copyright (c) 2013 Protectus,LLC.  All Rights Reserved.
#
import sys, time, os, signal
from select import select
import socket
from datetime import datetime
import subprocess
from optparse import OptionParser
import math
import traceback
import trafcap
from protectus_sentry.trafcap.trafcapIpPacket import *
from protectus_sentry.trafcap.trafcapEthernetPacket import *
from protectus_sentry.trafcap.trafcapContainer import *

from protectus_sentry.trafcap.trafcapProcess import *
import multiprocessing
#import queue
from collections import deque
from pymongo.bulk import InvalidOperation
import operator

#CYTHON
from cpython cimport array
from libc.stdint cimport uint64_t, uint32_t, uint16_t, uint8_t, int64_t
from libc.string cimport memcpy, memset
from libc.stdlib cimport malloc
import ctypes
from cpf_ring cimport * 
from trafcapIpPacket cimport * 

proc = None

trafcap.checkIfRoot()

def parseOptions():
    usage = "usage: %prog -t|u|i|o [-mq]"
    parser = OptionParser(usage)
    parser.add_option("-m", "--mongo", dest="mongo",
                      action="store_true", default=False,
                      help="write to mongo")
    parser.add_option("-q", "--quiet", dest="quiet",
                      action="store_true", default=False,
                      help="don't print status to stdout")
    parser.add_option("-t", "--tcp", dest="tcp",
                      action="store_true", default=False,
                      help="process tcp traffic")
    parser.add_option("-u", "--udp", dest="udp",
                      action="store_true", default=False,
                      help="process udp traffic")
    parser.add_option("-i", "--icmp", dest="icmp",
                      action="store_true", default=False,
                      help="process icmp traffic")
    parser.add_option("-o", "--other", dest="other",
                      action="store_true", default=False,
                      help="process other traffic")
    parser.add_option("-r", "--rtp", dest="rtp",
                      action="store_true", default=False,
                      help="process rtp traffic")
    parser.add_option("-p", "--process", dest="process",
                      action="store_true", default=False,
                      help="use multi-process ingest with pf_ring")
    parser.add_option("-g", "--group", dest="group",
                      action="store_true", default=False,
                      help="perform group processing")
    (options, args) = parser.parse_args()
    return options

def exitNowUni(message):
    # Kill the childprocess sniffing packets
    print "Exiting..."
    if proc:
        os.kill(proc.pid, signal.SIGTERM)
    sys.exit(message)
 
# This is not being used - maybe delete
def exitNowMulti(message):
    # Kill the childprocess sniffing packets
    print "Exiting now...", message
    global main_running
    main_running = False
    global packetParser_running
    packetParser_running = False
    global sessionUpdater_running
    sessionUpdater_running = False
    global sessionBookkeeper_running
    sessionBookkeeper_running = False
    global groupUpdater_running
    groupUpdater_running = False
    os.kill(os.getpid(), signal.SIGTERM)

start_bold = "\033[1m"
end_bold = "\033[0;0m"

cdef bint main_running = True
def main():

    #TODO: Options processing should probably go here, as well as interrupt code.
    options = parseOptions()     # Could combine this line with next line
    trafcap.options = options

    option_check_counter = 0
    if options.tcp: option_check_counter += 1
    if options.udp: option_check_counter += 1
    if options.icmp: option_check_counter += 1
    if options.other: option_check_counter += 1
    if options.rtp: option_check_counter += 1
    if option_check_counter != 1:
        sys.exit("Must use one of -t, -u, -i, or -o to specify a protocol.")

    if options.process:
        # Multi-process ingest

        # The main function is responsible for setting up and kicking off the parse
        # function and the ingest function.  It tries to be responsible for all
        # interupts, fatal errors, and cleanup.
        proto_opts = {}

        proto_opts['group_time_window'] = (15, 180)
        # Select protocol.  Note that packet_type variable must be set
        if options.tcp:
            proto_opts['bpf_filter'] = 'ip and tcp'
            proto_opts['parse_packet'] = <long>&parse_tcp_packet 
            proto_opts['generate_session_key_from_pkt'] = <long>&generate_tcp_session_key_from_pkt
            proto_opts['generate_session'] = <long>&generate_tcp_session
            proto_opts['update_session'] = <long>&update_tcp_session
            proto_opts['generate_session_key_from_session'] = <long>&generate_tcp_session_key_from_session
            proto_opts['alloc_capture_session'] = <long>&alloc_tcp_capture_session
            proto_opts['write_session'] = <long>&write_tcp_session
            proto_opts['packet_header_class_name'] = 'PythonTCPPacketHeaders'
            proto_opts['session_class_name'] = 'PythonTCPSession'
            proto_opts['group_class_name'] = 'PythonTCPGroup'
            proto_opts['session_info_coll_name'] = 'tcp_sessionInfo'
            proto_opts['session_bytes_coll_name'] = 'tcp_sessionBytes'
            proto_opts['capture_info_coll_name'] = 'tcp_captureInfo'
            proto_opts['capture_bytes_coll_name'] = 'tcp_captureBytes'
            proto_opts['capture_group_name'] = ('tcp_captureGroups', 'tcp_captureGroups2')
            #proto_opts['capture_group2_name'] = 'tcp_captureGroups2'
            proto_opts['session_group_name'] = ('tcp_sessionGroups', 'tcp_sessionGroups2')
            #proto_opts['session_group2_name'] = 'tcp_sessionGroups2'
            proto_opts['write_group'] = <long>&write_tcp_group
            #proto_opts['alloc_capture_group'] = <long>&alloc_tcp_capture_group
            proto_opts['init_capture_group'] = <long>&init_tcp_capture_group
            proto_opts['generate_group'] = <long>&generate_tcp_group
            proto_opts['generate_group_key_from_session'] = <long>&generate_tcp_group_key_from_session
            proto_opts['generate_group_key_from_group'] = <long>&generate_tcp_group_key_from_group
            proto_opts['update_group'] = <long>&update_tcp_group

        elif options.udp:
            proto_opts['bpf_filter'] = 'ip and udp'
            proto_opts['parse_packet'] = <long>&parse_udp_packet 
            proto_opts['generate_session_key_from_pkt'] = <long>&generate_udp_session_key_from_pkt
            proto_opts['generate_session'] = <long>&generate_udp_session
            proto_opts['update_session'] = <long>&update_udp_session
            proto_opts['generate_session_key_from_session'] = <long>&generate_udp_session_key_from_session
            proto_opts['alloc_capture_session'] = <long>&alloc_udp_capture_session
            proto_opts['write_session'] = <long>&write_udp_session
            proto_opts['packet_header_class_name'] = 'PythonUDPPacketHeaders'
            proto_opts['session_class_name'] = 'PythonUDPSession'
            proto_opts['group_class_name'] = 'PythonUDPGroup'
            proto_opts['session_info_coll_name'] = 'udp_sessionInfo'
            proto_opts['session_bytes_coll_name'] = 'udp_sessionBytes'
            proto_opts['capture_info_coll_name'] = 'udp_captureInfo'
            proto_opts['capture_bytes_coll_name'] = 'udp_captureBytes'
            proto_opts['capture_group_name'] = ('udp_captureGroups', 'udp_captureGroups2')
            #proto_opts['capture_group2_name'] = 'udp_captureGroups2'
            proto_opts['session_group_name'] = ('udp_sessionGroups', 'udp_sessionGroups2')
            #proto_opts['session_group2_name'] = 'udp_sessionGroups2'
            proto_opts['write_group'] = <long>&write_udp_group
            #proto_opts['alloc_capture_group'] = <long>&alloc_udp_capture_group
            proto_opts['init_capture_group'] = <long>&init_udp_capture_group
            proto_opts['generate_group'] = <long>&generate_udp_group
            proto_opts['generate_group_key_from_session'] = <long>&generate_udp_group_key_from_session
            proto_opts['generate_group_key_from_group'] = <long>&generate_udp_group_key_from_group
            proto_opts['update_group'] = <long>&update_udp_group

        elif options.icmp:
            sys.exit("-i not implemeted yet.")
        elif options.other:
            sys.exit("-o not implemeted yet.")
        elif options.rtp:
            sys.exit("-r not implemeted yet.")
        else:
           sys.exit('Invalid protocol') 

        packet_header_class = eval(proto_opts['packet_header_class_name'])
        session_class = eval(proto_opts['session_class_name'])
        group_class = eval(proto_opts['group_class_name'])

        def catchSignal1(signum, stac):
            print 'Caught Signal1 in main....'

        def catchSignal2(signum, stack):
            print 'Caught Signal2 in main....'

        def catchCntlC(signum, stack):
            print 'Caught CntlC in main....'
            global main_running
            main_running = False

        signal.signal(signal.SIGUSR1, catchSignal1)
        signal.signal(signal.SIGUSR2, catchSignal2)
        signal.signal(signal.SIGINT, catchCntlC)
        signal.signal(signal.SIGTERM, catchCntlC)

        oldest_session_time = int(time.time()) - trafcap.session_expire_timeout

        # Will be replaced by ring stats 
        parser_packet_count = multiprocessing.Value(ctypes.c_uint64)
        parser_packet_count.value = 0

        packet_cursor_pipe = multiprocessing.Pipe(False)
        # Try to increase pipe buffer size
        #import fcntl  
        #fd = packet_cursor_pipe[1].fileno() 
        #fl = fcntl.fcntl(fd, fcntl.F_GETFL) 
        #print 'has_attr: ', hasattr(fcntl, 'F_SETPIPE_SZ')  ==> This is False
        #fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK) 
        packet_ring_buffer = multiprocessing.RawArray(packet_header_class, trafcap.packet_ring_buffer_size)

        ring_stats_recv = multiprocessing.Value(ctypes.c_uint64)
        ring_stats_recv.value = 0
        ring_stats_drop = multiprocessing.Value(ctypes.c_uint64)
        ring_stats_drop.value = 0

        session_updater_packet_count = multiprocessing.Value(ctypes.c_uint64)
        session_updater_packet_count.value = 0
        session_updater_live_session_alloc_count = multiprocessing.Value(ctypes.c_uint64)
        session_updater_live_session_alloc_count.value = 0
        session_updater_live_session_dealloc_count = multiprocessing.Value(ctypes.c_uint64)
        session_updater_live_session_dealloc_count.value = 0
        session_keeper_live_session_alloc_count = multiprocessing.Value(ctypes.c_uint64)
        session_keeper_live_session_alloc_count.value = 0
        session_keeper_live_session_dealloc_count = multiprocessing.Value(ctypes.c_uint64)
        session_keeper_live_session_dealloc_count.value = 0
        session_keeper_saved_session_count = multiprocessing.Value(ctypes.c_uint64)
        session_keeper_saved_session_count.value = 0
        session_keeper_saved_session2_count = multiprocessing.Value(ctypes.c_uint64)
        session_keeper_saved_session2_count.value = 0

        live_session_buffer = multiprocessing.RawArray(session_class, trafcap.live_session_buffer_size)
        live_session_slot_alloc_pipe = multiprocessing.Pipe(False)
        live_session_slot_dealloc_pipe = multiprocessing.Pipe(False)
        live_session_locks = tuple((multiprocessing.Lock() for i in xrange(trafcap.live_session_buffer_size//SESSIONS_PER_LOCK)))

        saved_session_cursor_pipe = multiprocessing.Pipe(False)
        saved_session2_cursor_pipe = multiprocessing.Pipe(False)
        saved_session_ring_buffer = multiprocessing.RawArray(session_class, trafcap.saved_session_ring_buffer_size)
        saved_session2_ring_buffer = multiprocessing.RawArray(session_class, trafcap.saved_session_ring_buffer_size)

        group_updater_saved_session_count = multiprocessing.Value(ctypes.c_uint64)
        group_updater_saved_session_count.value = 0
        group2_updater_saved_session_count = multiprocessing.Value(ctypes.c_uint64)
        group2_updater_saved_session_count.value = 0

        group_buffer = multiprocessing.RawArray(group_class, trafcap.group_buffer_size)
        group2_buffer = multiprocessing.RawArray(group_class, trafcap.group2_buffer_size)
        capture_group_buffer = multiprocessing.RawArray(group_class, CAPTURE_GROUP_BUFFER_SIZE)
        capture_group2_buffer = multiprocessing.RawArray(group_class, CAPTURE_GROUP_BUFFER_SIZE)

        session_group_alloc_pipe = multiprocessing.Pipe(False)
        session_group_dealloc_pipe = multiprocessing.Pipe(False)
        capture_group_alloc_pipe = multiprocessing.Pipe(False)
        capture_group_dealloc_pipe = multiprocessing.Pipe(False)
        session_group2_alloc_pipe = multiprocessing.Pipe(False)
        session_group2_dealloc_pipe = multiprocessing.Pipe(False)
        capture_group2_alloc_pipe = multiprocessing.Pipe(False)
        capture_group2_dealloc_pipe = multiprocessing.Pipe(False)
        group_locks = tuple((multiprocessing.Lock() for i in xrange(trafcap.group_buffer_size//GROUPS_PER_LOCK)))
        capture_group_locks = tuple((multiprocessing.Lock() for i in xrange(CAPTURE_GROUP_BUFFER_SIZE//CAPTURE_GROUPS_PER_LOCK)))
        group2_locks = tuple((multiprocessing.Lock() for i in xrange(trafcap.group2_buffer_size//GROUPS_PER_LOCK)))
        capture_group2_locks = tuple((multiprocessing.Lock() for i in xrange(CAPTURE_GROUP_BUFFER_SIZE//CAPTURE_GROUPS_PER_LOCK)))

        group_updater_group_alloc_count = multiprocessing.Value(ctypes.c_uint64)
        group_updater_group_alloc_count.value = 0
        group2_updater_group_alloc_count = multiprocessing.Value(ctypes.c_uint64)
        group2_updater_group_alloc_count.value = 0
        group_updater_group_dealloc_count = multiprocessing.Value(ctypes.c_uint64)
        group_updater_group_dealloc_count.value = 0
        group2_updater_group_dealloc_count = multiprocessing.Value(ctypes.c_uint64)
        group2_updater_group_dealloc_count.value = 0

        group_updater_session_history_count = multiprocessing.Value(ctypes.c_uint64)
        group_updater_session_history_count.value = 0
        group2_updater_session_history_count = multiprocessing.Value(ctypes.c_uint64)
        group2_updater_session_history_count.value = 0

        group_keeper_group_alloc_count = multiprocessing.Value(ctypes.c_uint64)
        group_keeper_group_alloc_count.value = 0
        group2_keeper_group_alloc_count = multiprocessing.Value(ctypes.c_uint64)
        group2_keeper_group_alloc_count.value = 0
        group_keeper_group_dealloc_count = multiprocessing.Value(ctypes.c_uint64)
        group_keeper_group_dealloc_count.value = 0
        group2_keeper_group_dealloc_count = multiprocessing.Value(ctypes.c_uint64)
        group2_keeper_group_dealloc_count.value = 0

        packet_parser = multiprocessing.Process(target = packetParser, 
            args=(packet_cursor_pipe[1], parser_packet_count, 
                  packet_ring_buffer, 
                  ring_stats_recv, ring_stats_drop, proto_opts))
        session_updater = multiprocessing.Process(target = sessionUpdater, 
            args=(packet_cursor_pipe[0], session_updater_packet_count, 
                  packet_ring_buffer, live_session_buffer, live_session_locks, 
                  live_session_slot_alloc_pipe[1],  live_session_slot_dealloc_pipe[0], 
                  session_updater_live_session_alloc_count, session_updater_live_session_dealloc_count, 
                  proto_opts))
        session_keeper = multiprocessing.Process(target = sessionBookkeeper,
            args=(live_session_buffer, live_session_locks, 
                  live_session_slot_alloc_pipe[0], live_session_slot_dealloc_pipe[1], 
                  session_keeper_live_session_alloc_count, session_keeper_live_session_dealloc_count, 
                  saved_session_cursor_pipe[1], saved_session_ring_buffer, 
                  saved_session2_cursor_pipe[1], saved_session2_ring_buffer, 
                  session_keeper_saved_session_count, 
                  session_keeper_saved_session2_count, 
                  proto_opts))
        group_updater = multiprocessing.Process(target = groupUpdater,
            args=(saved_session_cursor_pipe[0], group_updater_saved_session_count, 
                  saved_session_ring_buffer, 
                  group_buffer, group_locks, 
                  session_group_alloc_pipe[1],  session_group_dealloc_pipe[0], 
                  group_updater_group_alloc_count, group_updater_group_dealloc_count, 
                  group_updater_session_history_count, 
                  capture_group_buffer, capture_group_locks, 
                  capture_group_alloc_pipe[1], capture_group_dealloc_pipe[0], 
                  proto_opts, <uint8_t>0))
        group_keeper = multiprocessing.Process(target = groupBookkeeper,
            args=(group_buffer, group_locks, 
                  session_group_alloc_pipe[0], session_group_dealloc_pipe[1], 
                  group_keeper_group_alloc_count, group_keeper_group_dealloc_count, 
                  capture_group_buffer, capture_group_locks, 
                  capture_group_alloc_pipe[0], capture_group_dealloc_pipe[1], 
                  proto_opts, <uint8_t>0))

        group2_updater = multiprocessing.Process(target = groupUpdater,
            args=(saved_session2_cursor_pipe[0], group2_updater_saved_session_count, 
                  saved_session2_ring_buffer, 
                  group2_buffer, group2_locks, 
                  session_group2_alloc_pipe[1],  session_group2_dealloc_pipe[0], 
                  group2_updater_group_alloc_count, group2_updater_group_dealloc_count, 
                  group2_updater_session_history_count, 
                  capture_group2_buffer, capture_group2_locks, 
                  capture_group2_alloc_pipe[1], capture_group2_dealloc_pipe[0], 
                  proto_opts, <uint8_t>1))
        group2_keeper = multiprocessing.Process(target = groupBookkeeper,
            args=(group2_buffer, group2_locks, 
                  session_group2_alloc_pipe[0], session_group2_dealloc_pipe[1], 
                  group2_keeper_group_alloc_count, group2_keeper_group_dealloc_count, 
                  capture_group2_buffer, capture_group2_locks, 
                  capture_group2_alloc_pipe[0], capture_group2_dealloc_pipe[1], 
                  proto_opts, <uint8_t>1))

        packet_parser.start()
        session_updater.start()
        session_keeper.start()
        group_updater.start()
        group_keeper.start()
        group2_updater.start()
        group2_keeper.start()

        prev_parser_packet_count = 0
        prev_session_updater_live_session_alloc_count = 0
        prev_group_updater_saved_session_count = 0
        prev_group2_updater_saved_session_count = 0
        loop_count = 0
        while main_running:
            time.sleep(1)
            #rsr = ring_stats_recv.value
            rsd = ring_stats_drop.value

            ppc = parser_packet_count.value
            pps = ppc - prev_parser_packet_count
            supc = session_updater_packet_count.value
            ppql = ppc - supc  # parser-to-updater q length
            
            ulsac = session_updater_live_session_alloc_count.value
            ulsps = ulsac - prev_session_updater_live_session_alloc_count
            klsac = session_keeper_live_session_alloc_count.value
            saql = ulsac - klsac  # allocate (updater-to-keeper) q length

            ulsdc = session_updater_live_session_dealloc_count.value
            klsdc = session_keeper_live_session_dealloc_count.value
            sdql = klsdc - ulsdc # deallocate (keeper-to-updater) q length
            klsc = klsac - klsdc # live session count

            kssc = session_keeper_saved_session_count.value
            gussc = group_updater_saved_session_count.value
            g2ussc = group2_updater_saved_session_count.value
            ssps = gussc - prev_group_updater_saved_session_count
            ss2ps = g2ussc - prev_group2_updater_saved_session_count
            ssql = kssc - gussc  # saved_session queue length
            gugac = group_updater_group_alloc_count.value
            g2ugac = group2_updater_group_alloc_count.value
            gugdc = group_updater_group_dealloc_count.value
            g2ugdc = group2_updater_group_dealloc_count.value
            gushc = group_updater_session_history_count.value
            g2ushc = group2_updater_session_history_count.value

            gkgac = group_keeper_group_alloc_count.value
            g2kgac = group2_keeper_group_alloc_count.value
            gkgdc = group_keeper_group_dealloc_count.value
            g2kgdc = group2_keeper_group_dealloc_count.value
            gklgc = gkgac - gkgdc # live group count
            g2klgc = g2kgac - g2kgdc # live group2 count
            gaql = gugac - gkgac # group allocate q length
            g2aql = g2ugac - g2kgac # group2 allocate q length
            gdql = gkgdc - gugdc # group de-allocate q length
            g2dql = g2kgdc - g2ugdc # group2 de-allocate q length

            prev_parser_packet_count = ppc
            prev_session_updater_live_session_alloc_count = ulsac
            prev_group_updater_saved_session_count = gussc 
            prev_group2_updater_saved_session_count = g2ussc 

            #print '{0:9d} {1:6d} > {2:3d} > {3:10d} {4:7d} > {5:4d}  {6:4d} < {7:8d} {8:7d}'.format(rsd, pps, ppql, supc, ulsps, saql, sdql, klsac, klsc)
            #if loop_count % 10 == 0:
            #    print '{0:>10}{1:>5}{2:>21}{3:>5}{4:>5}{5:^10}{6:>11}{7:>5}{8:>3}'.format('---parser:', parser.pid, '--     -----updater:', session_updater.pid, '---- ',loop_count,' ---keeper:',session_keeper.pid,'---')
            #    print '{0:>9} {1:>6}    {2:^3}  {3:>10} {4:>7}    {5:^4}   {6:^4} {7:>8} {8:>7}'.format('drop', 'pps', ' ', 'pkts', 'ulsps', ' ',' ', 'sess', 'live')
            #    global main_running
            #    if pps == 0: main_running = False

            if loop_count % 10 == 0:
                if loop_count % 20 != 0:
                    print '{0:>10}{1:>5}{2:>14}{3:>5}{4:>14}{5:>5}{6:>11}{7:>5}{8:>10}{9:>5}{10:>11}{11:>5}{12:>10}{13:>5}'.format(
                    '---parser:', packet_parser.pid, 
                    '--     -updtr:', session_updater.pid, 
                    '-        --kpr:', session_keeper.pid,
                    '-  -gUpdtr:',group_updater.pid,
                    '-   -gKpr:', group_keeper.pid,
                    '- -g2Updtr:',group2_updater.pid,
                    '-  -g2Kpr:', group2_keeper.pid)
                else:
                    print str(datetime.today().strftime("%a %m/%d/%y %H:%M:%S"))+' - - - - - d:h:m:s '+str(loop_count//86400)+':'+str((loop_count//3600)%24)+':'+str((loop_count//60)%60)+':'+str(loop_count%60)+' - - - - - gUpdtrSessHist: '+str(gushc)+' - - - - - g2UpdtrSessHist: '+str(g2ushc)
                print start_bold,
                #print '{0:>8} {1:>6} {2:^4}  {3:>7}  {4:^4}__{5:^4}  {6:>7} {7:^4}  {8:>7} {9:^4}  {10:^4} {11:>8} {12:>7} {13:^4}  {14:^4} {15:>8}'.format(
                #      'drop', 'pps',   ' ', 'lsps',   '',    ' ', 'liveSns', ' ',  'ssps',  ' ',    ' ', 'liveGrps', 'ss2ps', ' ', ' ', 'liveGrps2'),

                    #       0  55114  422>     669  426>     0<  769487    0>    2783    0>    0<   42088     839    0>    0<   87193
                hdr='    drop    pps .....    lsps ............ liveSns .....    ssps ...........  lvGrps   ss2ps ........... lvGrps2'
                print hdr,
                print end_bold

            print '{0:9d} {1:6d} {2:4d}> {3:7d} {4:4d}>  {5:4d}< {6:7d} {7:4d}> {8:7d} {9:4d}> {10:4d}< {11:7d} {12:7d} {13:4d}> {14:4d}< {15:7d}'.format(
                    rsd,   pps,   ppql,  ulsps,  saql,    sdql,   klsc,  ssql,   ssps,  gaql,    gdql,   gklgc, ss2ps, g2aql, g2dql, g2klgc)

            loop_count += 1
            sys.stdout.flush()

        # Handle shutdown 
        packet_parser.join(1)
        session_updater.join(1)
        session_keeper.join(1)
        group_updater.join(1)
        group_keeper.join(1)
        group2_updater.join(1)
        group2_keeper.join(1)
        
        # Just in case...
        time.sleep(1)
        if packet_parser.is_alive(): 
            print 'parser still alive...';sys.stdout.flush()
            packet_parser.terminate()
        if session_updater.is_alive(): 
            print 'updater still alive...';sys.stdout.flush()
            #session_updater.terminate()
        if session_keeper.is_alive(): 
            print 'keeper still alive...';sys.stdout.flush()
            #session_keeper.terminate()
        if group_updater.is_alive(): 
            print 'group_updater still alive...';sys.stdout.flush()
            #group_updater.terminate()
        if group_keeper.is_alive(): 
            print 'group_keeper still alive...';sys.stdout.flush()
            #group_keeper.terminate()
        if group2_updater.is_alive(): 
            print 'group2_updater still alive...';sys.stdout.flush()
            #group2_updater.terminate()
        if group2_keeper.is_alive(): 
            print 'group2_keeper still alive...';sys.stdout.flush()
            #group2_keeper.terminate()

    else:
        # Original, uni-process ingest

        # Select protocol.  Note that packet_type variable must be set
        if options.tcp:
            packet_type = "TcpPacket"
            session_info_collection_name = "tcp_sessionInfo"
            session_bytes_collection_name = "tcp_sessionBytes"
            capture_info_collection_name = "tcp_captureInfo"
            capture_bytes_collection_name = "tcp_captureBytes"
        elif options.udp:
            packet_type = "UdpPacket"
            session_info_collection_name = "udp_sessionInfo"
            session_bytes_collection_name = "udp_sessionBytes"
            capture_info_collection_name = "udp_captureInfo"
            capture_bytes_collection_name = "udp_captureBytes"
        elif options.icmp:
            packet_type = "IcmpPacket"
            session_info_collection_name = "icmp_sessionInfo"
            session_bytes_collection_name = "icmp_sessionBytes"
            capture_info_collection_name = "icmp_captureInfo"
            capture_bytes_collection_name = "icmp_captureBytes"
        elif options.other:
            packet_type = "OtherPacket"
            session_info_collection_name = "oth_sessionInfo"
            session_bytes_collection_name = "oth_sessionBytes"
            capture_info_collection_name = "oth_captureInfo"
            capture_bytes_collection_name = "oth_captureBytes"
        elif options.rtp:
            packet_type = "RtpPacket"
            session_info_collection_name = "rtp_sessionInfo"
            session_bytes_collection_name = "rtp_sessionBytes"
            capture_info_collection_name = "rtp_captureInfo"
            capture_bytes_collection_name = "rtp_captureBytes"
        else:
           exitNowUni('Invalid protocol') 

        # A python class is defined for each protocol (TCP, UDP, ...) and  
        # each class encapsulates packet-specific information
        pc = eval(packet_type)

        if options.other:
            container = eval("TrafcapEthPktContainer")
        else:
            container = eval("TrafcapIpPktContainer")
            
        session = container(pc, session_info_collection_name, 
                                session_bytes_collection_name, "session")
         
        capture = container(pc, capture_info_collection_name, 
                                capture_bytes_collection_name, "capture")


        def catchSignal1(signum, stac):
            num_sessions = len(session.info_dict)
            print "\n", num_sessions, " active sessions_info entries:"
            for k in session.info_dict:
                print "   ",
                print session.info_dict[k]
            print " "
            print capture.info_dict[pc.capture_dict_key]
            if num_sessions >= 1:
                print num_sessions, " active session_info entries displayed."

        def catchSignal2(signum, stack):
            num_sessions = len(session.bytes_dict)
            print "\n", num_sessions, " active sessions byte entries:"
            for k in session.bytes_dict:
                print "   ",
                print session.bytes_dict[k]
            print " "
            print capture.bytes_dict[pc.capture_dict_key]
            if num_sessions >= 1:
                print num_sessions, " active session_byte entries displayed."

        def catchCntlC(signum, stack):
            exitNowUni('')

        signal.signal(signal.SIGUSR1, catchSignal1)
        signal.signal(signal.SIGUSR2, catchSignal2)
        signal.signal(signal.SIGINT, catchCntlC)
        signal.signal(signal.SIGTERM, catchCntlC)

        # Pre-build the sessionInfo dictionary for more more efficient db writes
        print "Pre-building dictionaries..."
        oldest_session_time = int(time.time()) - trafcap.session_expire_timeout

        # sessionInfo dictionary
        info_cursor = session.db[session.info_collection].find( \
                                 {'tem':{'$gte':oldest_session_time}})

        for a_doc in info_cursor:
            key, data = pc.parse(None, a_doc)
            session.updateInfoDict(key, data, 0, 0)
            # Add packet, end time, and _id fields  - not done by updateInfoDict method
            session.info_dict[key][pc.i_te] = a_doc['te']
            session.info_dict[key][pc.i_pkts] = a_doc['pk']
            session.info_dict[key][pc.i_id] = a_doc['_id']
            session.info_dict[key][pc.i_csldw] = False 
        #catchSignal1(None, None)

        proc = pc.startSniffer()

        # make stdout a non-blocking file - not sure if this is required 
        import fcntl  
        fd = proc.stdout.fileno() 
        fl = fcntl.fcntl(fd, fcntl.F_GETFL) 
        fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK) 

        std_in = [fd]
        std_out = []
        std_err = []

        the_buffer=''                        # stores partial lines between reads  
        inputready = None
        outputready = None
        exceptready = None

        #
        # Begin main loop
        #
        select_loop_counter = 0.
        select_wait = 0.01
        while True:
            try:
                # Timeout of 0.0 seconds for non-blocking I/O causes 100% CPU usage
                inputready,outputready,exceptready = select(std_in,std_out,std_err,
                                                            select_wait)
            except Exception, e:
                # This code path is followed when a signal is caught
                if e[0] != 4:        # Excetion not caused by USR1 and USR2 signals 
                    trafcap.logException(e, inputready=inputready,
                                            outputready=outputready,
                                            exceptready=exceptready)
                    continue

            if exceptready:
                print "Something in exceptready..."
                print exceptready

            if std_err:
                print "Something in std_err..."
                print std_err

            # Update current_time approx once per second.  Current_time used to decide
            # when to write dictionary items to db so high precision not needed.
            select_loop_counter += select_wait
            if select_loop_counter >= 1.:
                trafcap.current_time = time.time()
                select_loop_counter = 0.
         
            # No data to be read.  Use this time to update the database.
            if not inputready:

                session.updateDb()
                
                capture.updateDb()

                if not options.quiet: print "\rActive: ", len(session.info_dict), \
                                            ", ", len(session.bytes_dict), "\r",
                sys.stdout.flush()
           
            else:
                # Process data waiting to be read 
                try:
                    # Explicitly cohersing to string, was implicit in python2
                    raw_data = (os.read(std_in[0],trafcap.bytes_to_read)).decode('ascii')
                except OSError:
                    # This exception occurs if signal handled during read
                    continue
                the_buffer += raw_data
                if '\n' in raw_data:
                    tmp = the_buffer.split('\n')
                    lines, the_buffer = tmp[:-1], tmp[-1] 
                else:
                    # not enough data has been read yet to make a full line 
                    lines = "" 
         
                for a_line in lines: 
                    try:
                        # Handle empty lines
                        if not a_line: continue

                        # Handle traffic that tcpdump parses automatically
                        #   TCP port 139 - NBT Session Packet: Unknown packet type 0x68Data
                        #   [000] 00 10 47 00 E8 EC 23 00  00 68 BC 85 40 00 68 08  \0x00\0x10G\0x00\0xe8\0xec#\0x00 \0x00h\0xbc\0x85@\0x00h\0x08
                        if a_line[0] == "[":
                            continue

                        line = a_line.split()
         
                        # Handle garbage lines / bad tcpdump output
                        if len(line) <= 4: continue

                        # For debug
                        #print line
                        key, data = pc.parse(line, None)

                        # parsing problem can sometimes cause    (),[]   to be returned
                        if data == []:
                            continue

                    except Exception, e:
                        # Something went wrong with parsing the line. Save for analysis
                        if not options.quiet:
                            print e
                            print "\n-------------line------------------\n"
                            print line
                            print "\n-------------lines------------------\n"
                            print lines
                            print "\n-------------buffer------------------\n"
                            print the_buffer
                            print traceback.format_exc()
           
                        trafcap.logException(e, line=line, lines=lines, 
                                                the_buffer=the_buffer)
                        continue     
          
                    # timestamp is always first item in the list
                    curr_seq = int(data[pc.p_etime].split(".")[0])
                    trafcap.last_seq_off_the_wire = curr_seq

                    # For session dicts, last two params are 0
                    session.updateInfoDict(key, data, 0, 0) 
                    session.updateBytesDict(key, data, curr_seq, 0, 0)

                    inbound_bytes, outbound_bytes = pc.findInOutBytes(data)

                    #print key
                    #print data
                    si = session.info_dict[key]
                    #print si
                    #print si[pc.i_ip1:pc.i_id+1]
                    #print si[pc.i_circ_bufr]
                    sb = session.bytes_dict[key]
                    #print sb
                    #print sb[pc.b_key:pc.b_se+1]
                    #print sb[pc.b_byt_ary]
                    #print sb[pc.b_lpj_ary]
                    #print sb[pc.b_r_sub_i:pc.b_csldw+1]
                    #print ''

                    capture.updateInfoDict(pc.capture_dict_key, data, inbound_bytes, 
                                                                      outbound_bytes)
                    #print capture.info_dict[pc.capture_dict_key]
                    #print ''

                    capture.updateBytesDict(pc.capture_dict_key, data, curr_seq,
                                                        inbound_bytes, outbound_bytes) 

                    #print capture.bytes_dict[pc.capture_dict_key]
                    #print ''
                    #continue

                if not options.quiet: 
                    print "\rActive: ", len(session.info_dict), ", ", \
                          len(session.bytes_dict), "\r",
                sys.stdout.flush()

        exitNowUni('')
        
if __name__ == "__main__":
    main()
