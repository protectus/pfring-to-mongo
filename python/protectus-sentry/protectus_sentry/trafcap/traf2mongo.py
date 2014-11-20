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
from trafcapIpPacket import *
from trafcapEthernetPacket import *
from trafcapContainer import *
import multiprocessing

#proc = None

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
    (options, args) = parser.parse_args()
    return options
 
def exitNow(message):
    # Kill the childprocess sniffing packets
    print "Exiting..."
    if proc:
        os.kill(proc.pid, signal.SIGTERM)
    sys.exit(message)

def OLDmain():
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
       exitNow('Invalid protocol') 

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


    def catchSignal1(signum, stack):
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
        exitNow('')

    signal.signal(signal.SIGUSR1, catchSignal1)
    signal.signal(signal.SIGUSR2, catchSignal2)
    signal.signal(signal.SIGINT, catchCntlC)
    signal.signal(signal.SIGTERM, catchCntlC)

    # Pre-build the sessionInfo dictionary for more more efficient db writes
    print "Pre-building dictionaries..."
    oldest_session_time = int(time.time()) - trafcap.session_expire_timeout

    # sessionInfo dictionary
    info_cursor = session.db[session.info_collection].find( \
                             spec = {'tem':{'$gte':oldest_session_time}})

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
                raw_data = os.read(std_in[0],trafcap.bytes_to_read)
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

    exitNow('')

parse_running = True
def parse(q, pc):
    def parseCatchCntlC(signum, stack):
        print 'Caught CntlC in parse...'
        global parse_running
        parse_running = False

    signal.signal(signal.SIGINT, parseCatchCntlC)

    proc = pc.startSniffer()

    # to make stdout non-blocking 
    #import fcntl  
    #fd = proc.stdout.fileno() 
    #fl = fcntl.fcntl(fd, fcntl.F_GETFL) 
    #fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK) 

    while parse_running:
        try:
            #for pkt in proc.stdout:  # blocks - not sure why
            pkt = proc.stdout.readline()
            q.put(pkt)

        except IOError:
            # Exception occurs if signal handled during read
            print "Exception in parse loop...", parse_running
            #time.sleep(1)
            continue

    # kill sniffer
    if proc:
        os.kill(proc.pid, signal.SIGTERM)


ingest_running = True
def ingest(q, pc, options, session, capture):
    def ingestCatchCntlC(signum, stack):
        print 'Caught CntlC in ingest...'
        global ingest_running
        ingest_running = False

    signal.signal(signal.SIGINT, ingestCatchCntlC)
    ### Need to handle this functionality somhow without a select loop
    # Update current_time approx once per second.  Current_time used to decide
    # when to write dictionary items to db so high precision not needed.
    #select_loop_counter += select_wait
    #if select_loop_counter >= 1.:
    #    trafcap.current_time = time.time()
    #    select_loop_counter = 0.
    while ingest_running:
        #time.sleep(1)
        try:
            pkt = q.get()   # Blocks if queue is empty
            key, data = pc.parse(pkt.split(), None)
        except IOError:
            # Exception occurs if signal handled during get
            continue
        except Exception, e:
            # Something went wrong with parsing the line. Save for analysis
            if not options.quiet:
                print e
                print "\n-------------pkt------------------\n"
                print pkt 
                print traceback.format_exc()
      
            trafcap.logException(e, pkt=pkt)
            continue     

        # parsing problem can sometimes cause (),[] to be returned
        if data == []: continue

        # timestamp is always first item in the list
        curr_seq = int(data[pc.p_etime].split(".")[0])
        trafcap.last_seq_off_the_wire = curr_seq

        # For session dicts, last two params are 0
        session.updateInfoDict(key, data, 0, 0) 
        session.updateBytesDict(key, data, curr_seq, 0, 0)

        inbound_bytes, outbound_bytes = pc.findInOutBytes(data)

        si = session.info_dict[key]
        sb = session.bytes_dict[key]
        capture.updateInfoDict(pc.capture_dict_key, data, inbound_bytes, 
                                                          outbound_bytes)
        capture.updateBytesDict(pc.capture_dict_key, data, curr_seq,
                                            inbound_bytes, outbound_bytes) 

        if not options.quiet: 
            print "\rActive: ", len(session.info_dict), ", ", \
                   len(session.bytes_dict), "\r",
            sys.stdout.flush()



main_running = True
def main():
    # The main function is responsible for setting up and kicking off the parse
    # function and the ingest function.  It tries to be responsible for all
    # interupts, fatal errors, and cleanup.

    #TODO: Options processing should probably go here, as well as interrupt code.
    options = parseOptions()     # Could combine this line with next line
    trafcap.options = options
    running = True

    option_check_counter = 0
    if options.tcp: option_check_counter += 1
    if options.udp: option_check_counter += 1
    if options.icmp: option_check_counter += 1
    if options.other: option_check_counter += 1
    if options.rtp: option_check_counter += 1
    if option_check_counter != 1:
        sys.exit("Must use one of -t, -u, -i, or -o to specify a protocol.")

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
       exitNow('Invalid protocol') 

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

    # Pre-build the sessionInfo dictionary for more more efficient db writes
    print "Pre-building dictionaries..."
    oldest_session_time = int(time.time()) - trafcap.session_expire_timeout

    # sessionInfo dictionary
    info_cursor = session.db[session.info_collection].find( \
                             spec = {'tem':{'$gte':oldest_session_time}})

    for a_doc in info_cursor:
        key, data = pc.parse(None, a_doc)
        session.updateInfoDict(key, data, 0, 0)
        # Add packet, end time, and _id fields  - not done by updateInfoDict method
        session.info_dict[key][pc.i_te] = a_doc['te']
        session.info_dict[key][pc.i_pkts] = a_doc['pk']
        session.info_dict[key][pc.i_id] = a_doc['_id']
        session.info_dict[key][pc.i_csldw] = False 

    parsed_packets = multiprocessing.Queue(maxsize=100000)
    parser = multiprocessing.Process(target = parse, 
                                     args=(parsed_packets,pc,))
    ingester = multiprocessing.Process(target = ingest, 
                                       args=(parsed_packets,pc,options,session,capture,))

    ingester.start()
    parser.start()

    while main_running:
        time.sleep(5)
        print 'Q len: ', parsed_packets.qsize()

    # Handle shutdown -- send signals?
    parser.join()
    ingester.join()


if __name__ == "__main__":
    main()
