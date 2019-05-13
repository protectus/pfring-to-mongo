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
from trafcap import trafcap
from trafcap.trafcapIpPacket import *
#from trafcapEthernetPacket import *
#from trafcapContainer import *
from trafcap.kwEvent import *
from trafcap.kwEventContainer import *
from trafcap import trafinj
from trafcap.ImpactPacket import IP, TCP

proc = None

trafcap.checkIfRoot()
db = trafcap.mongoSetup()

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
    #parser.add_option("-u", "--udp", dest="udp",
    #                  action="store_true", default=False,
    #                  help="process udp traffic")
    #parser.add_option("-i", "--icmp", dest="icmp",
    #                  action="store_true", default=False,
    #                  help="process icmp traffic")
    #parser.add_option("-o", "--other", dest="other",
    #                  action="store_true", default=False,
    #                  help="process other traffic")
    #parser.add_option("-r", "--rtp", dest="rtp",
    #                  action="store_true", default=False,
    #                  help="process rtp traffic")
    (options, args) = parser.parse_args()
    return options
 
def exitNow(message):
    # Kill the childprocess sniffing packets
    print("Exiting...")
    if proc:
        os.kill(proc.pid, signal.SIGTERM)
    sys.exit(message)

def main():

    options = parseOptions()     # Could combine this line with next line
    trafcap.options = options

    cc_list_type = trafcap.cc_list_type
    cc_list = trafcap.cc_list

    option_check_counter = 0
    if options.tcp: option_check_counter += 1
    #if options.udp: option_check_counter += 1
    #if options.icmp: option_check_counter += 1
    #if options.other: option_check_counter += 1
    #if options.rtp: option_check_counter += 1
    if option_check_counter != 1:
        sys.exit("Must use -t to specify a protocol.")
        #sys.exit("Must use one of -t, -u, -i, or -o to specify a protocol.")

    # Select protocol.  Note that packet_type variable must be set
    if options.tcp:
        #event_type = "TcpInjEvent"
        packet_type = "TcpInjPacket"
        event_info_collection_name = "tcp_injInfo"
        event_count_collection_name = None 
        event_container = eval('TcpInjEventContainer')
        pc = eval(packet_type)
        #ec = eval(event_type)
        inj_events = event_container(pc, event_info_collection_name,
                                     event_count_collection_name, "session")
        #ids_capture = container(pc, capture_info_collection_name,
        #                        capture_count_collection_name, "capture")

    else:
       exitNow('Invalid protocol') 

    blocked_ip = inj_events.blocked_ip
    blocked_info = inj_events.blocked_info

    # Open a raw socket to inject packets.
    a_socket=socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    a_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    def catchSignal1(signum, stac):
        num_blocks = len(blocked_ip)
        print("\n", num_blocks, " active blocked_ip entries:")
        for k in blocked_ip:
            print("   ", end=' ')
            print(k, blocked_ip[k])
        print(" ")

    def catchSignal2(signum, stack):
        num_sessions = len(blocked_info)
        print("\n", num_sessions, " active blocked_info entries:")
        for k in blocked_info:
            print("   ", end=' ')
            print(blocked_info[k])
        print(" ")

    def catchCntlC(signum, stack):
        exitNow('')

    signal.signal(signal.SIGUSR1, catchSignal1)
    signal.signal(signal.SIGUSR2, catchSignal2)
    signal.signal(signal.SIGINT, catchCntlC)
    signal.signal(signal.SIGTERM, catchCntlC)

    proc = pc.startSniffer()

    # make stdout a non-blocking file - not sure if this is required 
    import fcntl  
    fd = proc.stdout.fileno() 
    fl = fcntl.fcntl(fd, fcntl.F_GETFL) 
    fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK) 

    std_in = [fd]
    std_out = []
    std_err = []

    the_buffer=b''                        # stores partial lines between reads  
    inputready = None
    outputready = None
    exceptready = None

    ip = IP()
    tcp = TCP()

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
        except Exception as e:
            # This code path is followed when a signal is caught
            if e[0] != 4:        # Excetion not caused by USR1 and USR2 signals 
                trafcap.logException(e, inputready=inputready,
                                        outputready=outputready,
                                        exceptready=exceptready)
                continue

        if exceptready:
            print("Something in exceptready...")
            print(exceptready)

        if std_err:
            print("Something in std_err...")
            print(std_err)

        # Update current_time approx once per second.  Used to decide
        # when to write dictionary items to db so high precision not needed.
        select_loop_counter += select_wait
        if select_loop_counter >= 1.:
            trafcap.current_time = time.time()
            select_loop_counter = 0.
     
        # No data to be read.  Use this time to update the database.
        if not inputready:

            # Update mongo with inject events stored in blocked_info
            inj_events.updateDb()

            # Manage mongo IP list every minute
            if select_loop_counter == 0:
                #print 'Managing mongo ip list...', trafcap.current_time

                # Expire IPs from blocked_ip dict after timeout
                # List of keys (ip tuples) for expired IPs in blocked_ip dict is returned
                expired_ip_list = inj_events.expireIp()

                # For IPs expired from dict, remove them from mongo IP collection
                for an_ip in expired_ip_list:
                    if not options.quiet: print('Removing from mongo: ', an_ip)
                    trafinj.unBlockIp(trafcap.tupleToInt(an_ip))
    
                # Update mongo IP collection with any new blocked_ip IPs 
                for an_ip in blocked_ip:
                    #print 'inj2mongo blocked_ip contains: ', an_ip
                    if not blocked_ip[an_ip][2]:
                        if not options.quiet: print('Adding to mongo: ', an_ip)
                        trafinj.blockIp(trafcap.tupleToInt(an_ip), trafcap.inj_timeout)
                        blocked_ip[an_ip][2] = True
    
                # Sync blocked_ip dict from mongo IP collection.
                # This is how other mechanisms can add IPs to be blocked.

                # List of current IPs in mongo.  In tuple format for easy comparison.  Rebuilt 
                # every time so IPs manually removed from mongo can be identified.
                blocked_ip_list_from_mongo = [] 
                ip_to_pop = []
                blocked_ip_docs_from_mongo = trafinj.getBlockedIp()

                # Add new IPs in mongo to python dict
                for a_doc in blocked_ip_docs_from_mongo:
                    ip_t = trafcap.intToTuple(a_doc['ip'])
                    blocked_ip_list_from_mongo.append(ip_t)
                    #print ip_t, ' is on the mongo blocked_ip list...'
                    if not ip_t in blocked_ip:
                        blocked_ip[ip_t] = [a_doc['tb'], a_doc['texp'], True]
                        if not options.quiet: print(ip_t, ' added to inj2mongo blocked_ip dict')

                # Remove from blocked_ip any IP manually unblocked (removed from tcp_injIP coll'n)
                for an_ip in blocked_ip:
                    if not an_ip in blocked_ip_list_from_mongo:
                        ip_to_pop.append(an_ip)    

                for an_ip in ip_to_pop:
                    blocked_ip.pop(an_ip)
                    if not options.quiet: print(an_ip, ' removed from inj2mongo blocked_ip dict')

            if not options.quiet:
                print("\rActive: ", len(blocked_ip), ", ", \
                      len(blocked_info), "\r", end=' ')
            sys.stdout.flush()

        else:
            # Process data waiting to be read 
            try:
                raw_data = os.read(std_in[0],trafcap.bytes_to_read)
            except OSError:
                # This exception occurs if signal handled during read
                continue
            the_buffer += raw_data
            if b'\n' in raw_data:
                tmp = the_buffer.split(b'\n')
                lines, the_buffer = tmp[:-1], tmp[-1] 
            else:
                # not enough data has been read yet to make a full line 
                lines = b"" 
     
            for a_line in lines: 
                try:
                    # Handle empty lines
                    if not a_line: continue

                    # Handle traffic that tcpdump parses automatically
                    #   TCP port 139 - NBT Session Packet:
                    #                  Unknown packet type 0x68Data
                    #   [000] 00 10 47 00 E8 EC 23 00  00 68 BC 85 40 00 68 08
                    #   \0x00\0x10G\0x00\0xe8\0xec#\0x00 
                    #   \0x00h\0xbc\0x85@\0x00h\0x08
                    if a_line[0] == b"[":
                        continue

                    line = a_line.split()
     
                    # Handle garbage lines / bad tcpdump output
                    if len(line) <= 4: continue

                    # For debug
                    #print line
                    key, data = pc.parse(line, None)

                    # parsing problem can sometimes cause (),[] to be returned
                    if data == []:
                        continue

                    # This serves both as a flag to indicate an injected pkt 
                    # needs to be logged and which IP caused the block 
                    log_inject_addr_index = None
                    cc=loc=None

                    # IP1 in IP_block_list:
                    if data[pc.p_addr][0] in blocked_ip: 
                        pc.injectB2G(data, a_socket, ip, tcp)
                        log_inject_addr_index = 0

                    # IP2 in IP_block_list:
                    elif data[pc.p_addr][1] in blocked_ip: 
                        pc.injectG2B(data, a_socket, ip, tcp)
                        log_inject_addr_index = 1 
                        # swap key order for consistent logging
                        key = (key[1], key[0])

                    # Config'ed to allow certain CC's, ensure IP is not on whitelist (i.e. allow-list) 
                    elif (cc_list_type == 'allow') and (not trafinj.isIpAllowed(data[pc.p_addr][0],db)):
                        cc,name,loc,city,region=trafcap.geoIpLookupTpl(data[pc.p_addr][0])
                        if cc not in cc_list:
                            #print 'case 1...', cc, cc_list, cc_list_type
                            #sys.exit()
                            pc.injectB2G(data, a_socket, ip, tcp)
                            # Add ip to blocked list to avoid CC lookup on next packet 
                            # False flag means this IP not yet written to the db
                            blocked_ip[data[pc.p_addr][0]] = [data[pc.p_etime], 
                                                              data[pc.p_etime] + trafcap.inj_timeout, 
                                                              False]
                            log_inject_addr_index = 0
                        else:
                            cc,name,loc,city,region=trafcap.geoIpLookupTpl(data[pc.p_addr][1])
                            if cc not in cc_list:
                                #print 'case 2...', cc, cc_list, cc_list_type
                                #sys.exit()
                                pc.injectG2B(data, a_socket, ip, tcp)
                                # Add ip to blocked list to avoid CC lookup on next packet 
                                blocked_ip[data[pc.p_addr][1]] = [data[pc.p_etime], 
                                                                  data[pc.p_etime] + trafcap.inj_timeout, 
                                                                  False]
                                log_inject_addr_index = 1
                                # swap key order for consistent logging
                                key = (key[1], key[0])

                    # Config'ed to block certain CC's, ensure IP is not on whitelist (i.e. allow-list) 
                    elif (cc_list_type == 'block') and (not trafinj.isIpAllowed(data[pc.p_addr][0],db)):
                        # Check tcp_injAllowIp here............
                        cc,name,loc,city,region=trafcap.geoIpLookupTpl(data[pc.p_addr][0])
                        if cc in cc_list:
                            pc.injectB2G(data, a_socket, ip, tcp)
                            # Add ip to blocked list to avoid CC lookup on next packet 
                            blocked_ip[data[pc.p_addr][0]] = [data[pc.p_etime], 
                                                              data[pc.p_etime] + trafcap.inj_timeout, 
                                                              False]
                            log_inject_addr_index = 0
                        else:
                            cc,name,loc,city,region=trafcap.geoIpLookupTpl(data[pc.p_addr][1])
                            if cc in cc_list:
                                pc.injectG2B(data, a_socket, ip, tcp)
                                # Add ip to blocked list to avoid CC lookup on next packet 
                                blocked_ip[data[pc.p_addr][1]] = [data[pc.p_etime], 
                                                                  data[pc.p_etime] + trafcap.inj_timeout, 
                                                                  False]
                                log_inject_addr_index = 1
                                # swap key order for consistent logging
                                key = (key[1], key[0])

                    # Update dictionary
                    if log_inject_addr_index is not None:
                        try:
                            blocked_info[key][pc.i_te]=data[pc.p_etime]
                            blocked_info[key][pc.i_pkts] += 1 
                            blocked_info[key][pc.i_csldw] = True

                        except KeyError:
                            asn, org = trafcap.geoIpAsnLookupTpl(key[log_inject_addr_index][0])
                            blocked_info[key] = [key[0][0], 
                                                 key[1][0], 
                                                 key[0][1],
                                                 key[1][1],
                                                 log_inject_addr_index,
                                                 data[pc.p_etime],      # tb
                                                 data[pc.p_etime],      # te
                                                 1,                     # pkt count
                                                 data[pc.p_etime],      # ldwt
                                                 True,                  # csldw
                                                 cc, loc,
                                                 asn,
                                                 None]                  # _id

                    #curr_seq = int(data[pc.p_etime].split(".")[0])
                    #trafcap.last_seq_off_the_wire = curr_seq

                    log_inject_addr_index = None

                except Exception as e:
                    # Something went wrong parsing the line. Save for analysis
                    if not options.quiet:
                        print(e)
                        print("\n-------------line------------------\n")
                        print(line)
                        print("\n-------------lines------------------\n")
                        print(lines)
                        print("\n-------------buffer------------------\n")
                        print(the_buffer)
                        print(traceback.format_exc())
       
                    trafcap.logException(e, line=line, lines=lines, 
                                            the_buffer=the_buffer)
                    continue     

            if not options.quiet:
                print("\rActive: ", len(blocked_ip), ", ", \
                      len(blocked_info), "\r", end=' ')
            sys.stdout.flush()

    exitNow('')

if __name__ == "__main__":
    main()
