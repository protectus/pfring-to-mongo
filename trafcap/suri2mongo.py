#!/usr/bin/python
#
# Copyright (c) 2013 Protectus,LLC.  All Rights Reserved.
#
from select import select
import socket
import signal
import subprocess
import sys, time, os
from datetime import datetime
from optparse import OptionParser
import math
import traceback

from trafcap import trafcap
from trafcap.kwEvent import *
from trafcap.kwEventContainer import *
import binascii

proc = None
trafcap.checkIfRoot()

def parseOptions():
    usage = "usage: %prog -i|w [-mq]"
    parser = OptionParser(usage)
    parser.add_option("-i", "--ids", dest="ids",
                      action="store_true", default=False,
                      help="process ids events")
    # -h option is used by --help and is not available
    parser.add_option("-w", "--http", dest="http",
                      action="store_true", default=False,
                      help="process web / http requests")
    parser.add_option("-m", "--mongo", dest="mongo",
                      action="store_true", default=False,
                      help="write to mongo")
    parser.add_option("-q", "--quiet", dest="quiet",
                      action="store_true", default=False,
                      help="don't print status to stdout")
    (options, args) = parser.parse_args()
    return options

def main():
    trafcap.options = options = parseOptions()

    option_check_counter = 0
    if options.ids: option_check_counter += 1
    if options.http: option_check_counter += 1
    if option_check_counter == 0:
        sys.exit("Must use at least one of -i or -h to specify a event type.")

    # for select loop
    std_in = []
    std_out = []
    std_err = []


    # Select protocol.  Note that packet_type variable must be set
    if options.ids:
        packet_type = "IdsEvent"
        event_info_collection_name = "ids_eventInfo"        # not used
        event_count_collection_name = "ids_eventCount"
        capture_info_collection_name = "ids_captureInfo"
        capture_count_collection_name = "ids_captureCount"
        container = eval("IdsEventContainer")
        pc = eval(packet_type)
        ids_events = container(pc, event_info_collection_name, 
                               event_count_collection_name, "session")
        ids_capture = container(pc, capture_info_collection_name, 
                                capture_count_collection_name, "capture")
        # create socket to ingest ids events
        subprocess.call(['/bin/rm', '-f', '/run/ids2m_sock'], bufsize=-1, 
                                                              stdout=None)
        ids_socket = socket.socket( socket.AF_UNIX, socket.SOCK_DGRAM )
        ids_socket.bind('/run/ids2m_sock')
        ids_fd = ids_socket.fileno()
        std_in.append(ids_fd)

    if options.http:
        packet_type = "HttpEvent"
        event_info_collection_name = "http_eventInfo"
        event_count_collection_name = None 
        #event_count_collection_name = "http_eventCount"
        #capture_info_collection_name = "http_captureInfo"
        #capture_count_collection_name = "http_captureCount"
        container = eval("HttpEventContainer")
        pc = eval(packet_type)
        http_events = container(pc, event_info_collection_name, 
                                event_count_collection_name, "session")
        #http_capture = container(pc, event_info_collection_name, 
        #                         event_count_collection_name, "capture")
        # create socket to ingest http events
        subprocess.call(['/bin/rm', '-f', '/run/http2m_sock'], bufsize=-1, 
                                                               stdout=None)
        http_socket = socket.socket( socket.AF_UNIX, socket.SOCK_DGRAM )
        http_socket.bind("/run/http2m_sock")
        http_fd = http_socket.fileno()
        std_in.append(http_fd)

    def exitNow(message):
        # Kill the childprocess sniffing packets
        print("Shutting down suricata...")
        proc = eval('SuricataEvent').initStream('stop')

        sys.stdout.write("Closing socket...")
        sys.stdout.flush()
        if options.ids:
            ids_socket.shutdown(socket.SHUT_RDWR)
            ids_socket.close()
            subprocess.call(['/bin/rm', '-f', '/run/ids2m_sock'], bufsize=-1, 
                                                                  stdout=None)
        if options.http:
            http_socket.shutdown(socket.SHUT_RDWR)
            http_socket.close()
            subprocess.call(['/bin/rm', '-f', '/run/http2m_sock'], bufsize=-1, 
                                                                   stdout=None)

        sys.exit(message)

    def catchSignal1(signum, stac):
        #num_sessions = len(session.info_dict)
        #print "\n", num_sessions, " active sessions_info entries:"
        #for k in session.info_dict:
        #    print "   ",
        #    print session.info_dict[k]
        #print " "
        #print capture.info_dict[pc.capture_dict_key]
        #if num_sessions >= 1:
        #    print num_sessions, " active session_info entries displayed."
        pass

    def catchSignal2(signum, stack):
        #num_sessions = len(session.bytes_dict)
        #print "\n", num_sessions, " active sessions byte entries:"
        #for k in session.bytes_dict:
        #    print "   ",
        #    print session.bytes_dict[k]
        #print " "
        #print capture.bytes_dict[pc.capture_dict_key]
        #if num_sessions >= 1:
        #    print num_sessions, " active session_byte entries displayed."
        pass

    def catchCntlC(signum, stack):
        exitNow('')

    signal.signal(signal.SIGUSR1, catchSignal1)
    signal.signal(signal.SIGUSR2, catchSignal2)
    signal.signal(signal.SIGINT, catchCntlC)
    signal.signal(signal.SIGTERM, catchCntlC)

    ids_buffer = ''; http_buffer = ''   # stores partial reads
    inputready = None; outputready = None; exceptready = None

    print('Stopping Suricata...')
    proc = SuricataEvent.initStream('stop')
    print('Starting Suricata...')
    proc = SuricataEvent.initStream('start')

    # classification.config, from suricata github source, provided by sentry-suricata package
    class_file='/etc/suricata/classification.config'
    trafcap.classification_config_dict = SuricataEvent.getSuricataClassifications(class_file)
    print('Ingesting events...')

    #
    # Begin main loop
    #
    while True:
        try:
            # Timeout of 0.0 seconds for non-blocking I/O causes 100% CPU usage
            inputready,outputready,exceptready = select(std_in,std_out,std_err,0.1)
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
     
        # No data to be read.  Use this time to update the database.
        if not inputready:
            if options.ids:
                ids_events.updateDb()
                ids_capture.updateDb()
       
        else:
            # Process data waiting to be read 
            try:
                # Explicitly cohersing to string, was implicit in python2
                raw_data = (os.read(inputready[0], 32768)).decode('ascii', 'backslashreplace')

                events = ['']      # Initialize in case of parsing error
                if options.http and inputready[0] == http_fd: 
                    #print('Processing http buffer...')
                    pc = eval('HttpEvent')
                    event_delim = '\n'
                    http_buffer += raw_data
                    events_container = http_events 
                    #capture_container = http_capture

                    if event_delim in http_buffer:
                        tmp = http_buffer.split(event_delim)
                        events, http_buffer = tmp[:-1], tmp[-1] 

                elif options.ids and inputready[0] == ids_fd:
                    #print('Processing ids buffer...')
                    pc = eval('IdsEvent')
                    event_delim = '+================\n'
                    ids_buffer += raw_data
                    events_container = ids_events
                    #capture_container = ids_capture
                    
                    # Suricata sends events in 4096 byte chunks
                    if len(raw_data) == 4096: continue

                    if event_delim in ids_buffer:
                        tmp = ids_buffer.split(event_delim)
                        events, ids_buffer = tmp[:-1], tmp[-1] 

                else:
                    print('Caught event............')
                    print('raw_data: ', raw_data)
                    continue

            except OSError:
                # This exception occurs if signal handled during read
                continue

            if events == ['']: continue

            try:
                for event in events:
                    #print('Processing event...')
                    # Handle empty alert and large alerts
                    if len(event) == 0: continue

                    # for debug to see structure/format of large events
                    #if len(event) > 32768:
                    #    print 'len: ', len(event)
                    #    print event 

                    key, data = pc.parse(event)

                    # No eventInfo dictionary, write event directly to mongo
                    pc.saveEventInfo(events_container, data)

                    curr_seq = int(data['t'])
                    trafcap.last_seq_off_the_wire = curr_seq

                    # Update IDS dictionaries, no HTTP dictionaries at this time
                    if pc == eval('IdsEvent'):
                        #print('Updating events_dict.....')
                        ids_events.updateCountDict(key, data, curr_seq)
                        ids_capture.updateInfoDict(pc.capture_dict_key, 
                                                   data, curr_seq)
                        #print('Updating capture_dict.....')
                        ids_capture.updateCountDict(pc.capture_dict_key, 
                                                    data, curr_seq) 

                # parsing problem can sometimes cause    (),[]   to be returned
                if data == {}:
                    continue

            except Exception as e:
                # Something went wrong with parsing the line. Save for analysis
                trafcap.logException(e, event=event, events=events)
                continue     
      
        if not options.quiet and options.ids: 
            print("\rActive: ", \
                   ids_capture.count_dict[IdsEvent.capture_dict_key]\
                                         [IdsEvent.c_events], ", ", \
                   len(ids_events.count_dict), "\r", end=' ')

        sys.stdout.flush()

    exitNow('')

if __name__ == "__main__":
    main()
