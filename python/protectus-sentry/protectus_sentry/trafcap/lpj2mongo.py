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
from protectus_sentry.trafcap import trafcap
from protectus_sentry.trafcap import lpj
from protectus_sentry.trafcap.lpjPacket import *
from protectus_sentry.trafcap.lpjContainer import *
from protectus_sentry.trafcap.lpjTarget import *
import copy
import fcntl
import threading

class Lpj2MongoThread(threading.Thread):
    def __init__(self):
        super(Lpj2MongoThread, self).__init__()
        self._finished = threading.Event()

    def shutdown(self):
        self._finished.set()

    def run(self):
        options = trafcap.options

        info_collection_name = "lpj_info"
        data_collection_name = "lpj_data"
        proc = None

        container = LpjIpPktContainer

        # A python class is defined for each protocol (TCP, ICMP at this time)
        # and each class encapsulates packet-specific information
        pc = TcpLpjPacket
        tcp_session = container(pc, info_collection_name, data_collection_name)
        pc = IcmpLpjPacket
        icmp_session = container(pc, info_collection_name, data_collection_name)

        # When lpj2Mongo was it's own python script, it would query the DB for
        # target_ips.  Now we just copy data provided to us by lpjSend
        my_ips_cids = {}
        def updateMyTargets():
            my_ips_cids.clear()
            # We take a copy so we can quickly drop the lock.
            with lpj.target_cids_lock:
                my_ips_cids.update(lpj.target_cids)

            if not options.quiet:
                print("Injest: target_cids: ", my_ips_cids)

        updateMyTargets()

        def setFileNonBlock(proc):
            # make stdout and stderr non-blocking
            fd_stdout = proc.stdout.fileno()
            fd_stderr = proc.stderr.fileno()
            fl_stdout = fcntl.fcntl(fd_stdout, fcntl.F_GETFL)
            fl_stderr = fcntl.fcntl(fd_stderr, fcntl.F_GETFL)
            fcntl.fcntl(fd_stdout, fcntl.F_SETFL, fl_stdout | os.O_NONBLOCK)
            fcntl.fcntl(fd_stderr, fcntl.F_SETFL, fl_stderr | os.O_NONBLOCK)
            return fd_stdout

        proc = pc.startSniffer()
        fd_out = setFileNonBlock(proc)

        # Ensure network interface is available
        sniff_working = False
        while not sniff_working:
            try:
                if not options.quiet: print('Reading stderr for sniffer status...')
                std_err = proc.stderr.readline().decode('ascii')
                if not options.quiet: print('  std_err = ', std_err)
                if 'device is not up' in std_err:
                    # kill failed proc
                    if proc:
                        os.kill(proc.pid, signal.SIGTERM)
                    # start new proc
                    proc = pc.startSniffer()
                    fd_out = setFileNonBlock(proc)
                    time.sleep(1)
                elif 'verbose output' in std_err:
                    sniff_working = True
                    if not options.quiet: print('Sniffer started...good to go.')
                else:
                    # Sometimes stderr is empty - not sure why.  
                    # Maybe interference from SIGURS1 
                    if not options.quiet: print('std_err is empty...')
                    # kill failed proc
                    if proc:
                        os.kill(proc.pid, signal.SIGTERM)
                    # start new proc
                    proc = pc.startSniffer()
                    fd_out = setFileNonBlock(proc)
                    time.sleep(1) 

            except Exception as e:
                print(e)
                time.sleep(1)

        std_in = [fd_out]
        std_out = []
        std_err = []

        the_buffer=''                        # stores partial lines between reads  
        inputready = None
        outputready = None
        exceptready = None

        #
        # Begin main loop
        #
        while True:
            if self._finished.is_set():
                return

            try:
                # Timeout of 0.0 seconds here causes 100% CPU usage
                inputready,outputready,exceptready = select(std_in,std_out,std_err,0.1)
            except Exception as e:
                # This code path is followed when a signal is caught
                if e[0] != 4:        # Exception not caused by USR1 and USR2
                    trafcap.logException(e, inputready=inputready,
                                            outputready=outputready,
                                            exceptready=exceptready)
                    continue

            if exceptready:
                print("Injest: Something in exceptready...")
                print(exceptready)

            if std_err:
                print("Injest: Something in std_err...")
                print(std_err)

            if lpj.target_cids_changed.is_set():
                lpj.target_cids_changed.clear()
                updateMyTargets()

            # No data to be read.  Use this time to update the database.
            if not inputready:

                tcp_session.updateDb()
                icmp_session.updateDb()
                
            else:
                # Process data waiting to be read 
                try:
                   raw_data = os.read(std_in[0],trafcap.bytes_to_read)
                except Exception as e:
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

                        line = a_line.split()
         
                        # Handle garbage lines / bad tcpdump output
                        if len(line) <= 4: continue

                        # Check if packet is to/from expected target
                        c_id = None
                        if line[2] in my_ips_cids:
                            c_id = my_ips_cids[line[2]]
                        elif line[4].strip(":") in my_ips_cids:
                            c_id = my_ips_cids[line[4].strip(":")]
                        else:
                            continue

                        if line[5] == "ICMP":
                            request_key, session_key, data = IcmpLpjPacket.parse(line)
                            request, reply = icmp_session.updateInfoDict(request_key, 
                                                              session_key, data, c_id) 
                            if request:
                                icmp_session.updateDataDict(session_key, request, reply) 
                        elif line[5] == "Flags":
                            request_key, session_key, data = TcpLpjPacket.parse(line)
                            request, reply = tcp_session.updateInfoDict(request_key, 
                                                              session_key, data, c_id) 
                            if request:
                                tcp_session.updateDataDict(session_key, request, reply) 
                            pass

                        else:
                            print("Injest: Invalid input...")
                            raise Exception("Unexpected protocol.")

                    except MtrPacketError as e:
                        continue
                    except Exception as e:
                        # Something went wrong with parsing the line. Save for analysis
                        trafcap.logException(e, line=line, lines=lines,
                                                the_buffer=the_buffer)
                        continue
           
                    curr_seq = int(data[pc.p_etime])
                    trafcap.last_seq_off_the_wire = curr_seq

                sys.stdout.flush()
