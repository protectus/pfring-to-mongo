#!/usr/bin/python
import sys, time, os, signal
from select import select
import socket
from datetime import datetime
import subprocess
from optparse import OptionParser
import math
import traceback
import trafcap
import lpj
from lpjPacket import *
from lpjContainer import *
from lpjTarget import *
import copy
import fcntl

proc = None

trafcap.checkIfRoot()
check_db_task = None

def parseOptions():
    usage = "usage: %prog [-mq]"
    parser = OptionParser(usage)
    parser.add_option("-m", "--mongo", dest="mongo",
                      action="store_true", default=False,
                      help="write to mongo")
    parser.add_option("-q", "--quiet", dest="quiet",
                      action="store_true", default=False,
                      help="don't print status to stdout")
    (options, args) = parser.parse_args()
    return options
 
def exitNow(message):
    # Kill the childprocess sniffing packets
    print "Exiting..."
    if proc:
        os.kill(proc.pid, signal.SIGTERM)
    if check_db_task:
        check_db_task.shutdown()
    sys.exit(message)

trafcap.options = options = parseOptions()

info_collection_name = "lpj_info"
data_collection_name = "lpj_data"

container = eval("LpjIpPktContainer")

# A python class is defined for each protocol (TCP, ICMP at this time) and  
# each class encapsulates packet-specific information
pc = eval('TcpLpjPacket')
tcp_session = container(pc, info_collection_name, data_collection_name)
pc = eval('IcmpLpjPacket')
icmp_session = container(pc, info_collection_name, data_collection_name)
 
targets_from_config = lpj.readConfig()
for target in targets_from_config:
    print target
    a_target_obj = lpj.createTarget(target, False)
    LpjIpTarget.target_ips.append(a_target_obj.getTargetString())

if not options.quiet:
    print "target_ips: ", LpjIpTarget.target_ips

def catchSignal1(signum, stack):
    if not trafcap.options.quiet: print 'Caught SIGUSR1...'
    LpjIpTarget.checkDbForUpdates(False)

def catchSignal2(signum, stack):
    pass

def catchCntlC(signum, stack):
    exitNow('Terminating...')

def updateStatus():
    if not options.quiet: 
        info_total = len(tcp_session.info_dict)+len(icmp_session.info_dict)
        data_total = len(tcp_session.data_dict)+len(icmp_session.data_dict)
        print "\rActive: ", info_total, ", ", data_total, \
                            LpjIpTarget.target_ips, "\r",
        sys.stdout.flush()


signal.signal(signal.SIGUSR1, catchSignal1)
signal.signal(signal.SIGUSR2, catchSignal2)
signal.signal(signal.SIGINT, catchCntlC)
signal.signal(signal.SIGTERM, catchCntlC)

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
        if not options.quiet: print 'Reading stderr for sniffer status...'
        std_err = proc.stderr.readline()
        if not options.quiet: print '  std_err = ', std_err
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
            if not options.quiet: print 'Sniffer started...good to go.'
        else:
            # Sometimes stderr is empty - not sure why.  
            # Maybe interference from SIGURS1 
            if not options.quiet: print 'std_err is empty...'
            # kill failed proc
            if proc:
                os.kill(proc.pid, signal.SIGTERM)
            # start new proc
            proc = pc.startSniffer()
            fd_out = setFileNonBlock(proc)
            time.sleep(1) 

    except Exception, e:
        print e
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
    try:
        # Timeout of 0.0 seconds for non-blocking I/O causes 100% CPU usage
        inputready,outputready,exceptready = select(std_in,std_out,std_err,0.1)
    except Exception, e:
        # This code path is followed when a signal is caught
        if e[0] != 4:        # Exception not caused by USR1 and USR2 signals 
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
 
    # No data to be read.  Use this time to update the database.
    if not inputready:

        tcp_session.updateDb()
        icmp_session.updateDb()
        
        updateStatus()
   
    else:
        # Process data waiting to be read 
        try:
           raw_data = os.read(std_in[0],trafcap.bytes_to_read)
        except Exception, e:
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
                if line[2] not in LpjIpTarget.target_ips and \
                   line[4].strip(":") not in LpjIpTarget.target_ips:
                    continue

                if line[5] == "ICMP":
                    request_key, session_key, data = IcmpLpjPacket.parse(line)
                    request, reply = icmp_session.updateInfoDict(request_key, 
                                                             session_key, data) 
                    if request:
                        icmp_session.updateDataDict(session_key, request, reply) 
                elif line[5] == "Flags":
                    request_key, session_key, data = TcpLpjPacket.parse(line)
                    request, reply = tcp_session.updateInfoDict(request_key, 
                                                             session_key, data) 
                    if request:
                        tcp_session.updateDataDict(session_key, request, reply) 
                    pass

                else:
                    print "Invalid input..."
                    raise Exception("Unexpected protocol.")

            except MtrPacketError, e:
                continue
            except Exception, e:
                # Something went wrong with parsing the line. Save for analysis
                trafcap.logException(e, line=line, lines=lines,
                                        the_buffer=the_buffer)
                continue
   
            curr_seq = int(data[pc.p_etime])
            trafcap.last_seq_off_the_wire = curr_seq

        updateStatus()

        sys.stdout.flush()

exitNow('')
