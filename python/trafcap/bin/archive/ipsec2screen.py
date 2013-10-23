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
from ipsecPacket import *

from pprint import pprint  # for testing

proc = None

trafcap.checkIfRoot()

def parseOptions():
    usage = "usage: %prog [-q]"
    parser = OptionParser(usage)
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
    sys.exit(message)


options = parseOptions()     # Could combine this line with next line
trafcap.options = options

collection_name = "ipsec"
packet_type = "IpsecPacket"

ipsec = IpsecContainer(eval(packet_type),
                     collection_name)

# A python class is defined for each protocol (ARP, DNS, ...) and
# each class encapsulates packet-specific information
pc = eval(packet_type)

def catchSignal1(signum, stac):
    num_entries = len(nmi.dict)
    print "\n", num_entries, " active nmi dict entries:"
    for k in nmi.dict:
        print "   ",
        print nmi.dict[k]
    if num_entries >= 1:
        print num_entries, " active nmi dict entries displayed."

def catchCntlC(signum, stack):
    exitNow('')

signal.signal(signal.SIGUSR1, catchSignal1)
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

buffer=''                        # stores partial lines between reads
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
        if e[0] != 4:        # Excetion not caused by USR1 and USR2 signals
            sys.stdout.write("Caught exception...")
            sys.stdout.flush()
            print(e)
            file = open(trafcap.error_log,"a")
            file.write("\n========exception in select loop================\n")
            file.write(str(datetime.now())+"\n")
            file.write(e.__str__())
            file.write(traceback.format_exc())
            file.write("\n-------------inputready----------------\n")
            file.write(str(inputready))
            file.write("\n-------------outputready---------------\n")
            file.write(str(outputready))
            file.write("\n-------------exceptready---------------\n")
            file.write(str(exceptready))
            file.write("\n==========end exception in select loop==========\n")
            file.close()
            continue

    if exceptready:
        print "Something in exceptready..."
        print exceptready

    if std_err:
        print "Something in std_err..."
        print std_err

    # No data to be read.  Use this time to update the database.
    if inputready:
        # Process data waiting to be read
        raw_data = os.read(std_in[0],trafcap.bytes_to_read)
        #print raw_data
        buffer += raw_data
        if '\n' in raw_data:
            tmp = buffer.split('\n')
            lines, buffer = tmp[:-1], tmp[-1]
        else:
            # not enough data has been read yet to make a full line
            lines = ""

        for a_line in lines:

            try:
                line = a_line.split()

                if line[4] == "ESP":
                    time, proto, key, length = EspIpsecPacket.parse(line)
                    if len(key) > 0:   # successful parse
                       ipsec.update('Esp', time, key, length)

                elif line[4] == "ISAKMP":
                    time, proto, key, length = IsakmpIpsecPacket.parse(line)
                    if len(key) > 0:   # successful parse
                       ipsec.update('Isakmp', time, key, length)

                else:
                    print "Invalid input..."
                    raise Exception("Unexpected protocol.")

            except Exception, e:
                # Something went wrong with parsing the line. Save for analysis
                if not options.quiet:
                    print e
                    print "\n-------------line------------------\n"
                    print line
                    print "\n-------------lines-----------------\n"
                    print lines
                    print "\n-------------buffer----------------\n"
                    print buffer
                    print traceback.format_exc()

                file = open(trafcap.error_log,"a")
                file.write("\n===========================================\n")
                file.write(str(datetime.now())+"\n")
                file.write(e.__str__())
                file.write(traceback.format_exc())
                file.write("\n-------------line------------------\n")
                for item in line: file.write(item)
                file.write("\n-------------lines-----------------\n")
                file.write("\n".join(lines))
                file.write("\n-------------buffer----------------\n")
                file.write(buffer)
                file.close()

        if not options.quiet:
            print "\rActive: ", len(ipsec.dict), \
                  "\r",
            ipsec.dump()

        sys.stdout.flush()

exitNow('')

