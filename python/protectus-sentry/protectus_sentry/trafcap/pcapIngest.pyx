import os, sys, signal
import traceback
import time
import argparse
import io
import fcntl
import struct

#CYTHON
#from ctypes import Structure, c_uint16, c_uint32, c_uint64, c_int16, c_uint8, c_double, c_char
from libc.stdint cimport uint64_t, uint32_t, uint16_t, uint8_t, int64_t
from libc.string cimport memcpy, memset
from libc.stdlib cimport malloc

from libc.stdio cimport *
from posix.ioctl cimport ioctl
#cdef extern from "stdio.h": FILE *fdopen(int, const char *)
#cdef extern from "stdio.h": int fileno(FILE *)

# Ioctl defines
TUNSETNOCSUM  = 0x400454c8
TUNSETDEBUG   = 0x400454c9
TUNSETIFF     = 0x400454ca
TUNSETPERSIST = 0x400454cb
TUNSETOWNER   = 0x400454cc
TUNSETLINK    = 0x400454cd

# These flags same as http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/Documentation/networking/tuntap.txt?id=HEAD
# TUNSETIFF ifr flags
IFF_TUN       = 0x0001
IFF_TAP       = 0x0002
IFF_NO_PI     = 0x1000
IFF_ONE_QUEUE = 0x2000

# fcntl flags
O_NONBLOCK    = 0x0004  

EPOCH_MASK = 0xFFFFFF00
TIME_DIFF_THRESHOLD = 0xFFFFFFFF - EPOCH_MASK
# Maximum (and default) snaplen of tcpdump
DEF MAX_SNAPLEN = 65535

# pcap related constants
PCAP_MAGIC_NUMBER = 2712847316        # 0xa1b2c3d4
PCAP_MAGIC_NUMBER_SWPD = 3569595041   # 0xd4c3b2a1
PCAPNG_MAGIC_NUMBER = 439041101       # 0x1a2b3c4d
PCAPNG_MAGIC_NUMBER_SWPD = 1295788826 # 0x4d3c2b1a
PCAPNG_SECT_HDR_BLK_TYPE = 168627466  # 0x0A0D0D0A

def catchCntlC(signum, stack):
    # If any syb-procs, kill them here
    #if proc:
    #    os.kill(proc.pid, signal.SIGTERM)
    sys.exit('Exiting pcap ingest')

signal.signal(signal.SIGINT, catchCntlC)
signal.signal(signal.SIGTERM, catchCntlC)

def decBinHexPrint(hint, val):
    # For debug - prints in decimal, binary, and hex
    print hint, ':', val, format(val, '032b'), format(val, '08x')

cdef bint pcapAquired(int debug_flag, uint32_t micr_sec, int capt_len, 
                      int wire_len):
    # Crude aquisition check.
    # Converted bytes as unsigned-long so no negative numbers
    if micr_sec > 999999 or \
       capt_len > MAX_SNAPLEN or \
       wire_len > MAX_SNAPLEN:
        pcap_aquired = False 
        sys.stdout.write('\n' + time.ctime() + ' - ' + 
                         'Pcap not aquired (' + str(debug_flag) + 
                         #' micr_sec:' + str(micr_sec) + 
                         #',capt_len:' + str(capt_len) + 
                         #',wire_len:' + str(wire_len) + 
                         ')\n')
    else:
        pcap_aquired = True 
    return pcap_aquired

cdef uint32_t masked_epoch_flip
cdef uint32_t msb_ones_if_matched
cdef uint32_t current_time
cdef int epoch_diff 
cdef int wordIsEpoch(uint32_t maybe_epoch):
    # Create a time-dependent mask to detect timestamp.
    # Flip time value and mask-off last byte to create approximate time
    # value that can be easily compared with word from pcap stream.  
    current_time = int(time.time())
    masked_epoch_flip = ~current_time & EPOCH_MASK 

    # XOR pcap word with time-related mask to check for time stamp
    msb_ones_if_matched = maybe_epoch ^ masked_epoch_flip

    # Set a 'failing' value for epoch_diff
    epoch_diff = 99999
    # If a timestamp, most significant bytes will all be 1's
    if msb_ones_if_matched >= EPOCH_MASK: 
        # Calculate actual epoch_diff if reasonably sure this word is an epoch 
        epoch_diff = abs(current_time - maybe_epoch)
    return epoch_diff 

def parseArgs():
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', dest='file_input', type=str, default='-',
                        help='input file (or pipe?, fifo?); defaults to STDIN')
    parser.add_argument('-i', dest='interface', type=str, required=True,
                        help='interface on which to output packets; required')
    parser.add_argument('-v', dest='verbose', type=bool, default=False,
                        help='show verbose output with pkt count')
    args = parser.parse_args()
    if args.file_input == '-': args.file_input = sys.stdin.fileno()
    return args

cdef struct PcapData:
    uint32_t word 

cdef struct PcapGlobalHeaderLessMagicNumber:
    uint32_t maj_min_ver
    uint32_t time_zone
    uint32_t sig_figs
    uint32_t snap_len
    uint32_t link_type 

cdef struct PcapPktHeader:
    uint32_t epoch 
    uint32_t micr_sec 
    uint32_t capt_len
    uint32_t wire_len

cdef struct PcapPktHeaderLessEpoch:
    uint32_t micr_sec 
    uint32_t capt_len
    uint32_t wire_len

def main():
    args = parseArgs()

    # Use stdio.lib for faster reads...
    pcap_stream_ptr = fdopen(args.file_input, 'rb')

    cdef PcapData* pcap_data = <PcapData*>malloc(sizeof(PcapData))
    cdef PcapGlobalHeaderLessMagicNumber* pcap_ghlmn = <PcapGlobalHeaderLessMagicNumber*>malloc(sizeof(PcapGlobalHeaderLessMagicNumber))
    cdef PcapPktHeaderLessEpoch* pcap_phle = <PcapPktHeaderLessEpoch*>malloc(sizeof(PcapPktHeaderLessEpoch))
    cdef PcapPktHeader* pcap_ph = <PcapPktHeader*>malloc(sizeof(PcapPktHeader))
    
    # Setup the tap interface for writing output
    tap_py_file_obj = open("/dev/net/tun", "w+")   # returns a file object
    name = args.interface   # do some error checking on this arg
    ifreq = struct.pack("16sH", name, IFF_TAP | IFF_NO_PI) 
    fcntl.ioctl(tap_py_file_obj.fileno(), TUNSETIFF, ifreq)
    fcntl.ioctl(tap_py_file_obj.fileno(), TUNSETNOCSUM, 1)

    # Example C code for working with tap interface
    #struct ifreq ifr;
    #fd = open("/dev/net/tun", O_RDWR);
    #memset(&ifr, 0, sizeof(ifr));
    #ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    #strncpy(ifr.ifr_name, if_name, IFNAMSIZ);
    #ioctl(fd, TUNSETIFF, (void *)&ifr)
    #strcpy(if_name, ifr.ifr_name);
    #
    # https://github.com/freenas/py-netif/blob/master/netif.pyx
    # https://github.com/freenas/py-netif/blob/master/defs.pxd
    # 
    #cdef FILE* tap_file_ptr
    #tap_file_ptr = fdopen(tap_py_file_obj.fileno(), 'w+')
    #cdef char *ifreq_ptr = ifreq
    #print ''.join(x.encode('hex') for x in ifreq_ptr[:18])
    #    746170330000000000000000000000000210
    #    t a p 3
    #ret1 = ioctl(tap_py_file_obj.fileno(), TUNSETIFF, <void*>ifreq_ptr)
    #ret2 = ioctl(tap_py_file_obj.fileno(), TUNSETNOCSUM, 1)
    #print ret1, ret2
    #sys.exit()


    # Method: Identify pcap packet header using time value and other patterns.
    #         After some pkts successfully read, consider pcap stream aquired.
    # Assume: Packet capture time is within a few seconds of Sentry time.
    #         A few seconds of delay is introduced during pcap data transport.
    #         To simplify acquisition, look for time stamp on word boundry.
    #         A few lost packets at start-up is acceptable.
    # Notes:  Python reads (not used) give swapped byte ordering. 
    #         C reads to structs gives 'correct' byte order (mag_num=0xa1b2c3d4) 
    cdef bint pcap_aquired = False
    # MAke these C ints
    cdef int loop_count = 1
    cdef int write_count = 0
    cdef int total_bytes_written = 0
    cdef int aquired_count = 0
    cdef int not_aquired_count = 0

    # Buffer for packet payload data
    cdef char* pcap_pkt_bytes = <char *>malloc(MAX_SNAPLEN)
    cdef int num_bytes
    cdef int pad_len 
    cdef bint is_epoch
    cdef int time_diff

    while True:
        try:
            if pcap_aquired:
                # Get the next packet
                num_bytes = fread(pcap_ph, 1, sizeof(PcapPktHeader), 
                                  pcap_stream_ptr)
                # Check acquisition
                pcap_aquired = pcapAquired(1, pcap_ph.micr_sec, 
                                           pcap_ph.capt_len, 
                                           pcap_ph.wire_len)
    
                if pcap_aquired:
                    # Get the packet payload bytes
                    num_bytes = fread(pcap_pkt_bytes, 1, pcap_ph.capt_len, 
                                      pcap_stream_ptr)
    
                    aquired_count += 1
                    # Create packet padding if needed
                    pad_len = pcap_ph.wire_len - pcap_ph.capt_len
                    if pad_len >= 0 and pad_len < 65535:
                        memset(pcap_pkt_bytes + pcap_ph.capt_len, 'x', pad_len)
                    else:
                        # Assume aquisition lost if problem with pad calculation
                        pcap_aquired = False
                        continue
    
                    # Write packet plus padding onto the tap interface
                    num_bytes = os.write(tap_py_file_obj.fileno(), 
                                         pcap_pkt_bytes[:pcap_ph.wire_len])
    
                    total_bytes_written += num_bytes 
                    write_count += 1
    
                else:
                    not_aquired_count += 1
                    # Lost aquisition message posted by pcapAquired function
    
            else:
                not_aquired_count += 1
                # This read will block until pcap stream starts
                num_bytes = fread(pcap_data, 1, sizeof(PcapData), 
                                  pcap_stream_ptr)
    
                # Check if 4 byte word read from pcap stream is a time stamp
                time_diff = wordIsEpoch(pcap_data.word)
                if time_diff < TIME_DIFF_THRESHOLD: 
                    # We either found packet header timestamp (good) or happened
                    # upon a timestamp-like byte sequence.  Need to read more 
                    # data & check if it looks like a packet header.
    
                    # Get remainder of pcap header 
                    num_bytes = fread(pcap_phle, 1, 
                                      sizeof(PcapPktHeaderLessEpoch), 
                                      pcap_stream_ptr)
    
                    # Crude check for ping pkt which includes timestamp in 
                    # payload.  When trying to mistalenly sync on ping pkt 
                    # payload timestamp, observations show that 
                    # micr_sec and wire_len == 0.
                    if pcap_phle.micr_sec != 0 and pcap_phle.wire_len != 0:
                        # Probably not a ping packet, test for aquisition
                        pcap_aquired = pcapAquired(2, pcap_phle.micr_sec, 
                                                   pcap_phle.capt_len, 
                                                   pcap_phle.wire_len)
                        if pcap_aquired: 
                            # Read the pcap packet bytes - ignore this packet
                            num_bytes = fread(pcap_pkt_bytes, 1, 
                                              pcap_phle.capt_len,
                                              pcap_stream_ptr)
    
                            sys.stdout.write('\n' + time.ctime() + ' - ' +
                                             'Pcap aquired; clock diff: ' + 
                                             str(time_diff) + 
                                             ' sec\n') 
                            sys.stdout.flush()
    
                # Future dev: Check if second pcap stream has started
                elif pcap_data.word == PCAP_MAGIC_NUMBER:
                    sys.stdout.write('\n' + time.ctime() + ' - ' +
                                     'Pcap magic_number detected\n') 
                    sys.stdout.flush()
                    # Read rest of what should be the pcap global header.
                    # We don't use the global header but need to get it 
                    # out of the pipe so we can get to the epoch time.
                    num_bytes = fread(pcap_ghlmn, 1, 
                                      sizeof(PcapGlobalHeaderLessMagicNumber), 
                                      pcap_stream_ptr)
    
                    # Read what should be the epoch time
                    #num_bytes = fread(pcap_data, 1, sizeof(PcapData), 
                    #                  pcap_stream_ptr)
    
                elif pcap_data.word == PCAP_MAGIC_NUMBER_SWPD:
                    sys.stdout.write('\n' + time.ctime() + ' - ' +
                                     'Pcap magic_number detected; ' + 
                                     'ERROR: Bytes swapped!\n') 
                    sys.stdout.flush()
                    # Continue reading in case this was a false positive 
    
                elif pcap_data.word == PCAPNG_SECT_HDR_BLK_TYPE:
                    # Future dev - fully process pcap-ng
    
                    # Read what should be the section header block length
                    num_bytes = fread(pcap_data, 1, sizeof(PcapData), 
                                      pcap_stream_ptr)
                    # Read what should be the magic_number 
                    num_bytes = fread(pcap_data, 1, sizeof(PcapData), 
                                      pcap_stream_ptr)
    
                    if pcap_data.word == PCAPNG_MAGIC_NUMBER:
                        sys.stdout.write('\n' + time.ctime() + ' - ' +
                                         'Pcap-ng stream detected\n') 
                        sys.stdout.flush()
    
                    if pcap_data.word == PCAPNG_MAGIC_NUMBER_SWPD:
                        sys.stdout.write('\n' + time.ctime() + ' - ' +
                                         'Pcap-ng stream detected; ' + 
                                         'ERROR: Bytes swapped!\n') 
                        sys.stdout.flush()
                    # Continue reading in case this was a false positive 
                else:
                    pass
    
            # Check if stdin was closed due to upstream processing error  
            if feof(pcap_stream_ptr) != 0: 
                sys.stderr.write('\n' + time.ctime() + ' - ' +
                                 'Stdin closed; Pcap ingest exiting\n')
                sys.stderr.flush()
                sys.exit() 

            loop_count += 1
            if args.verbose:
                sys.stderr.write('  pkts:'+str(loop_count) + '\r')
                sys.stderr.flush()

        except Exception, e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            sys.stderr.write('\n' + time.ctime() + ' - ' + str(e) + 
                             ' in line # ' + str(exc_tb.tb_lineno) + 
                             ';  Pcap ingest exiting\n')
            sys.stderr.flush()
            sys.exit()

    
if __name__ == "__main__":
    main()
