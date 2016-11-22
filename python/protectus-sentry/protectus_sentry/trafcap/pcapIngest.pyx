import os, sys
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

EPOCH_MASK = 0xFFFFFF00
# Maximum (and default) snaplen of tcpdump
DEF MAX_SNAPLEN = 65535
# magic_number at beginning of pcap file
PCAP_MAGIC_NUMBER = 2712847316    # 0xa1b2c3d4
PCAPNG_MAGIC_NUMBER = 439041101   # 0x1a2b3c4d

def decBinHexPrint(hint, val):
    # For debug - prints in decimal, binary, and hex
    print hint, ':', val, format(val, '032b'), format(val, '08x')

cdef bint pcapAquired(uint32_t micr_sec, int capt_len, int wire_len):
    # Crude aquisition check.
    # Converted bytes as unsigned-long so no negative numbers
    if micr_sec > 999999 or \
       capt_len > MAX_SNAPLEN or \
       wire_len > MAX_SNAPLEN:
        pcap_aquired = False 
    else:
        pcap_aquired = True 
    return pcap_aquired

def parseArgs():
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', dest='file_input', type=str, default='-',
                        help='input file (or pipe?, fifo?); defaults to STDIN')
    parser.add_argument('-i', dest='interface', type=str, required=True,
                        help='interface on which to output packets; required')
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

    # make stdin non-blocking 
    #fd = sys.stdin.fileno()
    #fl = fcntl.fcntl(fd, fcntl.F_GETFL)
    #fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

    # Try using stdio.lib for faster reads...
    pcap_stream_ptr = fdopen(args.file_input, 'rb')

    cdef PcapData* pcap_data = <PcapData*>malloc(sizeof(PcapData))
    cdef PcapGlobalHeaderLessMagicNumber* pcap_ghlmn = <PcapGlobalHeaderLessMagicNumber*>malloc(sizeof(PcapGlobalHeaderLessMagicNumber))
    cdef PcapPktHeaderLessEpoch* pcap_phle = <PcapPktHeaderLessEpoch*>malloc(sizeof(PcapPktHeaderLessEpoch))
    cdef PcapPktHeader* pcap_ph = <PcapPktHeader*>malloc(sizeof(PcapPktHeader))
    
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
    pcap_aquired = False
    loop_count = 1
    write_count = total_bytes_written = aquired_count = not_aquired_count = 0

    cdef char* pcap_pkt_bytes = <char *>malloc(MAX_SNAPLEN)
    cdef int num_bytes

    while True:
        if pcap_aquired:
            # Get the next packet
            num_bytes = fread(pcap_ph, 1, sizeof(PcapPktHeader), 
                              pcap_stream_ptr)

            # Periodically check acquisition. Tune for sufficient performance
            if loop_count%10:
                pcap_aquired = pcapAquired(pcap_ph.micr_sec, pcap_ph.capt_len, 
                                           pcap_ph.wire_len)
            num_bytes = fread(pcap_pkt_bytes, 1, pcap_ph.capt_len, 
                              pcap_stream_ptr)

            if pcap_aquired:
                aquired_count += 1
                # Create packet padding if needed
                pad_len = pcap_ph.wire_len - pcap_ph.capt_len
                if pad_len > 0:
                    pad_str = 'x'*pad_len

                # Write packet plus padding onto the tap interface
                num_bytes = os.write(tap_py_file_obj.fileno(), 
                                     pcap_pkt_bytes[:pcap_ph.capt_len] +
                                     pad_str)

                ## Needed to avoid cython error:
                ## Storing unsafe C derivative of temporary Python reference
                #bytes_to_write = pkt_bytes + pad_bytes
                #bytes_to_write_ptr = <bytes>bytes_to_write
                #
                #bytes_written = fwrite(bytes_to_write_ptr, 1, 
                #                       num_bytes_to_write, tap_file_ptr)

                total_bytes_written += num_bytes 
                write_count += 1

            else:
                # Print message if aquisition is lost
                not_aquired_count += 1
                print loop_count, 'Lost aqusition...'
                #decBinHexPrint('epch_sec', pcap_ph.epoch) 
                #decBinHexPrint('micr_sec', pcap_ph.micr_sec) 
                #decBinHexPrint('capt_len', pcap_ph.capt_len) 
                #decBinHexPrint('wire_len', pcap_ph.wire_len) 

        else:
            not_aquired_count += 1
            num_bytes = fread(pcap_data, 1, sizeof(PcapData), pcap_stream_ptr)
            # Future dev: Check if second pcap stream has started
            # Future dev: Check for pcapng format 
            if pcap_data.word == PCAP_MAGIC_NUMBER:
                print 'Detected pcap stream...'
                # Read rest of what should be the pcap global header
                num_bytes = fread(pcap_ghlmn, 1, 
                                  sizeof(PcapGlobalHeaderLessMagicNumber), 
                                  pcap_stream_ptr)

                # Read what should be the epoch time
                num_bytes = fread(pcap_data, 1, sizeof(PcapData), 
                                  pcap_stream_ptr)

            # Get the current time
            current_epoch = int(time.time())
            #decBinHexPrint('maybe', pcap_data.word)

            # For debug - invert time bits by complementing and multiplying
            #epoch_flip = ~pcap_data.word & 0xFFFFFFFF
            #decBinHexPrint('ep_fl', epoch_flip)

            # Create a time-dependent mask to detect timestamp.
            # Flip time value and mask-off last byte to create approximate time
            # value that can be easily compared with word from pcap stream.  
            masked_epoch_flip = ~current_epoch & EPOCH_MASK 
            #decBinHexPrint('m_e_f', masked_epoch_flip)

            # XOR pcap word with time-related mask to check for time stamp
            msb_ones_if_matched = pcap_data.word ^ masked_epoch_flip
            #decBinHexPrint('ms1im', msb_ones_if_matched)

            # If a timestamp, most significant bytes will all be 1's
            if msb_ones_if_matched >= EPOCH_MASK: 
                # We either found packet header timestamp (good) or happened
                # upon a timestamp-like byte sequence.  Need to read more data
                # & check if it looks like a packet header.

                # Pcap header less epoch is 12 bytes
                num_bytes = fread(pcap_phle, 1, sizeof(PcapPktHeaderLessEpoch), 
                                  pcap_stream_ptr)

                # Crude check for ping pkt which includes timestamp in payload.
                # When trying to mistalenly sync on ping pkt payload timestamp,  
                # observatoins show that micr_sec and wire_len == 0.
                if pcap_phle.micr_sec != 0 and pcap_phle.wire_len != 0:
                    # Probably not a ping packet, test for aquisition
                    pcap_aquired = pcapAquired(pcap_phle.micr_sec, 
                                               pcap_phle.capt_len, 
                                               pcap_phle.wire_len)
                    if pcap_aquired: 
                        # Read the pcap packet bytes - this packet is ignored
                        num_bytes = fread(pcap_pkt_bytes, 1, pcap_phle.capt_len,
                                          pcap_stream_ptr)

                print loop_count, pcap_aquired, pcap_data.word,\
                      pcap_phle.micr_sec, pcap_phle.capt_len, pcap_phle.wire_len
            else:
                print loop_count, pcap_aquired, pcap_data.word 

        loop_count += 1
        sys.stdout.write('  pkts:'+str(loop_count)+
                         #', a:'+str(aquired_count)+
                         #',na:'+str(not_aquired_count)+
                         #', w:'+str(write_count)+
                         #',tbw'+str(total_bytes_written)+
                         '\r')
        sys.stdout.flush()

if __name__ == "__main__":
  main()
