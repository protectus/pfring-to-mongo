# ipsecPacket.py
# Class used to display real-time SPI information for a VPN tunnel
import subprocess
import time
import trafcap
from datetime import datetime
import traceback
import pprint
import sys
import socket
import struct
import re
import operator
import copy


# Legend for how data is temporarily stored in the python dictionary
#
# [ start_time, curr_time, proto, (key), min_len, max_len, curr_len]
i_time_strt=0
i_time_curr=1
i_proto=2
i_key=3
i_len_min=4
i_len_max=5
i_len_curr=6
i_pkt_cnt=7


class IpsecPacket(object):
    """
    Parent class for handling MAC, IP, Name packets and Geo info
    """
    def __init__(self):
        return

    @classmethod
    def parse(pc ,pkt):
        return


    @staticmethod
    def startSniffer():
        proc1 = subprocess.Popen(['/usr/bin/tshark',
               '-i', trafcap.sniff_interface,
               '-te', '-n', '-l',
               '-f',
               '(not tcp and not icmp and not arp and not port 53 and host 24.56.85.180)'],
               #'(arp or(ip and udp and (port 53 or port 138))) or (vlan and (arp or(ip and udp and (port 53 or port 138))))'],
               # ip string in packet filter (above) ensures IPV4
               bufsize=-1, stdout=subprocess.PIPE)

        #proc2 = subprocess.Popen(['/bin/sed', 's/ 0x/ /'],
        #proc2 = subprocess.Popen(['/usr/bin/tr', '-d', '9'],
        #       bufsize=-1, stdin = proc1.stdout, stdout=subprocess.PIPE)

        #proc1.stdout.close()
        #proc2.communicate()
        return proc1

class EspIpsecPacket(IpsecPacket):
    """
    Class for handling ARP traffic
    """
    def __init__(self):
        return

    @classmethod
    def parse(pc, pkt):
        # 1364914981.287280 98.103.75.234 -> 24.56.85.180 ESP 166 ESP (SPI=0x6e31ec97)
        try:
            pkt_time = float(pkt[0])

            # sanity check for correct packet
            #if len(pkt) < 6:
            #   return time, ()

            src_ip = pkt[1]
            dst_ip = pkt[3]
            proto = pkt[4]
            length = int(pkt[5])
            spi = pkt[7][5:15]

        except:
            raise Exception("Unable to parse ESP traffic." )

        key = (src_ip, dst_ip, spi)
        return pkt_time, proto, key, length


class IsakmpIpsecPacket(IpsecPacket):
    """
    Class for handling BROWSER traffic
    """
    def __init__(self):
        return

    @classmethod
    def parse(pc, pkt):
        # ['1365029760.780395', '98.103.75.234', '->', '24.56.85.180', 'ISAKMP', '118']
        try:
            pkt_time = float(pkt[0])
            src_ip = pkt[1]
            dst_ip = pkt[3]
            proto = pkt[4]
            length = int(pkt[5])

        except:
            raise Exception("Unable to parse ISAKMP traffic." )

        key = (src_ip, dst_ip)
        return pkt_time, proto, key, length


class IpsecContainer(object):
    """
    Manages data dictionaries and writes accumulated data to db
    """

    def __init__(self, packet_class, col_name):
        self.pc = packet_class
        self.collection = col_name
        self.dict = {}
        self.db = None

        if trafcap.options.mongo:
            self.db = trafcap.mongoSetup()

        return

    def update(self, proto, time, a_key, length):

        key = (proto, a_key)
        try:
            item = self.dict[key]
            item[i_time_curr] = time
            item[i_len_curr] = length
            if item[i_len_max] < length:
                item[i_len_max] = length
            if item[i_len_min] > length:
                item[i_len_min] = length

            item[i_pkt_cnt] += 1

        except KeyError:
            #self.dict[key] = [copy.depcopy(time), copy.deepcopy(time), proto, a_key,
            #                  copy.deepcopy(length),copy.deepcopy(length),copy.deepcopy(length),1]
            self.dict[key] = [time, time, proto, a_key, length,length,length,1]

        # Clean-up the dictionary
        #keys_to_pop = []
        #for key in self.dict:
        #    # If the dictionary entry is old enough that it will be updated
        #    # then delete it - a new entry will be created if needed.
        #    if (time - self.dict[key]) > trafcap.nmi_db_update_wait_time :
        #        keys_to_pop.append(key)
        #
        #        for key in keys_to_pop:
        #            self.dict.pop(key)

        return

    def dump(self):
        # clear screen
        sys.stderr.write("\x1b[2J\x1b[H")

        sorted_list = sorted(self.dict.iteritems(), key=operator.itemgetter(1))
        print "First".center(26), "Last".center(14), \
              "Proto".center(6), " Src -> Dst ".center(34), \
              "SPI".center(10), "Pkts".center(5), \
              "lmin".center(4), "lcur".center(4), "lmax".center(4)

        for item in sorted_list:
            #print item[1]
            a_line = item[1]
            start_time = datetime.fromtimestamp(a_line[0])
            curr_time = datetime.fromtimestamp(a_line[1])
            print start_time, str(curr_time)[11:-1], \
                  a_line[i_proto].center(6), \
                  a_line[i_key][0].rjust(15), "->", a_line[i_key][1].ljust(15),
            if a_line[i_proto] == 'Esp':
                print a_line[i_key][2].rjust(10),
            else:
                print " ".rjust(10),
            print str(a_line[i_pkt_cnt]).rjust(5), \
                  str(a_line[i_len_min]).rjust(4), \
                  str(a_line[i_len_curr]).rjust(4), \
                  str(a_line[i_len_max]).rjust(4)

