# nmiPacket.py
#
# Copyright (c) 2013 Protectus,LLC.  All Rights Reserved.
#
# Classes to help pull MAC, IP, Name, Geo data off the wire and update mongo
import subprocess
import time
from . import trafcap
from datetime import datetime
import traceback
import sys
import socket
import struct
import re


# Legend for how data is temporarily stored in the python dictionary
#
# [ time, mac, ip, name, region, city, country, lat, long, dns_id ]


class NmiPacket(object):
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
               '-b', 'filesize:8192',
               '-b', 'files:5',
               '-w', '/run/trafcap_nmi',
               '-P',
               '-o',
               'column.format:"""time","%t", "proto","%p", "src","%s", "esrc","%Cus:eth.src", "dst","%d", "id","%Cus:dns.id", "hn","%Cus:bootp.option.hostname", "yo","%Cus:bootp.ip.your", "i","%i"""',
               '-f',
               '(arp or(ip and udp and port(53 or 67 or 138))) or (vlan and (arp or(ip and udp and port (53 or 67 or 138))))'],
               # ip string in packet filter (above) ensures IPV4
               bufsize=-1, stdout=subprocess.PIPE)

        #proc2 = subprocess.Popen(['/bin/sed', 's/ 0x/ /'],
        #proc2 = subprocess.Popen(['/usr/bin/tr', '-d', '9'],
        #       bufsize=-1, stdin = proc1.stdout, stdout=subprocess.PIPE)

        #proc1.stdout.close()
        #proc2.communicate()
        return proc1

class ArpNmiPacket(NmiPacket):
    """
    Class for handling ARP traffic
    """
    def __init__(self):
        return

    @classmethod
    def parse(pc, pkt):
        # ARP
        #         0              1             2                  3
        #['1342469616.668436', 'ARP', '00:11:22:33:44:55', '00:11:22:33:44:55' 
        #        4               5      6        7         8        9
        # 'ff:ff:ff:ff:ff:ff', 'Who', 'has', '1.2.3.4?', 'Tell', '9.8.7.6']

        #         0              1             2                  3
        #['1342469616.668623', 'ARP', '99:88:77:66:55:44', '99:88:77:66:55:44', 
        #          4               5        6    7             8
        # '00:11:22:33:44:55', '9.8.7.6', 'is', 'at', '99:88:77:66:55:44']
        try:
            a_mac = ''
            a_ip = ''
            pkt_time = float(pkt[0])


            # sanity check for correct packet
            if len(pkt) != 10 and len(pkt) != 9:
               return pkt_time, () 
            
            a_mac = pkt[2]
            if pkt[5:7] == ['Who', 'has']:
                a_ip = [pkt[9]]

            if pkt[6:8] == ['is', 'at']:
                a_ip = [pkt[5]]

        except:
            raise Exception("Unable to parse ARP traffic." )

        if a_mac != '' and a_ip != '':
            #if not trafcap.options.quiet:
            #    print a_mac, a_ip
            return pkt_time, ['ARP', [], a_mac, a_ip]
        else:
            return 0, [] 

class BrowserNmiPacket(NmiPacket):
    """
    Class for handling BROWSER traffic
    """
    def __init__(self):
        return

    @classmethod
    def parse(pc, pkt):
        # BROWSER
        #         0                1             2                   3
        #['1348665064.932630', 'BROWSER', '192.168.168.47', '00:21:5A:1F:CF:04'
        #         5             6        7          8               9
        # '192.168.168.255', 'Local', 'Master', 'Announcement', 'JOEL-K12,',
        #
        # 'Workstation,', 'Server,', 'NT', 'Workstation,', 'Potential', .....
        try:
            pkt_time = float(pkt[0])
            ip = [pkt[2]]
            mac = pkt[3]
            a_index = pkt.index('Announcement')

            # Handle this: Host Announcement BRIDGERS[Packet size limited during capture]
            if pkt[a_index-1] == 'Host' or pkt[a_index-1] == 'Master':
                if '[' in pkt[a_index+1]:
                    name = [pkt[a_index+1].split('[')[0]]
                else:
                    name = [pkt[a_index+1].strip(',')]
            else:
                return pkt_time, []

            return pkt_time, ['BRW', name, mac, ip]

        except ValueError:
            # Announcement not in packet text
            return 0, [] 
        except IndexError:
            # 1363626153.079200 BROWSER 192.168.5.101 e8:ba:70:b0:e1:41 192.168.1.18  Master Announcement
            return 0, []
        except:
            raise Exception("Unable to parse BROWSER traffic." )

        return


class DhcpNmiPacket(NmiPacket):
    """
    Class for handling DHCP / BOOTP traffic
    """
    def __init__(self):
        return

    # Class attribute
    dhcp_req = {}

    @classmethod
    def parse(pc, pkt):
        # Either Inform packets:
        #     1508163682.781175 DHCP 10.141.2.224 00:0a:f7:4c:c7:a2 255.255.255.255 Owner-PC 0.0.0.0 DHCP Inform - Transaction ID 0x4dae08e
        # or Request / Ack packt pair
        #     1508165493.225875 DHCP 0.0.0.0 54:9f:13:47:76:40 255.255.255.255 iPhone-3 0.0.0.0 DHCP Request - Transaction ID 0x13c1ec76 
        #     1508165493.225973 DHCP 10.141.1.1 c0:ea:e4:c5:6b:3c 255.255.255.255 10.141.3.173 DHCP ACK - Transaction ID 0x13c1ec76 
        try:
            pkt_time = float(pkt[0])
            if pkt[8] == "Inform":
                ip = pkt[2]
                mac = pkt[3]
                name = pkt[5]

            elif pkt[8] == 'Request':
                # If duplicate request occurs, dict entry will simply be over-written.
                mac = pkt[3]
                name = pkt[5]
                trans_id = pkt[-1] 
                pc.dhcp_req[trans_id] = [pkt_time, mac, name]
                return 0,[]

            elif pkt[7] == 'ACK':
                # If unmatched ACK occurs, drop the packet and continue
                ip = pkt[5]
                trans_id = pkt[-1]
                try:
                    item = pc.dhcp_req.pop(trans_id)
                    mac = item[1]
                    name = item[2]
                except KeyError:
                    # Request not found
                    return 0,[]

            else:
                return pkt_time, []

            # Clean-up unanswered requests from the dhcp_req dict
            keys_to_pop = []
            current_time = time.time()
            for a_key in pc.dhcp_req:
                if (pc.dhcp_req[a_key][0] < (current_time -\
                                       float(trafcap.session_expire_timeout))):
                    keys_to_pop.append(a_key)

            for a_key in keys_to_pop:
                pc.dhcp_req.pop(a_key)

        except Exception as e:
            print(str(e))
            traceback.print_exc()
            raise Exception("Unable to parse DHCP traffic." )

        return pkt_time, ['DHCP', [name], mac, [ip]]

class DnsNmiPacket(NmiPacket):
    """
    Class for handling DNS traffic 
    """
    def __init__(self):
        return

    # Class attribute
    dns_req = {}

    @classmethod
    def parse(pc, pkt):

        # DNS
        #        0           1      2           3            4      5
        # 1344610756.256590 DNS 1.2.3.4 00:11:22:33:44:55 8.8.8.8 0x644e 
        #    6       7      8   9     10
        # Standard query 0x644e A dev.mysql.com 
        #
        #        0           1      2          3             4      5  
        # 1344610756.296899 DNS 8.8.8.8 99:88:77:66:55:44 1.2.3.4 0x6443  
        #    6      7      8        9      10        11        12    13
        # Standard query response 0x6443 CNAME d-m-u.orakle.com A 16.15.3.1

        # Note that there can be one or more CNAME or A entries:
        #  Standard query response CNAME dom.akadns.net CNAME dl.edgesuite.net 
        #  CNAME a26.akamai.net A 157.238.74.32 A 157.238.74.51 a26.akamai.net

        #     PTR replies also handled at this time:
        # 1344959039.738612 DNS 1.2.3.4 00:11:22:33:44:55 8.8.8.8 0x09a8
        # Standard query PTR 116.230.242.94.in-addr.arpa
        #
        # 1344959039.851116 DNS 8.8.8.8 99:88:77:66:55:44 1.2.3.4 0x09a8 
        # Standard query response PTR customer.ltkm11.net

        # Request with no response is ignored 

        ip_list = []       # IPs
        name_list = []     # Hostnames 

        try:
            # Handle this case:
            #  1375454775.464517 DNS 216.21.236.249 54:75:d0:3e:55:fb 10.200.129.202 
            #  0x8a71 Standard query response 0x8a71  
            #  CNAME my-load-balancer-953617886.us-east.elb.amazonaws.com[Malformed Packet]
            # or
            # ..... Standard query response 0xd0d4  A 23.0.160.74 A[Malformed Packet]
            # or
            # .....  0xa0f9 Standard query response 0xa0f9 [Malformed Packet]
            if pkt[-1] == 'Packet]': pkt.pop(-1)
            if pkt[-1] == '[Malformed': pkt.pop(-1)
            if '[' in pkt[-1]: pkt[-1] = pkt[-1].split('[')[0]

            # If [Malfored Packet] was removed and last item is a type, then remove now-useless type
            if pkt[-1] in  ['A', 'CNAME', 'PTR', 'RRSIG']:
                pkt.pop()     # removes last item

            # Sanity check for valid DNS response.  An empty response will look like this:
            # 1360806194.207006 DNS 192.168.168.1 00:13:10:1a:a2:88 192.168.168.35 0x39f7 Standard query response 0x39f7
            if len(pkt) < 11:   return 0, []

            pkt_time = float(pkt[0])
            if pkt[6:9] == ['Standard', 'query', 'response']:
                dns_id = pkt[5] 
                src = pkt[4]

                # Check if related request is in the dict
                try:
                    dns_request = pc.dns_req.pop((dns_id, src))
                except KeyError:
                    # Response with no corresponsing request - ignore
                    return 0,[] 
                  
                fqhn_or_ip = dns_request[1]
                first_reply_type = pkt[10]
                if first_reply_type == 'CNAME':  first_reply_type = 'CNM'
                reply_type = pkt[10]

                while len(pkt) > 10 and reply_type in ['A', 'CNAME', 'PTR', 'RRSIG']:
                    if reply_type == 'A':
                        pkt.pop(10)  # throw away the 'A' 
                        ip_list.append(pkt.pop(10))
                        if fqhn_or_ip not in name_list:
                            name_list.append(fqhn_or_ip)
                    elif reply_type == 'CNAME':
                        pkt.pop(10)  # throw away the 'CNAME'
                        cname_val = pkt.pop(10)
                        #if cname_val.endswith('[Malformed'):
                        #    cname_val = cname_val[:-10]
                        #    # Eliminate trailing 'Packet]' or exception will
                        #    # be thrown next time through loop
                        #    throw_away = pkt.pop(10) 
                        name_list.append(cname_val)
                        if fqhn_or_ip not in name_list:
                            name_list.append(fqhn_or_ip)
                    elif reply_type == 'PTR':
                        pkt.pop(10)  # throw away the 'PTR'
                        name_list.append(pkt.pop(10))
                        if fqhn_or_ip not in ip_list:
                            ip_list.append(fqhn_or_ip)
                    elif reply_type == 'RRSIG':
                        pkt.pop(10)  # throw away the 'RRSIG'
                    else:
                        raise Exception("Unable to parse DNS traffic - \
                                         did not find A, CNAME, RRSIG, or PTR")
                    if len(pkt) > 10: reply_type = pkt[10]    # needed for when loop repeats

            #1425349005.662003 DNS 10.200.129.210 3c:4a:92:2c:c4:00 4.2.2.2      0x1a27 Standard query 0x1a27  A sb.l.google.com[Malformed Packet]
            if pkt[6:8] == ['Standard', 'query'] and pkt[9] == 'A':
                src = pkt[2]
                queried_name = pkt[10]
                if queried_name.endswith('[Malformed'):
                    queried_name = queried_name[:-10]
                    # Eliminate trailing 'Packet]'
                    throw_away = pkt.pop(10) 
                dns_id = pkt[5]
                pc.dns_req[(dns_id, src)] = [pkt_time, queried_name]

            if pkt[6:8] == ['Standard', 'query'] and pkt[9] == 'PTR':
                src = pkt[2]
                in_addr_arpa = pkt[10]    # 15.4.100.202.in-addr.arpa
                valid_ip = True 

                if '.in-addr.arpa' not in in_addr_arpa: valid_ip = False
                in_addr = in_addr_arpa.rstrip('.in-addr.arpa')

                i_a = in_addr.split(".")
                if len(i_a) != 4: valid_ip = False

                # Ignore non-standard PTR requests   
                #  (e.g.   DNS Standard query PTR b235.innovx.net)
                for octet in i_a:
                    if not octet.isdigit():  valid_ip = False

                if valid_ip:
                    ip_addr = i_a[3] +"."+ i_a[2] +"."+ i_a[1] +"."+ i_a[0]
                    dns_id = pkt[5]
                    pc.dns_req[(dns_id, src)] = [pkt_time, ip_addr]
                    #print "DNS query: ", dns_id, "PTR", pc.dns_req[(dns_id,'PTR')]

            # Need to clean-up unanswered requests from dns_req dictionary  
            keys_to_pop = []
            for a_key in pc.dns_req:
                if (pc.dns_req[a_key][0] < (time.time() - \
                                      float(trafcap.session_expire_timeout))):
                    keys_to_pop.append(a_key)

            for a_key in keys_to_pop:
                pc.dns_req.pop(a_key)

        except Exception as e:
            print(str(e))
            traceback.print_exc()
            raise Exception("Unable to parse DNS traffic." )

        if (len(ip_list) > 0 or len(name_list) > 0):
            # Converting list with one item into a tuple results in 
            # tuple with the one item and an empty / blank item:
            #     tuple(['123']) = ('123',)
            return pkt_time, [first_reply_type, name_list, '', ip_list]
        else:
            return pkt_time, [] 


class NmiContainer(object):
    """
    Manages data dictionaries and writes accumulated data to db 
    """

    def __init__(self, packet_class, nmi_col_name):
        self.pc = packet_class
        self.collection = nmi_col_name
        self.dict = {}
        self.db = None

        if trafcap.options.mongo:
            self.db = trafcap.mongoSetup()

        return

    def update(self, pkt_time, list):
        # Store the result in a dictionary.  Only write to db if it is 
        # a new result or if the result was not recently written to the dict.
        # This keeps large numbers of redundant results (like ARP traffic) 
        # from being written to the db.


        nmi_doc = {'t':pkt_time, 'r':list[0]}
        if len(list[1]) > 0 :  
            nmi_doc.update({'n':list[1]})

        if list[2] != '' :   
            mac_char = re.sub(':', "", list[2])
            mac_long = int(mac_char, 16)
            nmi_doc.update({'m':mac_long})
        
        ip_long_list = []
        for a_ip in list[3]:
            #try:
            #    ip_int = struct.unpack('L',socket.inet_aton(a_ip)[::-1])[0]
            #except socket.error:
            #     raise ValueError('Invalid value "' + a_ip + '" for IP')
            ip_long_list.append(trafcap.stringToInt(a_ip))
             
        if len(ip_long_list) > 0 : 
            nmi_doc.update({'i':ip_long_list})

        #nmi_doc.update({'tc':datetime.utcfromtimestamp(
        #                              trafcap.secondsToMinute(time.time()))})

        nmi_doc.update({'tm':trafcap.secondsToMinute(time.time())})

        try:
            # Change the key from a list of lists into a tuple of tuples
            # type, name, mac, ip
            key = (list[0], tuple(list[1]), list[2], tuple(list[3]))
            last_time = self.dict[key]
            if pkt_time - last_time > trafcap.nmi_db_update_wait_time:
                self.dict[key] = pkt_time
                if not trafcap.options.quiet:
                    print(pkt_time, list)  

                if trafcap.options.mongo:
                    self.db[self.collection].insert(nmi_doc, manipulate=False)
        
        except KeyError:
            self.dict[key] = pkt_time
            if not trafcap.options.quiet:
                print(pkt_time, list) 

            if trafcap.options.mongo:
                self.db[self.collection].insert(nmi_doc, manipulate=False)


        # Clean-up the dictionary
        keys_to_pop = []
        for key in self.dict:
            # If the dictionary entry is old enough that it will be updated 
            # then delete it - a new entry will be created if needed.
            if (pkt_time - self.dict[key]) > trafcap.nmi_db_update_wait_time :
                keys_to_pop.append(key)

        for key in keys_to_pop:
            self.dict.pop(key)

        return

