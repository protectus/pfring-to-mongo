# trafcap.py - module for traffic capture
#
# Copyright (c) 2013 Protectus,LLC.  All Rights Reserved.
#
import time
import ConfigParser
import socket
import struct
import re
from calendar import timegm
from datetime import datetime
import traceback
import sys
import GeoIP
import json
# Include sentry-hardware which defines network interfaces
sys.path.extend(['/opt/sentry/hardware'])
import sentryHardware

last_seq_off_the_wire = 0
current_time = 0.

# Variable to allow access of command-line options across multiple modules
options = None

# Regex copied from kwebapp parse.py 11/02/12 --TCG
CIDR_RE = re.compile("""
    ^                              #Start of String
    [ \t]*                         #Allow extra whitespace
    (?P<ipstr>(?P<oct1>[0-9]{1,3}) #First octet
    [.]                            #Single dot
    (?P<oct2>[0-9]{1,3})           #Second octet
    [.]
    (?P<oct3>[0-9]{1,3})           #Third octet
    [.]
    (?P<oct4>[0-9]{1,3}))          #Forth octet
    ([/](?P<subnet>[0-9]{1,2}))?   #Subnet Bits (optional)
    [ \t]*
    $                              #End of String
""", re.X)

ASN_RE = re.compile("""
    .*
    AS                             # ASN Number prefix
    (?P<asn>[0-9]{1,10})           # the ASN number
    [ ]                            # One space
    (?P<name>.*)                   # ASN Org Name
""", re.X)

def convertLocalSubnets(local_subnet_strings):
    """
    Converts local_subnet strings from config file into a list of tuples.
    local_subnet_strings is of the form:
    [('subnet2', '10,0,0,0'), ('subnet1', '192,168,0,0'), ('subnet3', '172,16,0,0')]
    """
 
    local_subnets = []
    for subnet in local_subnet_strings:
        subnet_string = subnet[1]
        try:
            match = CIDR_RE.match(subnet_string)
            octets = [
                int(match.group("oct1")),
                int(match.group("oct2")),
                int(match.group("oct3")),
                int(match.group("oct4"))
            ]
            subnet_mask_size = int(match.group("subnet"))

        except AttributeError:
            raise ValueError('Subnet string "' + subnet_string + '" is not valid.')

        if subnet_mask_size % 8 != 0:
            raise ValueError("Subnet masks must use entire octets. ( subnet % 8 != 0 )")

        if octets[0]>254 or octets[1]>254 or octets[2]>254 or octets[3]>254:
                    raise ValueError("Octet value greater than 254")

        octets_masked = 4 - (subnet_mask_size / 8)
        octets[4-octets_masked:] = [0] * octets_masked
            
        local_subnets.append(tuple(octets))
    return local_subnets

def refreshConfigVars():
    global error_log, session_expire_timeout, latency_expire_timeout
    global store_timeout, bytes_to_read, nmi_db_update_wait_time
    global cap_filter, sniff_interface, network_interface
    global lrs_min_duration, rtp_portrange, http_save_url_qs
    global local_subnets, local_subnet, config, ingest_vlan_id
    global mongo_server, mongo_port, traffic_db, traffic_ttl
    global inj_filter, inj_timeout, cc_list_type, cc_list
    global suricata_cap_filter
    global packet_ring_buffer_size, saved_session_ring_buffer_size 
    global live_session_buffer_size, group_buffer_size, group2_buffer_size
    # Read settings from config file
    config = ConfigParser.SafeConfigParser()
    config.optionxform = str  # Read config keys case sensitively.
    config.read(['/opt/sentry/etc/sentry.conf', '/opt/sentry/trafcap/trafcap.conf', '/opt/sentry/etc/custom_settings.conf'])
    error_log = config.get('trafcap', 'error_logfile')
    session_expire_timeout = config.getint('trafcap', 'session_expire_timeout')
    latency_expire_timeout = config.getint('trafcap', 'latency_expire_timeout')
    store_timeout = config.getint('trafcap', 'store_timeout')
    bytes_to_read = config.getint('trafcap', 'bytes_to_read')
    nmi_db_update_wait_time=config.getfloat('trafcap', 'nmi_db_update_wait_time')
    cap_filter = config.get('trafcap', 'cap_filter')
    inj_filter = config.get('trafcap', 'inj_filter')
    inj_timeout = config.getint('trafcap', 'inj_timeout')
    cc_list_type = config.get('trafcap', 'cc_list_type').lower()
    cc_list = json.loads(config.get('trafcap', 'cc_list'))

    # Default is to obtain interface names from networking files in /etc.
    # Entry in config file can be used to override hardware settings.
    try:
       network_interface = config.get('interface', 'network_interface')
    except (ConfigParser.NoOptionError, ConfigParser.NoSectionError):
       network_interface = sentryHardware.getNetworkInterface()
    #
    try:
       sniff_interface = config.get('interface', 'sniff_interface')
    except (ConfigParser.NoOptionError, ConfigParser.NoSectionError):
       sniff_interface = sentryHardware.getSniffInterface()

    lrs_min_duration = config.getint('trafcap', 'lrs_min_duration')
    rtp_portrange = config.get('trafcap', 'rtp_portrange')
    http_save_url_qs = config.getboolean('trafcap', 'http_save_url_qs')
    ingest_vlan_id = config.getboolean('trafcap', 'ingest_vlan_id')
    suricata_cap_filter = config.get('trafcap', 'suricata_cap_filter')

    # Convert local_subnet strings from config file into a list of tuples
    local_subnets = config.items('local_subnets')
    local_subnet = convertLocalSubnets(local_subnets)

    mongo_server = config.get('mongo', 'mongo_server')
    mongo_port = config.getint('mongo', 'mongo_port')
    traffic_db = config.get('mongo', 'traffic_db')
    traffic_ttl = config.get('mongo', 'traffic_ttl')

    packet_ring_buffer_size = config.getint('trafcap', 'packet_ring_buffer_size')
    live_session_buffer_size = config.getint('trafcap', 'live_session_buffer_size')
    saved_session_ring_buffer_size = config.getint('trafcap', 'saved_session_ring_buffer_size')
    group_buffer_size = config.getint('trafcap', 'group_buffer_size')
    group2_buffer_size = config.getint('trafcap', 'group2_buffer_size')

    # Also get and store the current installed system version.
    global system_version
    
    sentry_version_file = open('/etc/sentry_version')
    system_version = sentry_version_file.readline().strip()
    sentry_version_file.close()

refreshConfigVars()

# Returns True if the ip is in the local subnet
# Improvement needed to handle case of 0 in the subnet IP address
def inLocalSubnet(local_subnet, ip):
    for subnet_index, subnet in enumerate(local_subnet):
        in_local_subnet=True
        for octet_index, octet in enumerate(local_subnet[subnet_index]):
            if (local_subnet[subnet_index][octet_index] != 0):
                if (local_subnet[subnet_index][octet_index]!=ip[octet_index]):
                    in_local_subnet=False
                    break
        if in_local_subnet:
            return True
        else:
            continue
    return False

# Convert IP address from tuple to int for storage
def tupleToInt(ip):
    ip_str = ['a','b','c','d']
    for i in range(0,4,1):
        ip_str[i] = hex(ip[i])[2:4]
        if len(ip_str[i]) == 1:
            ip_str[i] = "0" + ip_str[i]
    
    ip_int = int(ip_str[0]+ip_str[1]+ip_str[2]+ip_str[3], 16)
    return long(ip_int)

def intToTuple(ip):
    return (int(ip >> 24& 0xFF),int(ip >> 16& 0xFF), 
            int(ip >> 8& 0xFF), int(ip & 0xFF))

def stringToInt(ip):
    try:
        ip_int = struct.unpack('<L',socket.inet_aton(ip)[::-1])[0]
    except socket.error:
        raise ValueError('Invalid value "' + ip + '" for IP')
    return long(ip_int)

def intToString(ip):
    try:
        ip_str = socket.inet_ntoa(struct.pack('!L', ip))
    except socket.error:
        raise ValueError('Invalid value "' + ip + '" for IP')
    return str(ip_str)

def tupleToString(ip):
    return str(ip[0])+"."+str(ip[1])+"."+str(ip[2])+"."+str(ip[3])

# Python time struct details found here:
# http://docs.python.org/library/time.html#time.struct_time

def findChunckBoundary(t, sec):
    sec = int(sec)
    t_s = time.gmtime(t)
    if sec < 60:
        boundary = int(float(t_s[5])/float(sec)) * sec
        t_struct_boundary = (t_s[0], t_s[1], t_s[2], t_s[3], t_s[4],
                             boundary, t_s[6], t_s[7], t_s[8])
    else:
        min = int(float(sec)/60.0)
        boundary = int(float(t_s[4])/float(min)) * min
        t_struct_boundary = (t_s[0], t_s[1], t_s[2], t_s[3], boundary,
                             0, t_s[6], t_s[7], t_s[8])
        
    tm = timegm(t_struct_boundary)
    return int(tm)

def findWindowBoundary(t, min):
    min = int(min)
    t_s = time.gmtime(t)
    if min < 60:
        boundary = int(float(t_s[4])/float(min)) * min
        t_struct_boundary = (t_s[0], t_s[1], t_s[2], t_s[3], boundary,
                             0, t_s[6], t_s[7], t_s[8])
    else:
        hour = int(float(min)/60.0)
        boundary = int(float(t_s[3])/float(hour)) * hour 
        t_struct_boundary = (t_s[0], t_s[1], t_s[2], boundary, 0,
                             0, t_s[6], t_s[7], t_s[8])
        
    tm = timegm(t_struct_boundary)
    return int(tm)

def findSecondsBoundary(t, sec):
    t_s = time.gmtime(t)
    boundary = int(float(t_s[5])/float(sec))*sec
    t_struct_boundary = (t_s[0], t_s[1], t_s[2], t_s[3], t_s[4],
                               boundary, t_s[6], t_s[7], t_s[8])
    tm = timegm(t_struct_boundary)
    return int(tm)

def findMinuteBoundary(t, min):
    t_s = time.gmtime(t)
    boundary = int(float(t_s[4])/float(min))*min
    t_struct_boundary = (t_s[0], t_s[1], t_s[2], t_s[3], boundary,
                           0, t_s[6], t_s[7], t_s[8])
    tm = timegm(t_struct_boundary)
    return int(tm)

# Convert seconds to 10 second value
def secondsTo10Seconds(t):
    t_s = time.gmtime(t)
    ten_second = int(float(t_s[5])/10.0)*10
    t_struct_ten_second = (t_s[0], t_s[1], t_s[2], t_s[3], t_s[4],
                               ten_second, t_s[6], t_s[7], t_s[8])
    tm = timegm(t_struct_ten_second)
    return int(tm)

# Convert seconds to minute
def secondsToMinute(t):
    t_s = time.gmtime(t)
    t_struct_minute = (t_s[0], t_s[1], t_s[2], t_s[3], 
                       t_s[4], 0, t_s[6], t_s[7], t_s[8]) 
    tm = timegm(t_struct_minute)
    return int(tm)

# Convert seconds to 2 minute (120 seconds) value
def secondsTo2Minute(t):
    t_s = time.gmtime(t)
    two_minute = int(float(t_s[4])/2.0)*2
    t_struct_two_minute = (t_s[0], t_s[1], t_s[2], t_s[3], two_minute,
                           0, t_s[6], t_s[7], t_s[8])
    tm = timegm(t_struct_two_minute)
    return int(tm)

# Convert seconds to 15 minute value
def secondsTo15Minute(t):
    t_s = time.gmtime(t)
    fifteen_minute = int(float(t_s[4])/15.0)*15
    t_struct_fifteen_minute = (t_s[0], t_s[1], t_s[2], t_s[3], fifteen_minute,
                               0, t_s[6], t_s[7], t_s[8])
    tm = timegm(t_struct_fifteen_minute)
    return int(tm)

# Convert seconds to 3 hour value
def secondsTo3Hour(t):
    t_s = time.gmtime(t)
    three_hour = int(float(t_s[3])/3.0)*3
    t_struct_three_hour = (t_s[0], t_s[1], t_s[2], three_hour, 0,
                           0, t_s[6], t_s[7], t_s[8])
    tm = timegm(t_struct_three_hour)
    return int(tm)

import os, sys
def checkIfRoot():
    if os.geteuid() != 0:
        sys.exit('Program must be run as root.')


#pymongo bindings
#sys.path.append('/opt/sentry/trafcap/lib')

def mongoSetup(**kwargs):
    from pymongo import MongoClient
    conn = MongoClient(host=mongo_server,
                       port=mongo_port,**kwargs)
    db = conn[traffic_db]

    # DB is not actually created until something is written.  Ensure db exixts,
    # even if it is empty, to prevent downstream errors in certain situations.
    coll_names = db.collection_names()
    if len(coll_names) == 0:
        db['config'].insert_one({'x': 1})
        db['config'].delete_one({'x': 1})
    return db

def chkUtf8(a_string):
    # If string is not None, ensure it is in UTF8 format; else return None
    return a_string.decode('utf8', 'ignore') if a_string else a_string

gi = GeoIP.open("/opt/sentry/geoip/GeoLiteCity.dat",GeoIP.GEOIP_STANDARD)
def geoIpLookup(ip_addr):
    # ip_addr is a string representing a dotted quad
    g_addr = gi.record_by_addr(ip_addr)
    if g_addr == None:
        addr_cc = None 
        addr_name = None 
        addr_loc = None
        addr_city = None
        addr_region = None
    else:
        # Fields could be non-UTF8 or could be None
        addr_cc = chkUtf8(g_addr['country_code'])
        addr_name = chkUtf8(g_addr['country_name'])
        addr_loc = [g_addr['longitude'], g_addr['latitude']]
        addr_city = chkUtf8(g_addr['city'])
        addr_region = chkUtf8(g_addr['region_name'])
    return addr_cc, addr_name, addr_loc, addr_city, addr_region

def geoIpLookupTpl(ip_addr):
    return geoIpLookup(tupleToString(ip_addr))

def geoIpLookupInt(ip_addr):
    return geoIpLookup(intToString(ip_addr))

ga_filename="/opt/sentry/geoip/GeoIPASNum.dat"
ga = GeoIP.open(ga_filename, GeoIP.GEOIP_STANDARD)
def geoIpAsnLookup(ip_addr):
    # Returns org info given a string representing a dotted quad
    g_org = ga.org_by_addr(ip_addr)
    if g_org == None:
        org_asn = None
        org_name = None
    else:
        try:
            # Returned format:    AS15169 Google Inc.
            index = g_org.index(' ')
            org_asn, org_name = g_org[:index], g_org[index+1:]
        except ValueError:
            # Returned format:  AS15457
            org_asn = g_org.strip()
            org_name = None
    return org_asn, chkUtf8(org_name)

def geoIpAsnLookupTpl(ip_addr):
    return geoIpAsnLookup(tupleToString(ip_addr))

def geoIpAsnLookupInt(ip_addr):
    return geoIpAsnLookup(intToString(ip_addr))


def readAsnFile(asn_file):
    # Loads the binary db into a dictionary of ints to strings
    result = {}
    for line in asn_file:
        if "AS" not in line:
            continue
        
        for item in line.split('\x00'):
            match = ASN_RE.match(item)
            if match is None:
                continue

            asn = int(match.group("asn"))
            name = match.group("name")
            result[asn] = name

    if len(result) == 0:
        print "Warning: No ASN names found to load in readAsnFile"

    return result
    

asn_names = None
def initAsnNames():
    global asn_names

    if asn_names is not None:
        # Nothing to do
        return

    with open(ga_filename) as asn_file:
        asn_names = readAsnFile(asn_file)


def geoIpAsnNameLookupInt(asn):
    if asn_names is None:
        raise RuntimeError("ASN Database has not been initialized")

    return asn_names.get(asn, None)
    

from dns import resolver,reversename
dns_resolver = resolver.Resolver()
# Set arbitrary 1 second timeouts
dns_resolver.timeout = 1
dns_resolver.lifetime = 1
def dnsPtrRecLookup(ip_addr):
    # Returns PTR record string given a string representing a dotted quad
    addr=reversename.from_address(ip_addr)
    try:
        answer = str(dns_resolver.query(addr,'PTR')[0])   # dns.resolver.Answer
        answer = answer.rstrip('.')
    except:
        answer = ''
    return answer

def dnsPtrRecLookupInt(ip_addr):
    return dnsPtrRecLookup(intToString(ip_addr))

def dnsMxRecLookup(domain_name):
    # Give a string domain name, returns MX rec list somewhat sorted by 
    # decreasing priority (increasing MX record preference field) 
    previous_preference = None 
    mx_list = [] 
    try:
        answer = dns_resolver.query(domain_name, 'MX')
        for rdata in answer:
            if not mx_list:  
                # mx_list is empty
                mx_list.append(str(rdata.exchange).rstrip('.'))
                previous_preference = rdata.preference
                continue
            if rdata.preference >= previous_preference:
                mx_list.append(str(rdata.exchange).rstrip('.'))
            else:
                mx_list.insert(0, str(rdata.exchange).rstrip('.'))
            previous_preference = rdata.preference
    except:
        mx_list = [] 
    return mx_list 

# stores Suricata classification info for use during IDS event ingest
classification_config_dict = None

def logException(exception, **kwargs):
    arg_names = kwargs.keys()
    a_file = open(error_log,'a')

    if not options.quiet:
        print('\n=========== Logging Exception =================')
        print (str(datetime.now())+'\n')
        print exception
        print traceback.format_exc()
    a_file.write('\n=========== Logging Exception =================\n')
    a_file.write(str(datetime.now())+'\n')
    a_file.write(exception.__str__())
    a_file.write(traceback.format_exc())

    for arg_name in arg_names:
        arg = kwargs[arg_name]
        if not options.quiet:
            print '\n-------------' + arg_name + '------------------'
        a_file.write('\n-------------' + arg_name + '------------------\n')

        if type(arg) == str: 
           if not options.quiet: print arg 
           a_file.write(arg)

        elif type(arg) == list or type(arg) == tuple:
            for item in arg: 
                if not options.quiet: print item 
                a_file.write(item)
        else:
            a_type = type(arg)
            msg = 'Invalid parameter type  '+str(a_type)+'  passed to logException()'
            if not options.quiet:
                print msg
            a_file.write(msg + '\n')

    sys.stdout.flush()
    a_file.close()
 
def stringToDigit(arg):
    # change numbers from strings to ints
    if type(arg) is str:
        if arg.isdigit():
            return int(arg) 
    return arg

# item[0] = collection name   
# item[1] = list of index(es)
# item[1][i] = [ [index info], {optional kwarg dictionary} ]
collection_info = (
('tcp_sessionInfo',    [[[('tem',1),('tbm',1),('ip1',1),('ip2',1),('p2',1)]],
                        [[('tdm',1)], {'sparse':True} ]]),
('tcp_sessionBytes',   [[[('sem',1),('sbm',1),('p2',1),('ip1',1),('ip2',1)]]]),
('tcp_captureBytes',   [[[('sem',1),('sbm',1)]]]),
('tcp_sessionGroups',  [[[('tem',1),('tbm',1),('ip1',1),('ip2',1),('p2',1)]]]),
('tcp_captureGroups',  [[[('tem',1),('tbm',1)]]]),
('tcp_sessionGroups2', [[[('tem',1),('tbm',1),('ip1',1),('ip2',1),('p2',1)]]]),
('tcp_captureGroups2', [[[('tem',1),('tbm',1)]]]),
#('tcp_captureInfo',    [ ]),
('udp_sessionInfo',    [[[('tem',1),('tbm',1),('ip1',1),('ip2',1),('p2',1)]],
                        [[('tdm',1)], {'sparse':True} ]]),
('udp_sessionBytes',   [[[('sem',1),('sbm',1),('p2',1),('ip1',1),('ip2',1)]]]),
('udp_captureBytes',   [[[('sem',1),('sbm',1)]]]),
('udp_sessionGroups',  [[[('tem',1),('tbm',1),('ip1',1),('ip2',1),('p2',1)]]]),
('udp_captureGroups',  [[[('tem',1),('tbm',1)]]]),
('udp_sessionGroups2', [[[('tem',1),('tbm',1),('ip1',1),('ip2',1),('p2',1)]]]),
('udp_captureGroups2', [[[('tem',1),('tbm',1)]]]),
#('udp_captureInfo',    [ ]),
('icmp_sessionInfo',   [[[('tem',1),('tbm',1),('ip1',1),('ip2',1),('ty1',1)]],
                       [[('tdm',1)], {'sparse':True} ]]),
('icmp_sessionBytes',  [[[('sem',1),('sbm',1),('ty1',1),('ip1',1),('ip2',1)]]]),
('icmp_captureBytes',  [[[('sem',1),('sbm',1)]]]),
('icmp_sessionGroups', [[[('tem',1),('tbm',1),('ip1',1),('ip2',1),('ty1',1)]]]),
('icmp_captureGroups', [[[('tem',1),('tbm',1)]]]),
('icmp_sessionGroups2',[[[('tem',1),('tbm',1),('ip1',1),('ip2',1),('ty1',1)]]]),
('icmp_captureGroups2',[[[('tem',1),('tbm',1)]]]),
#('icmp_captureInfo',   [ ]),
('oth_sessionInfo',    [[[('tem',1),('tbm',1),('s',1),('d',1),('m',1)]],
                        [[('tdm',1)], {'sparse':True} ]]),
('oth_sessionBytes',   [[[('sem',1),('sbm',1),('m',1),('s',1),('d',1)]]]),
('oth_captureBytes',   [[[('sem',1),('sbm',1)]]]),
('oth_sessionGroups',  [[[('tem',1),('tbm',1),('s',1),('d',1),('m',1)]]]),
('oth_captureGroups',  [[[('tem',1),('tbm',1)]]]),
('oth_sessionGroups2', [[[('tem',1),('tbm',1),('s',1),('d',1),('m',1)]]]),
('oth_captureGroups2', [[[('tem',1),('tbm',1)]]]),
#('oth_captureInfo',   [ ]),
('nmi',                [[ [('tm',1),('i',1)] ]]),
('http_eventInfo',     [[ [('tm',1)] ]])
)

def redoIndex(db, c_name, c_indxs):
    print ' Redo index on ', c_name
    db[c_name].drop_indexes()
    for a_index in c_indxs:
        if len(a_index) == 2:
            # index with kwargs (e.g. sparse)
            db[c_name].create_index(a_index[0], **a_index[1])
        elif len(a_index) == 1:
            # index with no kwargs
            db[c_name].create_index(a_index[0])
        else:
            # no index
            pass
    

def ensureIndexes(collection_tuple):
    db = mongoSetup()
    index_info = None
    print 'Checking indexes...'

    coll_names = db.collection_names()

    for c_info in collection_tuple:
        c_name = c_info[0]
        c_indxs = c_info[1]

        # Verify number of indexes
        spec_index_count = len(c_indxs)

        # Check if collection exist.  Writing data creates it
        if not c_name in coll_names:
            db[c_name].insert_one({'x': 1})
            db[c_name].delete_one({'x': 1})
            # Collection will now contain an _id index

        # index_info is a dictionary provided by mongo, includes _id index
        index_info = db[c_name].index_information()

        actual_index_count = len(index_info) - 1  # do not count _id index

        if spec_index_count != actual_index_count:
            redoIndex(db, c_name, c_indxs)
            continue

        for spec_index in c_indxs:
            spec_index_string = ''
            for spec_field in spec_index[0]:
                spec_index_string += spec_field[0]+'_' 
                spec_index_string += str(spec_field[1])+'_'

            # remove trailing underscore
            spec_index_string = spec_index_string[:-1]

            try:
                if index_info[spec_index_string]:
                    # check for optional index parameters (e.g. sparse)
                    if len(spec_index[0]) != \
                       len(index_info[spec_index_string]['key']):
                        redoIndex(db, c_name, c_indxs)
                        continue

                    if len(spec_index) == 2:  # index spec has optional params
                        spec_kwarg_dict = spec_index[1]
                        for key in spec_kwarg_dict:
                           try:
                               if index_info[spec_index_string][key]:
                                   pass
                           except KeyError:
                               redoIndex(db, c_name, c_indxs)
                               continue
            except KeyError:    
                redoIndex(db, c_name, c_indxs)
            
