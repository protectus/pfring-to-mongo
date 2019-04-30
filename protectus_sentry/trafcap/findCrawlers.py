#!/usr/bin/python
#
# Copyright (c) 2013 Protectus,LLC.  All Rights Reserved.
#


import sys, time, os, signal
from select import select
import socket
import traceback
from datetime import datetime
import subprocess
from optparse import OptionParser
import math
import configparser
from datetime import timedelta
from operator import itemgetter
import re
import locale
locale.setlocale(locale.LC_ALL, 'en_US.utf8')

from protectus_sentry.trafcap import trafcap
import pymongo
from sets import Set
from . import trafinj 
import smtplib

start_bold = "\033[1m"
end_bold = "\033[0;0m"

def parseOptions():
    usage = "usage: %prog c | i(b|u) | i(glmnptv) | h"
    parser = OptionParser(usage)
    parser.add_option("-a", "--array", dest="array",
                      type="int", default=90,
                      help="# items in array needed for hit")
    parser.add_option("-b", "--block", dest="block",
                      default=False, action='store_true',
                      help="add ip to ip block list")
    parser.add_option("-c", "--config", dest="config",
                      default=False, action='store_true',
                      help="create config docs in mongo")
    parser.add_option("-d", "--days", dest="days",
                      type="int",
                      help="search back this many days")
    parser.add_option("-e", "--email", dest="email",
                      default=False, action='store_true',
                      help="send blocked IP email notification")
    parser.add_option("-i", "--ip", dest="ip",
                      action="store", default="",
                      help="target ip")
    parser.add_option("-l", "--limit", dest="limit",
                      type="int", default=100,
                      help="search results limit")
    parser.add_option("-m", "--mongo", dest="mongo",
                      default=False, action='store_true',
                      help="write IP addrs to mongo")
    parser.add_option("-n", "--minutes", dest="minutes",
                      type="int", 
                      help="search back this number of minutes")
    parser.add_option("-p", "--port", dest="port",
                      type="int", default=80,
                      help="target port")
    parser.add_option("-g", "--groups", dest="groups",
                      type="int", default=1,
                      help="collection to search: g0=bytes, g1=groups, g2=groups2")
    parser.add_option("-s", "--source", dest="source",
                      action="store", default="",
                      help="source ip")
    parser.add_option("-t", "--timeout", dest="timeout",
                      type="int", default=2592000,
                      help="blocking timeout in seconds")
    parser.add_option("-u", "--unblock", dest="unblock",
                      default=False, action='store_true',
                      help="remove ip from block list")
    parser.add_option("-v", "--verbose", dest="verbose",
                      default=False, action='store_true',
                      help="print CSV report to stdout")
    (options, args) = parser.parse_args()
    return options

def sizeof_readable(num):
    for x in [' ','K','M','G']:
        if num < 1000.0:
            return "%3.0f%s" % (num, x)
            #return "%3.1f%s" % (num, x)
        num /= 1000.0
    return "%3.1f%s" % (num, 'TB')

def sizeof_readable_bytes(num):
    for x in ['B','KB','MB','GB']:
        if num < 1024.0:
            return "%3.0f%s" % (num, x)
            #return "%3.1f%s" % (num, x)
        num /= 1024.0
    return "%3.1f%s" % (num, 'TB')

def createDefaultConfigDocs():
    config_docs = []

    # Suspect IPs to ignore doc.  Are currently subnets may someday 
    # include IP addresses also.
    # Format is ['regex applied to hostname', 'regex applied to user agent']
    config_docs.append({
        'doc_type' : 'names_to_ignore',
        'nti' : [
            ['', 'botify'],
            ['\.ahrefs\.com$', 'AhrefsBot'],
            ['\.amazonaws\.com$', 'ia_archiver'],
            ['\.amazonaws\.com$', 'rogerbot'],
            ['\.amazonaws\.com$', 'deepcrawl.com'],
            ['\.sogou\.com$', 'Sogou web spider'],
            ['\.bjtelecom\.net$', 'Sogou web spider'],
            ['\.bjtelecom\.net$', 'www.sogou.com'],
            ['\.exabot\.com$', 'Exabot'],
            ['\.google\.com$', 'AdsBot-Google'],
            ['\.google\.com$', 'Feedfetcher-Google'],
            ['\.google\.com$', 'GoogleDocs'],
            ['\.google\.com$', 'GoogleImageProxy'],
            ['\.google\.com$', 'Googlebot-Mobile'],
            ['\.googlebot\.com$', ''],
            ['^.*-proxy-.*\.google\.com$', ''],
            ['^.*googleusercontent\.com$', ''],
            ['\.mail\.ru$', 'Mail.RU Bot'],
            ['\.majestic12\.co\.uk$', 'MJ12bot'],
            ['\.msn\.(com|net)$', 'adidxbot'],
            ['\.msn\.(com|net)$', 'bingbot'],
            ['\.msn\.(com|net)$', 'BingPreview'],
            ['\.msn\.(com|net)$', 'msnbot'],
            ['\.paypal\.com$', 'PayPal IPN'],
            ['scan.\.ws\.symantec\.com$', ''],
            ['scan..\.ws\.symantec\.com$', ''],
            ['\.search\.msn\.com$', ''],
            ['\.securefastserver\.com$', 'deepcrawl.com'],
            ['\.sputnik\.ru$', 'SputnikBot'],
            ['\.seokicks\.de$', 'SEOkicks-Robot'],
            ['\.webmeup\.com$', 'BLEXBot'],
            ['\.wotbox\.com$', 'Wotbox'],
            ['\.yahoo\.net$', 'Yahoo! Slurp'],
            ['\.yandex\.com$', 'Yandex']
        ]
    })
            # No longer needed - IPs now have a hostname
            #[[106,120,173], ''],    # Sogou.com
    
    # Names to ignore doc
    # An empty string for the user_agent allows port 443 traffic 
    # to be ignored for the corresponding domain name.
    # Format is: [[ip_addr_or_subnet], 'regex applied to hostname']
    config_docs.append({
        'doc_type' : 'suspects_to_ignore',
        'sti' : [
            [[5,9,77], ''],           # Symantec
            [[17,], 'Applebot'],      # http://www.apple.com/go/applebot
            [[38,123,140], ''],       # TrustGuard
            [[46,4,85], ''],          # Symantec
            [[46,4,94], ''],          # Symantec
            [[46,4,95], ''],          # Symantec
            [[67,23,144], ''],        # Office TW
            [[67,192,122], ''],       # Symantec
            [[68,180,231], 'Yahoo! Slurp'],  # http://help.yahoo.com/help/us/ysearch/slurp
            [[72,3,209], ''],         # old ECS site
            [[72,89,243,84], ''],     # 72.89.243.84 - Flying Point per Bruce
            [[74,120,180], ''],       # shopping.com, allow 443 w/ no ua
            [[74,120,183], ''],       # shopping.com, allow 443 w/ no ua
            [[74,125,77], ''],        # google subnet, allows 443 w/ no hostname
            [[74,125,185], ''],       #  google subnet, allows 443 w/ no hostname
            [[96,84,220,226], ''],    # Turner Motorsport
            [[96,95,192], ''],        # Tom Long - Bertram
            [[98,100,70], ''],        # Office RR Cable
            [[108,75,123,61], ''],    # Dava Anna home office - SEO testing as per Lori 
            [[141,101,76], ''],       # Cloudflare 
            [[141,101,77], ''],       # Cloudflare 
            [[121,189,37], 'ZumBot'], # Zumbot, help.zum.com/inquiry
            [[121,241,106,173], ''],  # Developers in India as per Lori, 09Mar2016
            [[162,220,244,204], ''],  # as per Lori, 16May2016
            [[173,194,97], ''],       # google subnet, allows 443 w/ no hostname
            [[173,252], 'facebookexternalhit'],  # as per Kinsley 20may2016
            [[204,232,241], ''],      # Symantec
            [[205,203,134], 'Dow Jones'],    # Dow Jones Searchbot
            [[206,180,172], ''],      # Protectus 
            [[208,138,254], 'Dow Jones'],    # Dow Jones Searchbot
            [[207,141,153], ''],      # Bertram
            [[207,58,204], ''],       # Office Fidelity
            [[208,90,212], ''],       # per Bruce 11/2/15
            [[208,138,254], '']       # Dow Jones Searchbot
        ]
    })

# Blocked 9/22/15 as per discussion 
#            ['\.your-server\.de$', 'MegaIndex.ru'],

    # This function does not overwrite or modify existing docs.
    # To modify, must first delete docs manually
    trafinj.createDefaultInjectConfigDocs(config_docs)
    
# Delete this function...............
################################
def getSampleUa(db, src_ip):
    # test cases
    #src_ip = 2886794762  # src ip not in collection, returns None
    #src_ip = 1205129673  # valid ua, reutrns {_id:123, ua:'lalala'}
    #src_ip = 1188106663  # ua field does not exist {_id:345}
    try:
        result = db['http_eventInfo'].find({'src':src_ip}).distinct('ua')
        return result[0] 
    except:  # src_ip does not have UA
        return 'No user agent'

def countPath(db, src_ip, url_path):
    return db['http_eventInfo'].find({'src':src_ip, 'path': {'$regex':url_path}}).count()

def getQuerySeconds():
    etime_then = int(time.time()) - (trafcap.options.minutes * 60)
    return etime_then

def getByteArrayItemCount(db, coll_name, src_ip):
    return db.command({
    'aggregate': coll_name,
    'pipeline': [
        {'$match': {'sem': {'$gt': getQuerySeconds()},
                    'ip1': src_ip
        }},
        {'$group': {
            '_id': {'ip1':'$ip1'},
            'total': {'$sum':{'$size':'$b'}}
        }},
        {'$project': {
            '_id':0, 
            'total':1,
            'ip1':'$_id.ip1'
        }}
    ],
    'allowDiskUse': True
    })

def getAllUa(db, src_ip):
    # test cases
    #src_ip = 2886794762  # src ip not in collection, returns [] 
    #src_ip = 1205129673  # valid ua, reutrns [{count:1, ua:'lalala'},{...}]
    #src_ip = 1188106663  # ua field does not exist [{count:2, ua:None}]
    try:
        ua_list = db['http_eventInfo'].find({'src':src_ip}).distinct('ua')
        #result = db.command({
        #'aggregate': "http_eventInfo",
        #'pipeline': [
        #    {'$match': {'src': src_ip
        #    }},
        #    {'$group': {
        #        '_id': {'ua':'$ua'},
        #        'count': {'$sum':1}
        #    }},
        #    {'$project': {
        #        '_id':0, 'count':1,
        #        'ua':'$_id.ua'
        #    }},
        #    {'$limit': trafcap.options.limit }
        #],
        #'allowDiskUse': True
        #})
        #ua_list = result['result']
    except:
        ua_list= []

    return ua_list 


def getGroupsResult(db, collection, sort_dict, bytes_array_len):
    query_result = db.command({
    'aggregate': collection,
    'pipeline': [
        {'$match': {'tem': {'$gt': getQuerySeconds()},
                    'ip2': trafcap.stringToInt(trafcap.options.ip),
                    'p2': trafcap.options.port,
                    'b': {'$size': bytes_array_len}
        }},
        {'$group': {
            '_id': {'ip1':'$ip1'},
            'cc1': {'$max':'$cc1'},  #cc1 sometimes null - not sure why
            'cc2': {'$max':'$cc2'},  #cc2 sometimes not null - not sure why
            'b1': {'$sum': '$b1'},
            'b2': {'$sum': '$b2'},
            'count': {'$sum':1}
        }},
        {'$project': {
            '_id':0, 'b1':1, 'b2':1, 'count':1, 'cc1':1, 'cc2':1,
            'ip1':'$_id.ip1'
        }},
        sort_dict,
        {'$limit': trafcap.options.limit }
    ],
    'allowDiskUse': True
    })
    # If query yields no results, dict is:  {u'ok': 1.0, u'result': []}
    return query_result


def getInfoResult(db, collection, sort_dict, source_ip, dst_port, time_gt):
    if source_ip:
        match_doc = {'$match': {'tem': {'$gt': time_gt},
                                'ip1': trafcap.stringToInt(source_ip),
                                'ip2': trafcap.stringToInt(trafcap.options.ip),
                                'p2': dst_port}}
    else:
        match_doc = {'$match': {'tem': {'$gt': time_gt},
                                'ip2': trafcap.stringToInt(trafcap.options.ip),
                                'p2': dst_port}}

    return db.command({
    'aggregate': collection,
    'pipeline': [
        match_doc,
        {'$group': {
            '_id': {'ip1':'$ip1'},
            'cc1': {'$max':'$cc1'},  #cc1 sometimes null - not sure why
            'cc2': {'$max':'$cc2'},  #cc2 sometimes not null - not sure why
            'b1': {'$sum': '$b1'},
            'b2': {'$sum': '$b2'},
            'bt': {'$sum': '$bt'},
            'count': {'$sum':1}
        }},
        {'$project': {
            '_id':0, 'b1':1, 'b2':1, 'bt':1, 'count':1, 'cc1':1, 'cc2':1,
            'ip1':'$_id.ip1'
        }},
        sort_dict,
        {'$limit': trafcap.options.limit }
    ],
    'allowDiskUse': True
    })

def sendEmailNotification(item, dest_port, receivers, mail_server):
    sender = 'sentry40013@ecstuning.com'
    subject = 'Blocked web crawler ' +item['ip_str'] 
    body = '\n'+\
    'Source IP:  ' +item['ip_str']+ '\n'+\
    'Hostname:   ' +item['hostname']+ '\n'+\
    'Country:    ' +item['cc']+ '\n'+\
    'Avg bps:    ' +str(item['avg_bandwidth'])+ '\n'+\
    'Graphics%: ' +'{:>4.1f}'.format(item['graphic_pct'])+ '\n'+\
    'Dest port:  ' +str(dest_port)+ '\n'+\
    'UA count:   ' +str(item['ua_count'])+ '\n'+\
    'UA Sample:  ' +item['ua_sample']+ '\n'+\
    ''
    
    message = 'Subject: %s\n\n%s' %  (subject, body)
    
    try:
        smtpObj = smtplib.SMTP(mail_server)
        smtpObj.sendmail(sender, receivers, message)         
        #print "Successfully sent email"
    except Exception as e:
        print('Exception when sending email notification:', e)
        print(receivers, mail_server)
        print('---------------------------------------------')
    

def main():
    options = parseOptions()     # Could combine this line with next line
    trafcap.options = options
    if options.config:
        print("Creating default config docs...")
        createDefaultConfigDocs()
        sys.exit()

    if not options.ip: 
        print("Target IP address required.")
        sys.exit()

    if options.block:
        ip_s = options.ip
        ip_i = trafcap.stringToInt(ip_s)
        trafinj.blockIp(ip_i, options.timeout)
        print('Added ', ip_s, ' to block list...')
        sys.exit()

    if options.unblock:
        ip_s = options.ip
        ip_i = trafcap.stringToInt(ip_s)
        trafinj.unBlockIp(ip_i)
        print('Removed ', ip_s, ' from block list...')
        sys.exit()

    if options.days and options.minutes:
        print("Specify only minutes or only days, not both.")
        sys.exit()

    # ensure minutes is always set 
    if not options.days and not options.minutes:
        options.days = 1
        options.minutes = 60*24
    elif options.days:
        options.minutes = options.days * 24*60

    db = trafcap.mongoSetup()

    sti = trafinj.getSti()
    nti = trafinj.getNti()

    result = []  

    if options.source:
        if options.verbose: print("Checking sessionInfo.....\r", end=' ')
        # Set total_bytes search threshold low to get all documents 
        total_bytes = 1
        cursor = getInfoResult(db, 'tcp_sessionInfo', {'$sort': { 'bt':-1}}, 
                               options.source, options.port, getQuerySeconds())
        result = [ cursor['result'], total_bytes, 'info' ]

    elif options.groups == 2:
        if options.verbose: print("Checking groups2.....\r", end=' ')
        # Specify '# of items' in bytes array for a document to be counted
        # Specify threshold '# of docs' with selected '# of items' for blocking to occur
        #                                                                           # of items     # of docs
        cursor = getGroupsResult(db, 'tcp_sessionGroups2', {'$sort': { 'count':-1}}, options.array) 
        result = [ cursor['result'], 1, 'grps2'] 

    elif options.groups == 1:
        if options.verbose: print("Checking groups1.....\r", end=' ')
        cursor = getGroupsResult(db, 'tcp_sessionGroups', {'$sort': { 'count':-1}}, options.array) 
        result = [ cursor['result'], 4, 'grps1' ] 

    elif options.groups == 0:
        if options.verbose: print("Checking sessionInfo.....\r", end=' ')
        # 1048576 = 1Mb, calculate 1Mb/minute
        #total_bytes = int(1048576 * options.minutes )
        #total_bytes = int(1048576 * 50 )
        total_bytes = int(1048576 * 30 )
        cursor = getInfoResult(db, 'tcp_sessionInfo', {'$sort': { 'bt':-1}}, 
                               None, options.port, getQuerySeconds())
        result = [ cursor['result'], total_bytes, 'info' ]

    else:
        print('Must specify either -s source_ip or a valid groups option of 0, 1, or 2')
        sys.exit()

    suspect_list = []      # documents with all info about an IP, used for reporting
    suspect_set = Set()    # just integer IP addresses, checked with each packet 

    num_g0_slots = (trafcap.options.minutes * 60 * 1.5 )   # 1 sec per slot in sessionBytes 
    num_g1_slots = (trafcap.options.minutes * 60 ) / 10.0  # 10 sec per slot in groups1
    num_g2_slots = (trafcap.options.minutes ) / 2.0        # 2 minutes per slot in groups2

    # result list had two dicts - one from groups and one from groups2 
    # Need to get rid of next for statement
    #if options.verbose: print 'Processing ', len(result[0]), ' items...', '\r',
    sys.stdout.flush()
    item_count = 0 
    for item in result[0]:
        item_count += 1 
        if options.verbose: print('                                                            ', '\r', end=' ')
        if options.verbose: print('Processing ', item_count, ' of ', len(result[0]), ' items...', '\r', end=' ')
        # items look like this:
        # {u'count': 1, u'cc1': None, u'cc2': u'US', u'ip1': 3475901829L, u'b1': 2783255, u'b2': 33817542}

        # Ignore if IP is on white list
        if trafinj.isIpAllowed(item['ip1'], db):
            continue

        # Ignore if IP has an 'approved' ASN 
        asn_whitelist = [
                         'AS13335',    # CloudFlare, Inc.
                         'AS394536',   # cloudflare.com
                        ]
                        #'AS14618',    # Amazon.com, Inc.
                        #'AS16509',    # Amazon.com, Inc.
                        #'AS7224',     # amazon.com 
                        #'AS62785',    # amazon.com

        # ASN will be None if the lookup failed
        asn, name = trafcap.geoIpAsnLookupInt(item['ip1']) 
        if asn and asn in asn_whitelist:
            continue

        # Ignore if port 8969 (live chat) was used in the last week
        if options.verbose: print('Checking for Live Chat traffic.....', '\r', end=' ')
        cursor = getInfoResult(db, 'tcp_sessionInfo', {'$sort': { 'bt':-1}}, 
                               trafcap.intToString(item['ip1']), 8969, getQuerySeconds()-(60*60*24*7))
        item['8969'] = cursor['result']
        #print item['8969'], trafcap.intToString(item['ip1'])
        if len(item['8969']) > 0:
            # Ignore if port 8969 / live chat is used
            #print item['8969'], trafcap.intToString(item['ip1'])
            continue

        if trafcap.options.groups == 2 or trafcap.options.groups == 1:
            # Ignore if doc count is less than threshold
            if item['count'] < result[1]: continue
        else: 
            # Ignore if bytes total are less than threshold
            if item['bt'] < result[1]: continue

        # Ignore if this IP is a duplicate
        if item['ip1'] in suspect_set: continue

        # Get hostname for source IP 
        try: ptr_rec = socket.gethostbyaddr(trafcap.intToString(item['ip1']))
        except: ptr_rec = ('Hostname unknown', [], [])
        item['hostname'] = ptr_rec[0]

        # Get user agents for this IP
        if options.verbose: print('Getting user agents................', '\r', end=' ')
        ua_list = getAllUa(db, item['ip1'])

        #item['ua_sample'] = getSampleUa(db, item['ip1'])
        try:
            item['ua_sample'] = ua_list[0]
        except IndexError:  # src_ip does not have UA
            item['ua_sample'] = 'No user agent'

        #print 'Pre-processing ', trafcap.intToString(item['ip1']), item['hostname'], item['ua_sample'], '\r', 
        sys.stdout.flush()

        # Ignore whitelisted hostname / UA pairs of known-good web crawlers.
        # Do this early to eliminate high-volume, known-good (Google, Bing, ...)
        # web crawlers as early as possibe.
        # Ignore if ip or subnet is whitelisted
        item_suspect = True

        ip1_t = trafcap.intToTuple(item['ip1'])   # tuple
        for st in sti:
            # Use IP and ua info in sti to eliminate known-good sources 
            s = st[0]
            if ( ( (ip1_t[0]==s[0] and ip1_t[1]==s[1]) or \
                   (ip1_t[0]==s[0] and ip1_t[1]==s[1] and ip1_t[2] == s[2]) or \
                   (ip1_t[0]==s[0] and ip1_t[1]==s[1] and ip1_t[2] == s[2] and ip1_t[3]==s[3]) )\
                 and st[1] in item['ua_sample']): 
                item_suspect = False
                break 

        for nt in nti:
            # Use names in nti to eliminate common web crawlers
            if re.search(nt[0], item['hostname']) and (nt[1] in item['ua_sample']):
                item_suspect = False
                break

        if item_suspect:
            #print 'Processing ', trafcap.intToString(item['ip1']), '\r', 

            #print '   CC...'
            # Select CC to display
            if item['cc1']: item['cc'] = item['cc1']
            else: item['cc'] = item['cc2']

            #print '   G1...'
            ## Get number of groups1 docs for this IP
            #try: gr1_result = getCount(db, 'tcp_sessionGroups', item['ip1'])
            #except: gr1_result = {'ok': 1.0, 'result':[{total:-1}]} 
            ## Handle case of no results
            #try: gr1_total_docs = gr1_result['result'][0]['total']
            #except: gr1_total_docs = 0     # no results found
            ## Calculate percentage
            #item['g1pct'] = 100.0*(gr1_total_docs / num_g1_slots) 
    
            #print '   G2...'
            ## Get number of groups2 docs for this IP
            #try: gr2_result = getCount(db, 'tcp_sessionGroups2', item['ip1'])
            #except: gr2_result = {'ok': 1.0, 'result':[{total:-1}]} 
            ## Handle case of no results
            #try: gr2_total_docs = gr2_result['result'][0]['total']
            #except: gr2_total_docs = 0     # no results found
            ## Calculate percentage
            #item['g2pct'] = 100.0*(gr2_total_docs / num_g2_slots) 
    
            #print '   G0...'
            # Get number of bytes (groups0) docs for this IP
            try: gr0_result = getByteArrayItemCount(db, 'tcp_sessionBytes', item['ip1'])
            except: gr0_result = {'ok': 1.0, 'result':[{'total':-1}]} 
            # Handle case of no results
            try: gr0_total_byte_items = gr0_result['result'][0]['total']
            except: gr0_total_byte_items = 0     # no results found
            # Calculate percentage
            item['g0pct'] = 100.0*(gr0_total_byte_items / float(num_g0_slots)) 

            # possible divide by 0
            #item['act_bandwidth'] = int(((item['b1'] + item['b2']) * 8) / float(gr0_total_byte_items))

            item['avg_bandwidth'] = int(((item['b1'] + item['b2']) * 8) / float(options.minutes*60))
    
            #print '   GR...'
            # See how many hits are for graphics - useful to identify image proxies
            graphic_url_count =  countPath(db, item['ip1'], '.*\.(jpg|png|gif)$')
            all_url_count =  countPath(db, item['ip1'], '.*')
            if all_url_count > 0:
                item['graphic_pct'] = 100. * (graphic_url_count / float(all_url_count))
            else:
                item['graphic_pct'] = 0. 

            item['ua_count'] = len(ua_list) 
            item['ip_str'] = trafcap.intToString(item['ip1']) 
            item['from_col'] = result[2] 
            item['ior'] = float(item['b1'])/float(item['b2']) 
            #item['live_help_count'] = countPath(db, item['ip1'], 'livehelp/live_status.js')
    
            item['block_status'] = 'Y'
            suspect_set.add(item['ip1'])
            suspect_list.append(item)

    ip_list = []
    # Select suspect IPs that should not be blocked 
    for item in suspect_list:
        # High IOR then either ignore, either:
        #   - network scanner
        #   - keep-alive traffic
        if item['ior'] > 1.0: 
            item['block_status'] = 'N'
            continue

        # Low bandwidth traffic - TCP keep-alive
        if item['ior'] > 0.4 and item['avg_bandwidth'] < 1000:
            item['block_status'] = 'N'
            continue

        # Low bandwidth traffic - TCP keep-alive
        if item['avg_bandwidth'] < 400:
            item['block_status'] = 'N'
            continue

        # Image proxies
        if options.port == 80 and item['graphic_pct'] > 98.0:
            item['block_status'] = 'N'
            continue

        # Need to understand traffic pattern ongoing live_help traffic
        # High IOR and livehelp URL ==> customer, do not block
        # http://www.ecstuning.com/livehelp/live_status.js

        # g0 bandwidth > ___ and low graphic pct ==> block

        # UA contains Wget ==> block

        # from 65.55.x.x and >95% graphics ==> some type of MS image proxy ( ignore )
        # from 157.55.x.x and >95% graphics ==> some type of MS image proxy ( ignore )
        # from 157.56.x.x and >95% graphics ==> some type of MS image proxy ( ignore )

        ip_list.append(item['ip_str'])

        if options.email:
            result = db['tcp_injIp'].find( { 'ip': item['ip1'] } )
            if result.count() == 0:
                sendEmailNotification(item, options.port, ['alerts@protectus.com'], 
                                                           'mail2.protectus.com:587')
                sendEmailNotification(item, options.port, ['blockedip@ecstuning.com'], 
                                                           'aspmx.l.google.com')
                                                           #'mx1.emailsrvr.com')

        if options.mongo:
            trafinj.blockIp(item['ip1'], options.timeout)

    # Print results
    if options.verbose:
        print(time.asctime(time.localtime()).center(80))
        print('{:>5}'.format('Block'),',', \
              '{:>5}'.format('Count'),',', \
              '{:^5}'.format('Colln'), ',',\
              '{:>4}'.format('g0%'),',', \
              '{:>4}'.format('gr%'),',', \
              '{:>8}'.format('bps'),',', \
              '{:^15}'.format('Source_IP'), ',',\
              '{:<2}'.format('CC'), ',',\
              '{:>9}'.format('BytsTotl'), ',',\
              '{:>9}'.format('BytesIn'), ',',\
              '{:>9}'.format('BytesOut'), ',',\
              '{:^5}'.format('IOR'), ',',\
              '{:^4}'.format('#UAs'), ',',\
              '{:<40}'.format('Hostname'), ',',\
              '{:>10}'.format('UA Example'))

        for item in suspect_list: 
            if item['block_status'] == 'Y': print(start_bold)
            print('{:>5}'.format(item['block_status']),',', \
                  '{:>5}'.format(item['count']),',', \
                  '{:^5}'.format(item['from_col']), ',',\
                  '{:>4.1f}'.format(item['g0pct']),',', \
                  '{:>4.1f}'.format(item['graphic_pct']),',', \
                  '{:>8}'.format(item['avg_bandwidth']),',', \
                  '{:^15}'.format(item['ip_str']), ',',\
                  '{:^2}'.format(item['cc']), ',',\
                  '{:>9}'.format(item['b1']+item['b2']), ',',\
                  '{:>9}'.format(item['b1']), ',',\
                  '{:>9}'.format(item['b2']), ',',\
                  '{:^5.2f}'.format(item['ior']), ',',\
                  '{:^4}'.format(item['ua_count']), ',',\
                  '{:<40}'.format(item['hostname']), ',',\
                  '{:>10}'.format(item['ua_sample']))
            if item['block_status'] == 'Y': print(end_bold)

    sys.exit()

if __name__ == "__main__":
    main()

