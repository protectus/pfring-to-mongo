# trafinj.py - module for Active Defense packet injection 
#
# Copyright (c) 2013 Protectus,LLC.  All Rights Reserved.
#
from trafcap import trafcap
import sys
#from sets import Set
import time

cfg_coll_name = 'tcp_injConfig'
block_coll_name = 'tcp_injIp'
allow_coll_name = 'tcp_injAllowIp'

def createDefaultInjectConfigDocs(config_docs):
    # Will not overwrite existing config docs.
    # If a reset to default is needed, first delete existing docs 
    # and then call this method.

    db = trafcap.mongoSetup()
    
    ## These items may someday be in mongo but are currently in custom_settings.conf

    ## cc_list doc
    ##   list_type = None disables blocking by CC, block or allow otherwise
    ##   List item of None represents internal IP addrs
    #config_docs.append({
    #    'doc_type' : 'cc_list',
    #    'list_type' : None,
    #    'list' : [None, 'US']
    #})

    ## bpf_filter doc
    #config_docs.append({
    #    'doc_type' : 'inj_filter',
    #    'bpf':'and ((dst host 192.168.1.100 and dst port 80) or (src host 192.168.1.100 and src port 80))'
    #})

    ## timeout doc
    #config_docs.append({
    #    'doc_type' : 'inj_timeout',
    #    'seconds': 3600
    #})

    for a_doc in config_docs:
        result = db[cfg_coll_name].find_one({'doc_type':a_doc['doc_type']})
        if not result: 
            db[cfg_coll_name].insert(a_doc)
            print(a_doc['doc_type'], ':  created')
        else:
            print(a_doc['doc_type'], ':  already exists')


def getSti():
    a_set = set()
    db = trafcap.mongoSetup()
    sti_doc = db[cfg_coll_name].find_one({'doc_type':'suspects_to_ignore'})
    sti_tuple = (sti_doc['sti'])
    for item in sti_tuple: 
        a_set.add((tuple(item[0]),item[1]))
    return a_set

def getNti():
    a_set = set()
    db = trafcap.mongoSetup()
    nti_doc = db[cfg_coll_name].find_one({'doc_type':'names_to_ignore'})
    nti_list = nti_doc['nti']
    for item in nti_list: a_set.add(tuple(item))
    return a_set

#def getCcListType():
#    db = trafcap.mongoSetup()
#    return db[cfg_coll_name].find_one({'doc_type':'cc_list'})['list_type']

#def getCcList():
#    db = trafcap.mongoSetup()
#    return db[cfg_coll_name].find_one({'doc_type':'cc_list'})['list']

#def getInjFilter():
#    db = trafcap.mongoSetup()
#    return db[cfg_coll_name].find_one({'doc_type':'inj_filter'})['bpf']

def unBlockIp(ip_i):
    db = trafcap.mongoSetup()
    db[block_coll_name].remove({'ip':ip_i})

def blockIp(ip_i, timeout):
    db = trafcap.mongoSetup()
    time_now = time.time()
    db[block_coll_name].update(
        { 'ip': ip_i, 
          'ip_s': trafcap.intToString(ip_i) },
        { '$setOnInsert': { 'tb':time_now },
          '$set': { 'texp':time_now + timeout} },
        upsert=True)

def getBlockedIp():
    db = trafcap.mongoSetup()
    return db[block_coll_name].find()

def getBlockExpireTime(ip_i):
    db = trafcap.mongoSetup()
    doc = db[block_coll_name].find_one({"ip":ip_i})
    if doc is None:
        return 0

    return doc["texp"]


def getAllowedIp():
    db = trafcap.mongoSetup()
    return db[allow_coll_name].find()

def allowIp(ip_i):
    db = trafcap.mongoSetup()
    db[allow_coll_name].update(
        { 'ip': ip_i, 
          'ip_s': trafcap.intToString(ip_i) },
        { '$setOnInsert': { 'tb':time.time() } },
        upsert=True)

def unAllowIp(ip_i):
    db = trafcap.mongoSetup()
    db[allow_coll_name].remove({'ip': ip_i}) 

def isIpAllowed(ip_i, db=None):
    if db is None: db = trafcap.mongoSetup()
    a_cursor = db[allow_coll_name].find({'ip':ip_i})
    return False if (a_cursor.count() == 0) else True 
