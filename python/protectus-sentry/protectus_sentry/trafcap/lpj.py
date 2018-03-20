# lpj.py
#
# Copyright (c) 2013 Protectus,LLC.  All Rights Reserved.
#
from . import trafcap
import socket
import signal
import threading
from protectus_sentry.trafcap.lpjTarget import *


t_target=0        # could be hostname or ip
t_ip=1; t_prev_ip=2; t_c_id=3; t_title=4; t_interval=5; t_protocol=6
#icmp
t_type=7; t_length=8
#tcp
t_port=7

targets = []     # list of target objects

### Thread-safe deaddrop ###
target_cids_changed = threading.Event()
target_cids_lock = threading.Lock()
target_cids = {}

def updateLpj2MongoData():
    with target_cids_lock:
        target_cids.clear()
        for target in targets:
            c_id = target.target_info[t_c_id]
            target_cids[target.getTargetString()] = c_id
            if target.getPrevTargetString():
                target_cids[target.getPrevTargetString()] = c_id

    target_cids_changed.set()
        
def createTarget(target, send_packets_flag):
    if target[t_protocol] == 'icmp':
        a_target_obj = LpjIcmpTarget(target, send_packets_flag)

    elif target[t_protocol] == 'tcp':
        a_target_obj = LpjTcpTarget(target, send_packets_flag)

    else:
        print("Invalid target: ", target)
        a_target_obj = None

    if a_target_obj:
        #LpjIpTarget.target_ips.append(a_target_obj.getTargetString())
        #a_target_obj.updateIp()
        targets.append(a_target_obj)

    return a_target_obj


config_collection_name = 'config'
db = trafcap.mongoSetup()

def readConfig():
    targets = []
    cursor = db[config_collection_name].find()

    for item in cursor:
        if item['doc_type'] == 'latency':
            try: 
                ip_addr = item['ip']
            except Exception as e:
                print("Target without IP: ", item['target'])
                ip_addr = '0.1.2.3'

            if item['protocol'] == 'icmp':
                target = [item['target'], 
                          ip_addr,
                          item['prev_ip'],
                          item['_id'],
                          item['title'],
                          item['interval'],
                          item['protocol'], 
                          item['protocolOptions']['type'],
                          item['protocolOptions']['length']]

            if item['protocol'] == 'tcp':
                target = [item['target'], 
                          ip_addr,
                          item['prev_ip'],
                          item['_id'],
                          item['title'],
                          item['interval'],
                          item['protocol'], 
                          item['protocolOptions']['port']]
            #print target
            targets.append(target)

    return targets

collection_info = (
('lpj_data',    [[[('c_id',1),('sem',1),('sbm',1)]]]),
('lpj_info',    [[[('c_id',1)]]]),
('lpj_groups',  [[[('c_id',1),('tem',1)]]]),
('lpj_groups2', [[[('c_id',1),('tem',1)]]])
)
