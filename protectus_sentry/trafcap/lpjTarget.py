# Cilasses used by lpjSend
#
# Copyright (c) 2013 Protectus,LLC.  All Rights Reserved.
#
import threading
from subprocess import Popen, PIPE
import time
import socket
from protectus_sentry.trafcap import trafcap
import signal
#import urllib2
from urllib.request import urlopen
import pymssql

# Target class is created when user enteres new target in UI and
# exists until user removes target from UI.  Target might have an
# IP address that changes.
class LpjIpTarget(object):

    @classmethod
    def checkDbForUpdates(cls, send_packet_flag):
        something_changed = False
        try:
            if not trafcap.options.quiet: print('')
            
            # Temporary list of targets from config file.  This list will
            # be edited as active targets are found.
            targets_from_config = readConfig()

            targets_to_pop = []
            for target_obj in targets:
                target_in_config = target_obj.inConfig(targets_from_config)

                # Not in list anymore. If target has task, kill it.
                if not target_in_config:  
                    targets_to_pop.append(target_obj)

                else:
                    targets_from_config.remove(target_obj.target_info)

            for target_obj in targets_to_pop:
                # Otherwise, target is in config, remove target from list
                if target_obj.task_thread: 
                    target_obj.stop()

                if not trafcap.options.quiet: 
                    print('Removing: ', target_obj.target_info)
                targets.remove(target_obj)
                something_changed = True

            # If anything is left in the list, it is a new target 
            for target in targets_from_config:
                if not trafcap.options.quiet: 
                    print('Adding: ', target)
                a_target_obj = createTarget(target, send_packet_flag) 
                something_changed = True
                if send_packet_flag:
                    a_target_obj.start()

            if not trafcap.options.quiet:
                print('')

        except Exception as e:
            print(e)

        return something_changed


    def __init__(self, target, send_packets_flag):
        self.task_thread = None
        self.target_info = target
        self.send_packets = send_packets_flag

    # This method only called by lpjSend.  lpj2mongo reads config collection
    # from mongo to know if IP addresses have changed
    def updateIp(self):
        c_id = self.target_info[t_c_id]
        cursor = db[config_collection_name].find({"_id":c_id})
        item = cursor[0]

        try:
            ip_addr = socket.gethostbyname(item['target']),
        except Exception as e:
            # This excpetion occurs if hostname cannot be resolved to IP
            print(e, ": ", item['target'])
            return False

        if ip_addr[0] != self.target_info[t_ip]:
            if not trafcap.options.quiet:
                print("Updating  ", self.target_info[t_target], \
                                    "  from  ", \
                                    self.target_info[t_ip], \
                                    "  to  ", ip_addr[0])

            # update mongo with IP
            criteria = {"_id":c_id}
            new_ip = ip_addr[0]
            old_ip = self.target_info[t_ip]
            new_cr = {'ip':new_ip}
            old_cr = {'prev_ip':old_ip}
            db[config_collection_name].update(criteria, {"$set":old_cr})
            db[config_collection_name].update(criteria, {"$set":new_cr})
            self.target_info[t_prev_ip] = old_ip 
            self.target_info[t_ip] = new_ip 

            return True

        # Otherwise, If not a new IP, return false
        return False


    def stop(self):
        if self.task_thread:
            #print 'Stopping: ', self.target_info
            self.task_thread.shutdown()
            self.task_thread = None

    def inConfig(self, targets_from_config):
        if self.target_info in targets_from_config:
           if not trafcap.options.quiet: 
               print('Found: ', self.target_info)
           return True
        else:
           if not trafcap.options.quiet: 
               print('Did not find: ', self.target_info)
           return False 


class LpjIcmpTarget(LpjIpTarget):
    def start(self):
        print('Starting: ', self.target_info)
        ping_task = IcmpTaskThread(self.target_info)
        ping_task.start()
        self.task_thread = ping_task

    def getTargetString(self):
        return self.target_info[t_ip]

    def getPrevTargetString(self):
        return self.target_info[t_prev_ip]


class LpjTcpTarget(LpjIpTarget):
    def start(self):
        print('Starting: ', self.target_info)
        syn_task = TcpTaskThread(self.target_info)
        syn_task.start()
        self.task_thread = syn_task

    def getTargetString(self):
        return self.target_info[t_ip] + "." + \
               str(self.target_info[t_port]) 

    def getPrevTargetString(self):
        return self.target_info[t_prev_ip] + "." + \
               str(self.target_info[t_port]) 

class LpjHttpTarget(LpjIpTarget):
    def start(self):
        print('Starting: ', self.target_info)
        http_task = HttpTaskThread(self.target_info)
        http_task.start()
        self.task_thread = http_task

    def getTargetString(self):
        return self.target_info[t_ip] + "." + \
               str(self.target_info[t_port])

    def getPrevTargetString(self):
        ret = self.target_info[t_prev_ip]
        if ret:
            ret = ret + "." + str(self.target_info[t_port])
        return ret

class LpjHttpsTarget(LpjIpTarget):
    def start(self):
        print('Starting: ', self.target_info)
        https_task = HttpsTaskThread(self.target_info)
        https_task.start()
        self.task_thread = https_task

    def getTargetString(self):
        return self.target_info[t_ip] + "." + \
               str(self.target_info[t_port])

    def getPrevTargetString(self):
        ret = self.target_info[t_prev_ip]
        if ret:
            ret = ret + "." + str(self.target_info[t_port])
        return ret

class LpjMsSqlTarget(LpjIpTarget):
    def start(self):
        print('Starting: ', self.target_info)
        mssql_task = MsSqlTaskThread(self.target_info)
        mssql_task.start()
        self.task_thread = mssql_task

    def getTargetString(self):
        return self.target_info[t_ip] + "." + \
               str(self.target_info[t_port])

    def getPrevTargetString(self):
        ret = self.target_info[t_prev_ip]
        if ret:
            ret = ret + "." + str(self.target_info[t_port])
        return ret

class TaskThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self._finished = threading.Event()
        self.interval = None

    def shutdown(self):
        self._finished.set()

    def run(self):
        while True:
            if self._finished.isSet(): return
            self.task()
            # sleep for interval or until shutdown
            self._finished.wait(self.interval)

    def task(self):
        pass

#  Tasks start / stop pings.  If target IP changes, old task is stopped
#  and new task is started.
class LpjTaskThread(TaskThread):
    def __init__(self, target):
        TaskThread.__init__(self)
        self.target = target
        self.dest = target[t_ip]
        self.interval = target[t_interval]

class IcmpTaskThread(LpjTaskThread):
    def __init__(self, target):
        LpjTaskThread.__init__(self, target)
        self._type = target[t_type]
        self.length = target[t_length] + 8
        self.code = 0
        self.out = ''
        self.err = ''
        self.proc = None

    def shutdown(self):
        self._finished.set()

    def run(self):
        self.task()
        while True:
            if self._finished.isSet():
                if self.proc:
                    #print "Terminating: ", self.target
                    self.proc.terminate()
                return
            # Return value of None from poll() indicates process is alive
            if self.proc.poll():
                self.task()
            # sleep for interval or until shutdown
            self._finished.wait(self.interval)

    def task(self):
        try:
            command = '/bin/ping -q -n -s ' + str(self.length) + \
                      ' -i ' + str(self.interval) + ' ' + self.dest
            # exec is needed for proc.terminate() method to kill command
            self.proc = Popen('exec '+command, shell=True, stdout=PIPE, 
                                                           stderr=PIPE)
        except Exception as e:
            print('Exception in IcmpTaskThread: ', e)
            print('       ', self.target)

class TcpTaskThread(LpjTaskThread):
    def __init__(self, target):
        LpjTaskThread.__init__(self, target)
        self.dport = target[t_port]
        socket.setdefaulttimeout(1.0)

    def task(self):
        try:
            self.socket = socket.socket()
            self.socket.connect((self.dest,self.dport))
            self.socket.close()
        except Exception as e:
            print('Exception in TcpTaskThread: ', e)
            print('       ', self.target)

class HttpTaskThread(LpjTaskThread):
    def __init__(self, target):
        LpjTaskThread.__init__(self, target)
        self.dport = target[t_port]
        #socket.setdefaulttimeout(1.0)
        self.timeout = 1
        self.url = "http://" + target[t_target]
        if target[t_path]:
            self.url += "/" + target[t_path]
        #self.req = urllib2.Request(self.url)

    def task(self):
        try:
            rsp = urlopen(self.url)
        except Exception, e:
            print('Exception in HttpTaskThread: ', e)
            print('       ', self.target)

class HttpsTaskThread(LpjTaskThread):
    def __init__(self, target):
        LpjTaskThread.__init__(self, target)
        self.dport = target[t_port]
        #socket.setdefaulttimeout(1.0)
        self.timeout = 1
        self.url = "https://" + target[t_target]
        if target[t_path]:
            self.url += "/" + target[t_path]
        #self.req = urllib2.Request(self.url)

    def task(self):
        try:
            rsp = urlopen(self.url)
        except Exception, e:
            print('Exception in HttpTaskThread: ', e)
            print('       ', self.target)

class MsSqlTaskThread(LpjTaskThread):
    def __init__(self, target):
        print( 'target:', target)
        LpjTaskThread.__init__(self, target)
        self.timeout = 1
        self.result = None

    def task(self):
        t = self.target
        try:
            server = t[t_target] + ':' + str(t[t_port])
            conn = pymssql.connect(server, t[t_user], t[t_pwrd])
            cursor = conn.cursor()
            cursor.execute(t[t_query])
            row = cursor.fetchall()
            # Print info about result; don't fill-up logs with all results
            if not self.result:
                # First result
                self.result = row
                print('Mssql result is list of: ', len(row), ' items.')
                print('First item is: ', row[0])
            cursor.close()
        except Exception, e:
            print('Exception in MsSqlTaskThread: ', e)
            print('       ', self.target)

class CheckDbThread(TaskThread):
    def __init__(self, interval, send_packets_flag):
        TaskThread.__init__(self)
        self.interval = interval
        self.send_packets = send_packets_flag

    def task(self):
        if LpjIpTarget.checkDbForUpdates(self.send_packets):
            updateLpj2MongoData()

#
# Code below previously contained in lpj.py and consolidated
# here to eliminate circular import.
#
# Copyright (c) 2013 Protectus,LLC.  All Rights Reserved.
#

t_target=0        # could be hostname or ip
t_ip=1; t_prev_ip=2; t_c_id=3; t_title=4; t_interval=5; t_protocol=6
#icmp
t_type=7; t_length=8
#tcp
t_port=7; t_appl=8
#http and https
t_port=7; t_appl=8; t_path=9
#mssql
t_port=7; t_appl=8; t_user=9; t_pwrd=10; t_query=11


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
            target_type = target.__class__.__name__
            target_cids[target.getTargetString()] = (c_id, target_type)
            if target.getPrevTargetString():
                target_cids[target.getPrevTargetString()] = (c_id, target_type)

    target_cids_changed.set()
        
def createTarget(target, send_packets_flag):
    if target[t_protocol] == 'icmp':
        a_target_obj = LpjIcmpTarget(target, send_packets_flag)

    elif target[t_protocol] == 'tcp':
        if target[t_appl] == 'http':
            a_target_obj = LpjHttpTarget(target, send_packets_flag)
        if target[t_appl] == 'https':
            a_target_obj = LpjHttpsTarget(target, send_packets_flag)
        if target[t_appl] == 'mssql':
            a_target_obj = LpjMsSqlTarget(target, send_packets_flag)
        else:
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

            target = [item['target'],
                      ip_addr,
                      item['prev_ip'],
                      item['_id'],
                      item['title'],
                      int(item['interval']),
                      item['protocol']]
            if item['protocol'] == 'icmp':
                target.append(item['protocolOptions']['type'])
                target.append(item['protocolOptions']['length'])

            if item['protocol'] == 'tcp':
                proto_opts = item['protocolOptions']
                target.append(int(proto_opts['port']))
                if 'appl' in proto_opts:
                    target.append(proto_opts['appl'])
                    # HTTP / HTTPS
                    if proto_opts['appl'] == 'http' or \
                       proto_opts['appl'] == 'https':
                        target.append(proto_opts['path'])
                    # MSSQL
                    elif proto_opts['appl'] == 'mssql':
                        target.append(proto_opts['user'])
                        target.append(proto_opts['pass'])
                        target.append(proto_opts['query'])
                    else:
                        print("Invalid LPJ target type.  Ignoring:", item)
                        continue
                else:
                    # For straight TCP ping, appl = None
                    target.append(None)

            #print target
            targets.append(target)

    return targets

collection_info = (
('lpj_data',    [[[('c_id',1),('sem',1),('sbm',1)]]]),
('lpj_info',    [[[('c_id',1)]]]),
('lpj_groups',  [[[('c_id',1),('tem',1)]]]),
('lpj_groups2', [[[('c_id',1),('tem',1)]]])
)
