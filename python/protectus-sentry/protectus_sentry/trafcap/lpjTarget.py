# Classes used by lpjSend
#
# Copyright (c) 2013 Protectus,LLC.  All Rights Reserved.
#
import protectus_sentry.trafcap.lpj as lpj
import threading
from subprocess import Popen, PIPE
import time
import socket
from protectus_sentry.trafcap import trafcap

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
            targets_from_config = lpj.readConfig()

            targets_to_pop = []
            for target_obj in lpj.targets:
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
                lpj.targets.remove(target_obj)
                something_changed = True

            # If anything is left in the list, it is a new target 
            for target in targets_from_config:
                if not trafcap.options.quiet: 
                    print('Adding: ', target)
                a_target_obj = lpj.createTarget(target, send_packet_flag) 
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
        c_id = self.target_info[lpj.t_c_id]
        cursor = lpj.db[lpj.config_collection_name].find({"_id":c_id})
        item = cursor[0]

        try:
            ip_addr = socket.gethostbyname(item['target']),
        except Exception as e:
            # This excpetion occurs if hostname cannot be resolved to IP
            print(e, ": ", item['target'])
            return False

        if ip_addr[0] != self.target_info[lpj.t_ip]:
            if not trafcap.options.quiet:
                print("Updating  ", self.target_info[lpj.t_target], \
                                    "  from  ", \
                                    self.target_info[lpj.t_ip], \
                                    "  to  ", ip_addr[0])

            # update mongo with IP
            criteria = {"_id":c_id}
            new_ip = ip_addr[0]
            old_ip = self.target_info[lpj.t_ip]
            new_cr = {'ip':new_ip}
            old_cr = {'prev_ip':old_ip}
            lpj.db[lpj.config_collection_name].update(criteria, {"$set":old_cr})
            lpj.db[lpj.config_collection_name].update(criteria, {"$set":new_cr})
            self.target_info[lpj.t_prev_ip] = old_ip 
            self.target_info[lpj.t_ip] = new_ip 

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
        return self.target_info[lpj.t_ip]

    def getPrevTargetString(self):
        return self.target_info[lpj.t_prev_ip]


class LpjTcpTarget(LpjIpTarget):
    def start(self):
        print('Starting: ', self.target_info)
        syn_task = TcpTaskThread(self.target_info)
        syn_task.start()
        self.task_thread = syn_task

    def getTargetString(self):
        return self.target_info[lpj.t_ip] + "." + \
               str(self.target_info[lpj.t_port]) 

    def getPrevTargetString(self):
        return self.target_info[lpj.t_prev_ip] + "." + \
               str(self.target_info[lpj.t_port]) 

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
        self.dest = target[lpj.t_ip]
        self.interval = target[lpj.t_interval]

class IcmpTaskThread(LpjTaskThread):
    def __init__(self, target):
        LpjTaskThread.__init__(self, target)
        self._type = target[lpj.t_type]
        self.length = target[lpj.t_length] + 8
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
        self.dport = target[lpj.t_port]
        socket.setdefaulttimeout(1.0)

    def task(self):
        try:
            self.socket = socket.socket()
            self.socket.connect((self.dest,self.dport))
            self.socket.close()
        except Exception as e:
            print('Exception in TcpTaskThread: ', e)
            print('       ', self.target)

class CheckDbThread(TaskThread):
    def __init__(self, interval, send_packets_flag):
        TaskThread.__init__(self)
        self.interval = interval
        self.send_packets = send_packets_flag

    def task(self):
        if LpjIpTarget.checkDbForUpdates(self.send_packets):
            lpj.updateLpj2MongoData()

