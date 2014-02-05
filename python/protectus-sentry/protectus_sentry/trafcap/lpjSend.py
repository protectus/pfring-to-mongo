#!/usr/bin/python
# lpjSend.py
import sys, os, signal
import random
import threading
import datetime
import trafcap
from optparse import OptionParser
import copy
import lpj 
import time
from lpjTarget import *

trafcap.checkIfRoot()
check_db_task = None

def parseOptions():
    usage = "usage: %prog [-mq]"
    parser = OptionParser(usage)
    parser.add_option("-m", "--mongo", dest="mongo",
                      action="store_true", default=False,
                      help="write to mongo")
    parser.add_option("-q", "--quiet", dest="quiet",
                      action="store_true", default=False,
                      help="don't print status to stdout")
    (options, args) = parser.parse_args()
    return options

def main():
    trafcap.options = options = parseOptions() 

    config_collection_name = 'config'
    db = trafcap.mongoSetup()

    # get the list of targets
    targets_from_config = lpj.readConfig()

    for target in targets_from_config:
        a_target_obj = lpj.createTarget(target, True)
        a_target_obj.updateIp()
        a_target_obj.start()

    # Signal ingest to capture any/all IP changes during startup above
    LpjIpTarget.signalLpjIngest()

    def catchSignal1(signum, stack):
        #checkDb()
        pass

    def catchSignal2(signum, stack):
        print "\n Targets:"
        for target in lpj.targets:
            print "   ", target
        print ""

    def catchCntlC(signum, stack):
        print "Terminating ", len(lpj.targets), " targets..."
        for target in lpj.targets:
            print "Stopping...", target.target_info
            target.stop()
        if check_db_task:
           check_db_task.shutdown()
        print "Exiting..."
        sys.exit()

    signal.signal(signal.SIGUSR1, catchSignal1)
    signal.signal(signal.SIGUSR2, catchSignal2)
    signal.signal(signal.SIGINT, catchCntlC)
    signal.signal(signal.SIGTERM, catchCntlC)


    check_db_task = CheckDbThread(15, True)
    check_db_task.start()

    if not trafcap.options.quiet:
        # Subtract 1 for main thread and 1 for check_db thread
        print "Target count = ", threading.activeCount() - 2
        #print "Threads info = ", threading.enumerate()


    while True:
        time.sleep(60)
        try:
            for target in lpj.targets:
                if target.updateIp():
                    #if target.send_packets:
                    target.stop()
                    target.start()
                    LpjIpTarget.signalLpjIngest()

        except Exception, e:
            print e         

        #except KeyboardInterrupt:
        #    break

if __name__ == "__main__":
    main()
