#!/usr/bin/python
from argparse import ArgumentParser
from ConfigParser import SafeConfigParser
from socket import inet_ntoa, gethostname
from struct import pack
from collections import OrderedDict
import pymongo
from datetime import datetime, timedelta
import time
import sys
import fcntl
import syslog
import pickle
import smtplib
import json
import re
import glob
from email.mime.text import MIMEText

# In theory, we should have protectus-sentry installed in the current python
# set of packages.  But Trafcap hasn't been made a module yet, so the build
# system doesn't really have a way to do that yet. In practice, we know that
# there's a protectus-sentry module installed by sentry-kwebapp that we can
# use.
sys.path.extend(glob.glob("/opt/sentry/share/sentry-kwebapp/python-dist/protectus_sentry*"))
from protectus_sentry.commands.nmi import HostByIPCommand
from protectus_sentry.db_schema import IPAddress

PICKLE_PATH = '/tmp/checkAlert.pickle'


class Alert(object):
    """
    An alert object.  More a data structure than a true object.
    """
    def __init__(self, one_liner="", key_value={}):
        self.one_liner = one_liner
        self.key_value = key_value

    def messageBody(self):
        returnable = ""
        for key,item in self.key_value.iteritems():
            returnable = returnable + key + ": " + str(item) + "\n"

        # We don't need the last newline character
        return returnable[:-1]


def num_to_ip(num):
    # This may not be portable
    return inet_ntoa(pack("!I", num))


TEMPLATE_RE = re.compile("""%[0-9a-zA-Z_]*%""")
def fill_template(template, data):
    # We define a function that re.sub will use to replace %keywords%
    def replace_func(matchobj):
        # Pull out the key living between the %s
        template_key = matchobj.group(0)[1:-1]
        # If there's no text, we assume the user wanted a literal %
        if len(template_key) == 0:
            return '%'
        # Lookup and return the variable.
        return str(data[template_key])

    # Substiute each %keyword% using the replacement function above.
    return TEMPLATE_RE.sub(replace_func, template)

def ports_to_string(ports):
    if ports is None:
        return "Many"
    return ", ".join((str(p) for p in group['src_ports']))

def ip_to_hosts(ipnum):
    host = HostByIPCommand.run({"hostip":ipnum, "db":db}) # db is global
    if not host:
        host = "Hostname not recorded"
    return host

def thresholded_ids_check(state, match_doc, message, threshold, timeout, **unknown_args):
    # If match_doc is a string, load json from it
    if type(match_doc) == str:
        match_doc = json.loads(match_doc)

    timeout = timedelta(seconds=timeout)
    new_last_id = db.ids_eventInfo.find_one(fields={"_id":1}, sort=[('_id', -1)])['_id']

    if "last_id" not in state:
        # We don't know where to start.  So we set the most recent doc as a
        # starting place and return an empty list.
        state['last_id'] = new_last_id
        log(syslog.LOG_DEBUG, "No last_id found in simple_ids_check state")
        return []

    if "groups" not in state:
        state["groups"] = {}
    groups = state["groups"]

    if '$and' in match_doc:
        match_doc['$and'].append({'_id':{'$gt':state['last_id']}})  #Destructive
    else:
        match_doc['_id'] = {'$gt':state['last_id']}  #Destructive

    log(syslog.LOG_DEBUG, "simple_ids_check(): match_doc = " + str(match_doc))
    events = db.ids_eventInfo.find(match_doc, sort=[('_id',1)])

    state['last_id'] = new_last_id

    alerts = []
    for event in events:
        source = IPAddress(event["src"])
        dest = IPAddress(event["dst"])
        group_key = (source.toInt(),dest.toInt())
        if group_key not in groups:
            groups[group_key] = {
                "last_id": event['_id'],
                "count": 0,
                "triggered": False,
                "src_ports": set(),
                "dst_ports": set()
            }
        group = groups[group_key]

        if group["last_id"].generation_time + timeout < event["_id"].generation_time:
            group["count"] = 0
            group["triggered"] = False

        group["count"] += 1
        group["last_id"] = event['_id']

        # For source and dest ports, track them in a set.  If the set gets too
        # big, use the value None instead
        # XXX: Transition code: If old groups don't have ports, just overwrite
        # dumbly
        if "src_ports" not in group:
            group["src_ports"] = None
        if "dst_ports" not in group:
            group["dst_ports"] = None
            
        if group["src_ports"] is not None and 'src_port' in event:
            group["src_ports"].add(event['src_port'])
            if len(group['src_ports']) > 5:
                group["src_ports"] = None

        if group["dst_ports"] is not None and 'dst_port' in event:
            group["dst_ports"].add(event['dst_port'])
            if len(group['dst_ports']) > 5:
                group["dst_ports"] = None

        # Check threshold and triggered-state to see if we should alert
        if group["count"] >= threshold and not group["triggered"]:

            alert_properties = [ 
                ("Signature", event['msg']),
                ("Source", "%s %s" % (str(source), ip_to_hosts(source)))
            ]

            src_ports = ports_to_string(group['src_ports'])
            if src_ports:
                alert_properties.append(("Source Port(s)", src_ports))
                
            dst_host = ip_to_hosts(dest)
            alert_properties.append(("Destination", "%s (%s)" % (str(dest), dst_host))),

            dst_ports = ports_to_string(group['dst_ports'])
            if dst_ports:
                alert_properties.append(("Dest. Port(s)", dst_ports))

            alert_properties.extend([
                ("Time", datetime.fromtimestamp(event["t"]).isoformat()),
                ("Signature ID", event['sid']),
                ("Threshold Triggered", threshold)
            ])

            # Make a one-liner
            compiled_message = fill_template(message, event)
            subject = compiled_message + " [" + str(source) + " -> " + str(dest) + "]"

            alerts.append(Alert(subject, OrderedDict(alert_properties)))
            group["triggered"] = True

    return alerts


def simple_ids_check(state, match_doc, message, rate_limit=None, **unknown_args):
    # If match_doc is a string, load json from it
    if type(match_doc) != dict:
        match_doc = json.loads(match_doc)

    new_last_id = db.ids_eventInfo.find_one(fields={"_id":1}, sort=[('_id', -1)])['_id']

    if "last_id" not in state:
        # We don't know when to start looking for alerts.  So we set the most
        # recent doc as a starting place and return an empty list.  We also
        # initialize rate_info
        state['last_id'] = new_last_id
        log(syslog.LOG_DEBUG, "No last_id found in simple_ids_check state")
        return []

    if "rate_info" not in state:
        state['rate_info'] = {}

    if '$and' in match_doc:
        match_doc['$and'].append({'_id':{'$gt':state['last_id']}})  #Destructive
    else:
        match_doc['_id'] = {'$gt':state['last_id']}  #Destructive

    log(syslog.LOG_DEBUG, "simple_ids_check(): match_doc = " + str(match_doc))
    events = db.ids_eventInfo.find(match_doc, sort=[('_id',-1)])

    state['last_id'] = new_last_id

    # One alert per event
    alerts = []
    rate_info = state['rate_info']
    for event in events:
        source = IPAddress(event["src"])
        src_port = str(event['src_port'])
        dest = IPAddress(event["dst"])
        dst_port = str(event['dst_port'])
        alert_grouping = (source.toInt(),dest.toInt(),event['sid'])

        if rate_limit:
            # Find or initialize this group's rate_info
            if alert_grouping not in rate_info:
                rate_info[alert_grouping] = {'first': 0, 'count':0}

            group_rate_info = rate_info[alert_grouping]

            # Update this group's rate_info
            if group_rate_info['first'] < (time.time() - rate_limit['unit_time']):
                group_rate_info['first'] = time.time()
                group_rate_info['count'] = 1
            else:
                group_rate_info['count'] += 1

            # Ignore the alert if we're past the threshold
            if group_rate_info['count'] > rate_limit['threshold']:
                continue

        else:
            # There shouldn't be any trace of rate_info in the state, but check anyway.
            rate_info.pop(alert_grouping,None)
                

        alert_properties = OrderedDict((
            ("Signature", event['msg']),
            ("Source", "%s (%s)" % (str(source), ip_to_hosts(source))),
            ("Source Port", src_port),
            ("Destination", "%s (%s)" % (str(dest), ip_to_hosts(dest))),
            ("Dest. Port", dst_port),
            ("Time", datetime.fromtimestamp(event["t"]).isoformat()),
            ("Signature ID", event['sid'])
        ))

        # TODO: better data than just raw event.
        compiled_message = fill_template(message, event)
        subject = compiled_message + " [" + str(source) + " -> " + str(dest) + "]"

        alerts.append(Alert(subject, alert_properties))

    return alerts

def check_factory(trigger_doc):
    """
    Chooses (but does not call) the correct check to be performed based on a
    trigger document.
    """
    if trigger_doc['type'] == "ids-polling":
        if "threshold" in trigger_doc and "timeout" in trigger_doc:
            return thresholded_ids_check
        else:
            return simple_ids_check

def file_alert(alert, alert_state, **alert_doc):
    output = open('/tmp/testAlertOutput.txt', 'a')
    output.write(str(alert))
    return
 
def stdout_alert(alert, alert_state, **alert_doc):
    print str(alert)
    return

def email_alert(alert, alert_state, mailto, **alert_doc):
    msg = MIMEText(alert.messageBody())
    try:
        sentry_name = sentry_config_doc["sentryname"]
        smtp_server = sentry_config_doc["smtp_server"]
        smtp_port = int(sentry_config_doc["smtp_port"])
    except KeyError as e:
        raise LookupError("Sentry Config Document doesn't have " + str(e) + ". Aborting alert.")

    # XXX: Depends on global sentry_config_doc
    msg['subject'] = "[" + sentry_name + "] " + alert.one_liner
    msg['to'] = mailto
    msg['from'] = gethostname() + "@protectus.com"

    mailserver = smtplib.SMTP(smtp_server,smtp_port)
    mailserver.sendmail(msg['from'], [mailto], msg.as_string())
    return

def stdout_log(*arguments):
    # Intended to be a rough copy of the syslog.syslog function.
    try:
        message = arguments[-1]
    except IndexError:
        raise TypeError('stdout_log() Requires at least 1 argument')

    # XXX: Depends on options from __name__ == "__main__" below.
    if arguments[0] is syslog.LOG_DEBUG and not options.verbose:
        # Cut short if we're not suppose to be verbose.
        return

    sys.stdout.write(message)
    sys.stdout.write("\n")
    return

log = stdout_log

### Sentry Config ### XXX: Duplicated in kwebapp knightwatch __init__.py
# Get config file settings
kw_config = SafeConfigParser()
kw_config.read([
    '/opt/sentry/etc/sentry.conf',
    '/opt/sentry/etc/custom_settings.conf'
])
sections = kw_config.sections();

db_uri = kw_config.get('mongo','mongo_server')
db_port = kw_config.getint('mongo','mongo_port')
db_name = kw_config.get('mongo','traffic_db')
conn = pymongo.Connection(db_uri, db_port)
db = conn[db_name]
sentry_config_doc = db.config.find_one({"doc_type": "sentrysettings"})
### End Copied Sentry Config ### 

def parseOptions():
    """
    Simple options handling.
    """
    parser = ArgumentParser(description="Check to see if any user alerts should trigger")
    parser.add_argument("-d", "--dry-run", dest="dry",
                      action="store_true", default=False,
                      help="Dry run (Print results, but don't alert anyone)")
    parser.add_argument("-s", "--syslog", dest="syslog",
                      action="store_true", default=False,
                      help="Use syslog instead of stdout.")
    parser.add_argument("-v", "--verbose", dest="verbose",
                      action="store_true", default=False,
                      help="When not in syslog mode, be more verbose.")
    args = parser.parse_args()
    return args
 
## Program Start ##
if __name__ == "__main__":
    options = parseOptions()

    if options.syslog:
        syslog.openlog("checkAlert.py", facility=syslog.LOG_LOCAL1)
        log = syslog.syslog
    
    # Load Saved State
    stateFile = None
    state = None
    try:
        stateFile = open(PICKLE_PATH,'r+')
    except IOError as e:
        if e.errno == 2:
            log("No saved state file found, continuing..")
            stateFile = open(PICKLE_PATH,'w')
            state = {}
        else:
            log("IOError #" + str(e.errno) + " reading saved state. Abort!")
            sys.exit(1)

    try:
        # We try to gain an exclusive lock on the file, and fail quickly.
        fcntl.flock(stateFile,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except IOError as e:
        if e.errno == 11:
            log("File locked by another process, aborting!")
            sys.exit(1)
        else:
            log("IOError #" + str(e.errno) + " reading saved state. Abort!")
            sys.exit(1)

    # Load state if we haven't decided to write a new state from scratch.
    if state is None:
        try:
            state = pickle.load(stateFile)
        except EOFError:
            log(syslog.LOG_ERR, "State file appears to be corrupt/empty.")
            state = {}

    # For each alert rule in the config, process.
    rule_docs = db.config.find({"doc_type": "alert_rule"})

    any_rules = False
    rules_triggered = 0
    alerts_sent = 0

    new_state = {}
    for rule_doc in rule_docs:
        any_rules = True
        # Make sure we can get everything we need
        rule_id = rule_doc["_id"]
        try:
            trigger_doc = rule_doc["trigger"]
            alert_docs = rule_doc["alerts"]
        except KeyError as e:
            log('Rule ' + str(rule_id) + ' is missing field "' + e.message +
                '". Skipping.')
            continue

        if len(rule_doc["alerts"]) == 0:
            log('No alerting methods in rule ' + str(rule_id) + '. Skipping.')
            continue
                
        # Get the state for this specific rule
        rule_state = state.get(rule_id, {})
        
        # Create the command and execute it
        try:
            check_function = check_factory(trigger_doc)
            alerts = check_function(rule_state, **trigger_doc)
        except Exception as e:
            log("Alert check failed with " + str(e.__class__.__name__) + ": " +
                str(e.message))
            continue
        finally:
            if rule_state:
                new_state[rule_id] = rule_state

        # Start notifying
        if len(alerts) == 0:
            continue
        else:
            rules_triggered += 1

        for alert_doc in alert_docs:
            try:
                alert_id = alert_doc['uuid']
                alert_state = state.get(alert_id, {})
            except KeyError:
                log('Bad alert doc encountered -- No UUID found -- Skipping.')
                continue

            # Each alert (usually only one) needs to be sent out individually.
            for alert in alerts:

                try:
                    # alert_command = alert_factory(alert_doc)
                    alert_command = email_alert
                    if options.dry:
                        alert_command = stdout_alert

                    alert_command(alert, alert_state, **alert_doc)
                    alerts_sent += 1
                except Exception as e:
                    log("Alert action failed with " + str(e.__class__.__name__) +
                        ": " + str(e))
                    continue

            new_state[alert_id] = alert_state

    ### End Rule Loop ###

    if not any_rules:
        log("No rule documents found in DB.  Exiting.")
        sys.exit(0)

    # Save state for next time.
    stateFile.seek(0)
    pickle.dump(new_state, stateFile)
    stateFile.truncate()
    fcntl.flock(stateFile,fcntl.LOCK_UN) # Unlock state file
    stateFile.close()

    ### END ###
    log("Alert check completed. %d rules triggered, and %d alerts sent." %
        (rules_triggered, alerts_sent))

