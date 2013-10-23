# kwEventContainer.py
# Classes to manage temporary storage of events in dictionaries
# and writes to mongo
import sys, time
import trafcap
from datetime import datetime
import traceback
import pprint
from trafcapIpPacket import * 

class KwEventContainer(object):
    """
    Manages data dictionaries and writes accumulated data to db 
    """
    def __init__(self, packet_class, i_col_name, c_col_name):
        self.db = None
        self.pc = packet_class        # Packet class storing data in container 
        self.info_collection = i_col_name
        self.count_collection = c_col_name
        return

    def updateDb():   
        # Override in subclass
        return


class KwEventGroupContainer(KwEventContainer):
    """
    Used by Session Groups script to aggregate packet data  
    """
    def __init__(self, packet_class, b_col_name, g_col_name):
        KwEventContainer.__init__(self, packet_class, None, b_col_name)

        self.groups_dict = {}           # Holds traffic info
        self.groups_collection = g_col_name
        
        # Even if not writing to db, need db connection to read input data
        self.db = trafcap.mongoSetup()
        return

    def updateGroupsDict(self, group_key, a_count, chunck_size, doc_win_start):
        pc = self.pc
        # Add item to the group dictionaries if needed
        try:
            a_group = self.groups_dict[group_key]
            # Update groups end time
            a_group[pc.g_tem] = trafcap.secondsToMinute(a_count['se'])
            #a_group[pc.g_e_cnt] += 1

        except KeyError:
            # No matching key, create a new session_groups entry
            a_group = pc.updateGroupsDict(a_count, chunck_size, doc_win_start)

            self.groups_dict[group_key] = a_group

            if trafcap.options.groups:
                print "New event_group items for: ", group_key
        return


    def updateDb(self):
        pc = self.pc
        # Remove zero data elements from the event groups count array
        if not trafcap.options.quiet: print ""
        if trafcap.options.groups: 
            print "Writing groups dict with ",len(self.groups_dict), " entries."
        for k in self.groups_dict:
            a_group = self.groups_dict[k]

            # Prepare data for write to the database
            if trafcap.options.mongo:
    
                group_data = pc.buildGroupsDoc(a_group)
                if trafcap.options.groups:
                    print "Update db with data: ", group_data

                try:

                    # If _id field exists in dictionary, upsert is done
                    if a_group[pc.g_id] != None:
                        group_data['_id'] = a_group[pc.g_id]

                    #self.db[self.groups_collection].update(
                    #        group_criteria , group_data, upsert=True )

                    _id = self.db[self.groups_collection].save(group_data)

                    # If new doc, insert was done.  Put _id in the dictionary
                    if a_group[pc.g_id] == None:
                        a_group[pc.g_id] = _id

                except Exception, e:
                    trafcap.logException(e, group_data=group_data)
    
                if not trafcap.options.quiet:
                    print "\033[31m", k, "\t", group_data ,"\033[0m"
        return


# Previously TrafcapEthernetPktContainer
class IdsEventContainer(KwEventContainer):
    """
    Used by ingest script to store events and write them to db 
    """
    def __init__(self, packet_class, i_col_name, c_col_name, container_type):
        KwEventContainer.__init__(self, packet_class, i_col_name, c_col_name)

        self.info_dict = {}           # Holds traffic info
        self.count_dict = {}          # Holds traffic bytes
        self.container_type = container_type   # session or capture
        
        if trafcap.options.mongo:
            self.db = trafcap.mongoSetup()

        if container_type == "capture":
            # Initialize Capture Count dictionary 
            # Begin sequence is set when adding first bytes 
            capture_count_list = self.pc.initializeCaptureCount() 
            self.count_dict[self.pc.capture_dict_key] = capture_count_list

            # Initialize Capture Info dictionary 
            capture_info_list = self.pc.initializeCaptureInfo()
            self.info_dict[self.pc.capture_dict_key] = capture_info_list

        return

    def updateDb(self): 
        pc = self.pc                # pc = Packet Class

        # Create place to put active sessions older than timeout value
        keys_to_pop = []

        for key in self.count_dict:
            # Update mongo if needed
            a_count = self.count_dict[key]

            current_time = time.time()     # float

            # If doc changed since last db write and
            if ((a_count[pc.c_csldw] == True) and  
                # more than store_timeout seconds have passed since last write
                (current_time > a_count[pc.c_ldwt] + 
                 float(trafcap.store_timeout))):  

                # If (seq + largest offset == time of last received event)
                if ((a_count[pc.c_sb] + a_count[pc.c_array][-1][pc.c_offset]) \
                   == int(current_time)):
                    # If only one entry in the count array
                    if (len(a_count[pc.c_array]) == 1):
                        # Do not write to db, go to next key
                        continue

                    # More than one entry in the count array
                    else:
                        # Pop last count array entry and save it for the first
                        # entry in the new event_count array
                        new_count_list = [a_count[pc.c_array].pop()]
                        new_seq_begin = a_count[pc.c_sb] + \
                                        new_count_list[0][pc.c_offset]
                        new_seq_end = new_seq_begin
                        new_count_list[0][pc.c_offset] = 0

                        # Modify sequence_end value to refer to the last 
                        # remaining entry in the count array
                        a_count[pc.c_se] = a_count[pc.c_sb] + \
                                           a_count[pc.c_array][-1][pc.c_offset]
                        new_event_count = new_count_list[0][1]

                else:
                    # seq + largest offset < time of last received packet.
                    # Write to db
                    new_count_list = [[0,0]]
                    new_seq_begin = 0
                    new_seq_end = 0
                    new_event_count = 0

                if not trafcap.options.quiet:
                    print "\rUc:", a_count

                # Prepare for write to the database if user specified option
                if trafcap.options.mongo:

                    event_count_doc = pc.buildCountDoc(a_count)

                    if self.container_type == 'capture':
                        a_info = self.info_dict[pc.capture_dict_key]
                        capture_info_doc = pc.buildInfoDoc(a_info)

                    try:
                        self.db[self.count_collection].insert(event_count_doc,
                                                          manipulate=False)

                        if self.container_type == 'capture':
                            # If _id field exists in dictionary, upsert is done
                            if a_info[pc.i_id] != None:
                                capture_info_doc['_id'] = a_info[pc.i_id]

                            _id = \
                            self.db[self.info_collection].save(capture_info_doc)

                            # If new doc, insert was done. Put _id in dictionary
                            if a_info[pc.i_id] == None:
                                a_info[pc.i_id] = _id

                    except Exception, e:
                        trafcap.logException(e, event_count_doc=event_count_doc,
                                                a_count=a_count)

                # Reset the change flags
                a_count[pc.c_csldw] = False

                # Update time of last db write
                a_count[pc.c_ldwt] = current_time

                # Reset the sequnce number
                a_count[pc.c_sb] = new_seq_begin
                a_count[pc.c_se] = new_seq_end

                # Clear-out the now-stored count info
                a_count[pc.c_array] = new_count_list
                a_count[pc.c_events] = new_event_count

            # Expire count entries if older than timeout.  Do not expire the 
            # single entry in Capture Info or Capture Bytes dictionaries.
            # If count was written to db, it will have se=0

            # Not sure why this line was added - prevents proper expiring?
            # Removing to allow e_cnt reset in ids_eventCount doc
            #if a_count[pc.c_se] != 0:

            if (current_time - float(a_count[pc.c_se]) > \
                              float(trafcap.session_expire_timeout)):
                if key != pc.capture_dict_key:
                    keys_to_pop.append(key)

        # Remove expired sessions from the dictionaries
        for key in keys_to_pop:
            try:
                expired_count = self.count_dict.pop(key)
            # Sometimes there are no bytes for an info doc 
            except KeyError:
                continue
            if not trafcap.options.quiet:
                print "\rEc:", expired_count
 
        return

    # Only used by captureInfo 
    def updateInfoDict(self, key, data, curr_seq):
        pc = self.pc
        try:
            # Find dictionary entry with matching key if it exists
            a_info = self.info_dict[key]

            if self.container_type == "capture":
                a_info[pc.i_te] =  float(curr_seq)
                a_info[pc.i_events] += 1
                a_info[pc.i_csldw] = True
            else:
                print "Invalid container type...."

        except KeyError:
            # For IDS, events are written directly into an eventInfo 
            # collection.  There is no eventInfo python dictionary.
            # CaptureInfo is initialized elsewhere.
            print "Capture Info dict should already have an entry..."

        return


    def updateCountDict(self, key, data, curr_seq):
        pc = self.pc

        try:
            # Find dictionary entry with matching key if it exists
            a_count = self.count_dict[key]

            # Update packet count and change flag
            a_count[pc.c_events] +=1
            a_count[pc.c_csldw] = True

            # Three cases for existing event_count entries:

            # Case 1:  sb=0, se=0, and one count=[[0,0]] item if the
            # count was just written completely to db
            if a_count[pc.c_sb] == 0 and a_count[pc.c_se] == 0:
                if len(a_count[pc.c_array]) != 1:             # error checking
                    print "Error case 1 of event_count update"
                a_count[pc.c_sb] = curr_seq
                a_count[pc.c_se] = curr_seq

            # Case 2:  sb=x, se=x, and one count=[[0,#,] item if the
            # count was just partially written to db
            elif a_count[pc.c_sb] == a_count[pc.c_se]:
                if len(a_count[pc.c_array]) != 1:     # error checking
                    print "Error case 2 of event_count update"
                if a_count[pc.c_se] == curr_seq:
                    pass
                else:
                    a_count[pc.c_se] = curr_seq
                    a_count[pc.c_array].append([curr_seq - a_count[pc.c_sb],0])

            # Case 3:  sb=x, se=y, and many count=[[0,#,#],[...],...] items if
            #  the count was not recently written to db
            elif a_count[pc.c_sb] < a_count[pc.c_se]:
                if len(a_count[pc.c_array]) == 1:             # error checking
                    print "Error case 3 of event_count update"
                if a_count[pc.c_se] == curr_seq:
                    pass
                else:
                    a_count[pc.c_se] = curr_seq
                    a_count[pc.c_array].append([curr_seq - a_count[pc.c_sb],0])
            else:
                print "Error case 4 (undefined) of event_count update"

            a_count[pc.c_array][-1][pc.c_count] += 1

        except KeyError:
            # Create a new Count entry
            new_count_item = [list(key), curr_seq, curr_seq,
                             [[0, 1]], 1, data['msg'], data['short_class'],
                             data['prio'], data['t'] ,True]
            self.count_dict[key] = new_count_item
            a_count = new_count_item

        return

# Previously TrafcapIpPacketContainer
class HttpEventContainer(KwEventContainer):
    """
    Used by ingest script to process HTTP events 
    """
    def __init__(self, packet_class, i_col_name, b_col_name, container_type):
        KwEventContainer.__init__(self, packet_class, i_col_name, b_col_name)
        return

    def updateInfoDict(self, key, data, inbound_bytes, outbound_bytes):
        pc = self.pc
        return


    def updateCountDict(self, key, data, curr_seq, in_bytes, out_bytes):
        pc = self.pc
        return
