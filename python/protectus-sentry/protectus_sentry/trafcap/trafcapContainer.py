# trafcapContainer.py
#
# Copyright (c) 2013 Protectus,LLC.  All Rights Reserved.
#
# Classes to help manage temporary storage of traffic in dictionaries
# and writes to mongo
import sys, time
from . import trafcap
from datetime import datetime
import traceback
import pprint
from trafcapIpPacket import * 

class TrafcapContainer(object):
    """
    Manages data dictionaries and writes accumulated data to db 
    """
    def __init__(self, packet_class, i_col_name, b_col_name):
        self.db = None
        self.db_no_wc = None
        self.pc = packet_class        # Packet class storing data in container 
        self.info_collection = i_col_name
        self.bytes_collection = b_col_name
        return

    def updateDb():   
        print('Override TrafcapContainer.updateDb() in subclass')
        return


class TrafcapGroupContainer(TrafcapContainer):
    """
    Used by Session Groups script to aggregate packet data  
    """
    def __init__(self, packet_class, b_col_name, g_col_name):
        TrafcapContainer.__init__(self, packet_class, None, b_col_name)

        self.groups_dict = {}           # Holds traffic info
        self.groups_collection = g_col_name
        
        # Even if not writing to db, need db connection to read input data
        self.db = trafcap.mongoSetup()
        self.db_no_wc = trafcap.mongoSetup(w=0)
        return

    def updateGroupsDict(self, group_key, a_bytes, chunck_size, doc_win_start):
        pc = self.pc
        # Add item to the group dictionaries if needed
        try:
            a_group = self.groups_dict[group_key]
            # Update groups end time
            a_group[pc.g_tem] = trafcap.secondsToMinute(a_bytes['se'])
            #a_group[pc.g_pkts] += a_bytes['pk']

        except KeyError:
            # No matching key, create a new session_groups entry
            a_group = pc.updateGroupsDict(a_bytes, chunck_size, doc_win_start)

            self.groups_dict[group_key] = a_group

            if trafcap.options.groups:
                print("New session_group items for: ", group_key)
        return


    def updateDb(self):
        pc = self.pc
        # Remove zero data elements from the session groups byte array
        if not trafcap.options.quiet: print("")
        if trafcap.options.groups: 
            print("Writing groups dict with ", len(self.groups_dict), " entries.")
        for k in self.groups_dict:
            a_group = self.groups_dict[k]

            # Prepare data for write to the database
            # Session Group dictionary data structure:
            if trafcap.options.mongo:
    
                #group_criteria, group_data = pc.buildGroupsDoc(a_group)
                group_data = pc.buildGroupsDoc(a_group)
                if trafcap.options.groups:
                    print("Update db with data: ", group_data)

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

                except Exception as e:
                    trafcap.logException(e, group_data=group_data)
    
                if not trafcap.options.quiet:
                    print("\033[31m", k, "\t", group_data ,"\033[0m")
        return

class TrafcapEthPktContainer(TrafcapContainer):
    """
    Used by ingest script to pull packets off the wire and store them in a db 
    """
    def __init__(self, packet_class, i_col_name, b_col_name, container_type):
        TrafcapContainer.__init__(self, packet_class, i_col_name, b_col_name)

        self.info_dict = {}           # Holds traffic info
        self.bytes_dict = {}          # Holds traffic bytes
        self.container_type = container_type   # session or capture

        # Even if not writing to db, need db connection to prebuild dictionary
        self.db = trafcap.mongoSetup()
        self.db_no_wc = trafcap.mongoSetup(w=0)

        #if container_type == "capture":
            # Initialize Capture Bytes dictionary 
            # Begin sequence is set when adding first bytes 
            #capture_bytes_list = self.pc.initializeCaptureBytes()
            #self.bytes_dict[self.pc.capture_dict_key] = capture_bytes_list

            # Initialize Capture Info dictionary 
            #capture_info_list = self.pc.initializeCaptureInfo()
            #self.info_dict[self.pc.capture_dict_key] = capture_info_list

        return


    def updateDb(self): 
        pc = self.pc                # pc = Packet Class

        # Create place to put active sessions older than timeout value
        keys_to_pop = []

        for key in self.info_dict:
            # Update mongo if needed
            a_info = self.info_dict[key]

            current_time = trafcap.current_time 

            # If doc changed since last db write and
            if ((a_info[pc.i_csldw] == True) and  
                # more than store_timeout seconds have passed since last write
                (current_time > a_info[pc.i_ldwt] + 
                 float(trafcap.store_timeout))):  

                a_bytes = self.bytes_dict[key]

                # If (seq + largest offset == time of last received packet)
                if ((a_bytes[pc.b_sb] + a_bytes[pc.b_array][-1][pc.b_offset]) \
                   == trafcap.last_seq_off_the_wire):
                    # If only one entry in the byte array
                    if (len(a_bytes[pc.b_array]) == 1):
                        # Do not write to db, go to next key
                        continue

                    # More than one entry in the byte array
                    else:
                        # Pop last byte array entry and save it for the first
                        # entry in the new session_bytes array
                        new_byte_list = [a_bytes[pc.b_array].pop()]

                        # Hack for better performance.  Poor OO design.
                        if pc == eval('RtpPacket'):
                            new_lpj_list = [a_bytes[pc.b_lpj_array].pop()]
                            new_lpj_list[0][pc.b_offset] = 0
                            
                        new_seq_begin = a_bytes[pc.b_sb] + \
                                        new_byte_list[0][pc.b_offset]
                        new_seq_end = new_seq_begin
                        new_byte_list[0][pc.b_offset] = 0

                        # Modify sequence_end value to refer to the last 
                        # remaining entry in the byte array
                        a_bytes[pc.b_se] = a_bytes[pc.b_sb] + \
                                           a_bytes[pc.b_array][-1][pc.b_offset]

                else:
                    # seq + largest offset < time of last received packet.
                    # Write to db
                    new_byte_list = [[0,0,0]]
                    new_lpj_list = [[0,0.,0.,0.]]
                    new_seq_begin = 0
                    new_seq_end = 0

                if not trafcap.options.quiet:
                    print("\rUi:", a_info)
                    print("\rUb:", a_bytes)

                # Prepare for write to the database if user specified option
                if trafcap.options.mongo:

                    # Client_index (1 or 0) is used to write client info 
                    # into the ip1 position in the database.
                    # Set server_index to the opposite of the client_index
                    ci = a_info[pc.i_ci]
                    si = abs(ci - 1)

                    # Build the query document
                    #session_criteria = pc.buildCriteriaDoc(ci, si, a_info)
                    #session_criteria = {"_id":a_info[pc.i_id]}

                    session_info_doc = pc.buildInfoDoc(ci, si, a_info)

                    # If ip1 & ip2 are swapped for a_info then corresponding
                    # byte values in a_bytes also need to be swapped
                    if ci == 1:
                        for an_array in a_bytes[pc.b_array]:
                            an_array[1], an_array[2] = an_array[2], an_array[1]

                    session_bytes_doc = pc.buildBytesDoc(ci, si, a_info, 
                                                         a_bytes)

                    try:
                        # session_info & session_bytes

                        # If _id field exists in dictionary, upsert is done
                        if a_info[pc.i_id] != None:
                            session_info_doc['_id'] = a_info[pc.i_id]

                        _id=self.db[self.info_collection].save(session_info_doc)

                        # If new doc, insert was done. Put _id in dictionary
                        if a_info[pc.i_id] == None:
                            a_info[pc.i_id] = _id

                        self.db_no_wc[self.bytes_collection].insert(session_bytes_doc,
                                                          manipulate=False)

                    except Exception as e:
                        trafcap.logException(e, a_info=a_info, a_bytes=a_bytes,
                                            session_info_doc=session_info_doc,
                                            session_bytes_doc=session_bytes_doc)

                # Reset the change flags
                a_info[pc.i_csldw] = False
                a_bytes[pc.b_csldw] = False

                # Update time of last db write
                a_info[pc.i_ldwt] = current_time
                a_bytes[pc.b_ldwt] = current_time

                # Reset the sequnce number
                a_bytes[pc.b_sb] = new_seq_begin
                a_bytes[pc.b_se] = new_seq_end

                # Clear-out the now-stored byte info
                a_bytes[pc.b_array] = new_byte_list
                # Hack for better performance. Poor OO design.
                if pc == eval('RtpPacket'):
                    a_bytes[pc.b_lpj_array] = new_lpj_list

            # Expire session if older than timeout.  Do not expire the single
            # entry in Capture Info or Capture Bytes dictionaries
            if (current_time - a_info[pc.i_te] > \
               float(trafcap.session_expire_timeout)):
                if key != pc.capture_dict_key:
                    keys_to_pop.append(key)

        # Remove expired sessions from the dictionaries
        for key in keys_to_pop:
            expired_session = self.info_dict.pop(key)
            try:
                expired_bytes = self.bytes_dict.pop(key)
            # Sometimes there are no bytes for an info doc 
            except KeyError:
                continue
            if not trafcap.options.quiet:
                print("\rEi:", expired_session)
                print("\rEb", expired_bytes)
 
        return


    def updateInfoDict(self, key, data, inbound_bytes, outbound_bytes):
        pc = self.pc
        try:
            # Find dictionary entry with matching key if it exists
            a_info = self.info_dict[key]

            a_info[pc.i_te] =  float(data[pc.p_etime])
            a_info[pc.i_pkts] += 1
            a_info[pc.i_csldw] = True

            if self.container_type == "session":
                a_info[pc.i_src][pc.i_bytes] += data[pc.p_src][pc.p_bytes]
                a_info[pc.i_src][pc.i_pkt] += data[pc.p_src][pc.p_pkts]
                #a_info[pc.i_src][pc.i_pkt] += 1 

                # Following line noticed as duplicate of line above and 
                # commented out - PFG - Jan2017.  The line was doubling 
                # byte counts for 'other' traffic. 
                #a_info[pc.i_src][pc.i_bytes] += data[pc.p_src][pc.p_bytes]

                # updateInfoDict not needed for Ethernet packets
                #pc.updateInfoDict(data, a_info)

            elif self.container_type == "capture":
                a_info[pc.i_src][pc.i_bytes] += inbound_bytes 
                a_info[pc.i_src][pc.i_bytes] += outbound_bytes 

            else:
                print("Invalid container type....")

        except KeyError:
            new_info = pc.buildInfoDictItem(key, data)
            self.info_dict[key] = new_info
        return


    def updateBytesDict(self, key, data, curr_seq, in_bytes, out_bytes):
        pc = self.pc
        if self.container_type == "session":
            src_bytes = data[pc.p_src][pc.p_bytes]
            dst_bytes = data[pc.p_dst][pc.p_bytes]
        elif self.container_type == "capture":
            src_bytes = in_bytes
            dst_bytes = out_bytes
        else:
            print("Invalid container type...")

        try:
            # Find dictionary entry with matching key if it exists
            a_bytes = self.bytes_dict[key]

            # Update packet count and change flag
            a_bytes[pc.b_pkts] +=1
            a_bytes[pc.b_csldw] = True

            # Three cases for existing session_bytes entries:

            # Case 1:  sb=0, se=0, and one byte=[[0,0,0]] item if the
            # session was just written completely to db
            if a_bytes[pc.b_sb] == 0 and a_bytes[pc.b_se] == 0:
                if len(a_bytes[pc.b_array]) != 1:             # error checking
                    print("Error case 1 of session_bytes update")
                    print(a_bytes)
                a_bytes[pc.b_sb] = curr_seq
                a_bytes[pc.b_se] = curr_seq
                #a_bytes[pc.b_array][-1][pc.b_bytes1] += ip1_bytes
                #a_bytes[pc.b_array][-1][pc.b_bytes2] += ip2_bytes

            # Case 2:  sb=x, se=x, and one byte=[[0,#,#]] item if the
            # session was just partially written to db
            elif a_bytes[pc.b_sb] == a_bytes[pc.b_se]:
                if len(a_bytes[pc.b_array]) != 1:     # error checking
                    print("Error case 2 of session_bytes update")
                    print(a_bytes)
                if a_bytes[pc.b_se] == curr_seq:
                    #a_bytes[pc.b_array][-1][pc.b_bytes1] += ip1_bytes
                    #a_bytes[pc.b_array][-1][pc.b_bytes2] += ip2_bytes
                    pass
                else:
                    a_bytes[pc.b_se] = curr_seq
                    a_bytes[pc.b_array].append([curr_seq - a_bytes[pc.b_sb],
                                                0, 0])
                                                #ip1_bytes, ip2_bytes])

            # Case 3:  sb=x, se=y, and many byte=[[0,#,#],[...],...] items if
            #  the session was not recently written to db
            elif a_bytes[pc.b_sb] < a_bytes[pc.b_se]:
                if len(a_bytes[pc.b_array]) == 1:             # error checking
                    print("Error case 3 of session_bytes update")
                    print(a_bytes)
                if a_bytes[pc.b_se] == curr_seq:
                    #a_bytes[pc.b_array][-1][pc.b_bytes1] += ip1_bytes
                    #a_bytes[pc.b_array][-1][pc.b_bytes2] += ip2_bytes
                    pass
                else:
                    a_bytes[pc.b_se] = curr_seq
                    a_bytes[pc.b_array].append([curr_seq - a_bytes[pc.b_sb],
                                                0, 0])
                                                #ip1_bytes, ip2_bytes])
            else:
                print("Error case 4 (undefined) of session_bytes update")
                print(a_bytes)

            a_bytes[pc.b_array][-1][pc.b_bytes1] += src_bytes
            a_bytes[pc.b_array][-1][pc.b_bytes2] += dst_bytes

        except KeyError:
            # Create a new Session Bytes entry
            #new_bytes_item = [list(key), curr_seq, curr_seq,
            #                 [[0, src_bytes, dst_bytes]], 1,0,True]
            new_bytes = pc.buildBytesDictItem(key, data, curr_seq,
                                              src_bytes, dst_bytes)
            self.bytes_dict[key] = new_bytes

        return

class TrafcapIpPktContainer(TrafcapEthPktContainer):
    """
    Used by ingest script to pull packets off the wire and store them in a db 
    """
    def __init__(self, packet_class, i_col_name, b_col_name, container_type):
        TrafcapEthPktContainer.__init__(self, packet_class, i_col_name, 
                                          b_col_name, container_type)
        return

    def updateInfoDict(self, key, data, inbound_bytes, outbound_bytes):
        pc = self.pc
        try:
            # Find dictionary entry with matching key if it exists
            a_info = self.info_dict[key]

            # Update stop_time
            a_info[pc.i_te] =  float(data[pc.p_etime])
            # Increment packet count and change flag
            a_info[pc.i_pkts] += 1
            a_info[pc.i_csldw] = True

            if self.container_type == "session":
                a_info[pc.i_ip1][pc.i_bytes] += data[pc.p_ip1][pc.p_bytes]
                a_info[pc.i_ip2][pc.i_bytes] += data[pc.p_ip2][pc.p_bytes]
                
                a_info[pc.i_ip1][pc.i_pkt] += data[pc.p_ip1][pc.p_pkts]
                a_info[pc.i_ip2][pc.i_pkt] += data[pc.p_ip2][pc.p_pkts]

                # Do any protocol-specific updates
                pc.updateInfoDict(data, a_info)

            elif self.container_type == "capture":
                a_info[pc.i_ip1][pc.i_bytes] += inbound_bytes 
                a_info[pc.i_ip2][pc.i_bytes] += outbound_bytes 

            else:
                print("Invalid container type....")

        except KeyError:
            new_info = pc.buildInfoDictItem(key, data)
            self.info_dict[key] = new_info
        return


    def updateBytesDict(self, key, data, curr_seq, in_bytes, out_bytes):
        pc = self.pc
        if self.container_type == "session":
            ip1_bytes = data[pc.p_ip1][pc.p_bytes]
            ip2_bytes = data[pc.p_ip2][pc.p_bytes]
        elif self.container_type == "capture":
            ip1_bytes = in_bytes
            ip2_bytes = out_bytes
        else:
            print("Invalid container type...")

        try:
            # Find dictionary entry with matching key if it exists
            a_bytes = self.bytes_dict[key]

            # Update packet count and change flag
            a_bytes[pc.b_pkts] +=1
            a_bytes[pc.b_csldw] = True

            # Three cases for existing session_bytes entries:

            # Case 1:  sb=0, se=0, and one byte=[[0,0,0]] item if the
            # session was just written completely to db
            if a_bytes[pc.b_sb] == 0 and a_bytes[pc.b_se] == 0:
                if len(a_bytes[pc.b_array]) != 1:             # error checking
                    print("Error case 1 of session_bytes update")
                    print(a_bytes)
                a_bytes[pc.b_sb] = curr_seq
                a_bytes[pc.b_se] = curr_seq
                #a_bytes[pc.b_array][-1][pc.b_bytes1] += ip1_bytes
                #a_bytes[pc.b_array][-1][pc.b_bytes2] += ip2_bytes

            # Case 2:  sb=x, se=x, and one byte=[[0,#,#]] item if the
            # session was just partially written to db
            elif a_bytes[pc.b_sb] == a_bytes[pc.b_se]:
                if len(a_bytes[pc.b_array]) != 1:     # error checking
                    print("Error case 2 of session_bytes update")
                if a_bytes[pc.b_se] == curr_seq:
                    #a_bytes[pc.b_array][-1][pc.b_bytes1] += ip1_bytes
                    #a_bytes[pc.b_array][-1][pc.b_bytes2] += ip2_bytes
                    pass
                else:
                    a_bytes[pc.b_se] = curr_seq
                    a_bytes[pc.b_array].append([curr_seq - a_bytes[pc.b_sb],
                                                0, 0])
                                                #ip1_bytes, ip2_bytes])

            # Case 3:  sb=x, se=y, and many byte=[[0,#,#],[...],...] items if
            #  the session was not recently written to db
            elif a_bytes[pc.b_sb] < a_bytes[pc.b_se]:
                if len(a_bytes[pc.b_array]) == 1:             # error checking
                    print("Error case 3 of session_bytes update")
                    print(a_bytes)
                if a_bytes[pc.b_se] == curr_seq:
                    #a_bytes[pc.b_array][-1][pc.b_bytes1] += ip1_bytes
                    #a_bytes[pc.b_array][-1][pc.b_bytes2] += ip2_bytes
                    pass
                else:
                    a_bytes[pc.b_se] = curr_seq
                    a_bytes[pc.b_array].append([curr_seq - a_bytes[pc.b_sb],
                                                0, 0])
                                                #ip1_bytes, ip2_bytes])
            else:
                print("Error case 4 (undefined) of session_bytes update")
                print(a_bytes)

            a_bytes[pc.b_array][-1][pc.b_bytes1] += ip1_bytes
            a_bytes[pc.b_array][-1][pc.b_bytes2] += ip2_bytes

            # Hack for performance.  Poor OO design.
            # Packet loss & jitter updated here.
            if self.pc == eval('RtpPacket') and self.container_type=="session":
                pc.updateBytesDict(key, data, curr_seq, a_bytes)

        except KeyError:
            # Create a new Session Bytes entry
            new_bytes_item = pc.buildBytesDictItem(key, data, curr_seq,
                                                  ip1_bytes, ip2_bytes)
            self.bytes_dict[key] = new_bytes_item
        return
