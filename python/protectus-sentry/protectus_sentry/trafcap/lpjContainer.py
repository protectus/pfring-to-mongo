# lpjContainer.py
# Classes to help manage temporary storage of traffic in dictionaries
# and writes to mongo
import sys, time
import trafcap
from datetime import datetime
import traceback
import pprint
from lpjPacket import * 

class LpjContainer(object):
    """
    Manages data dictionaries and writes accumulated data to db 
    """
    def __init__(self, packet_class, i_col_name, d_col_name):
        self.db = None
        self.pc = packet_class        # Packet class storing data in container 
        self.info_collection = i_col_name
        self.data_collection = d_col_name
        self.requests = {}
        return

    def updateDb():   
        return


class LpjGroupContainer(LpjContainer):
    """
    Used by Session Groups script to aggregate packet data  
    """
    def __init__(self, packet_class, b_col_name, g_col_name):
        LpjContainer.__init__(self, packet_class, None, b_col_name)

        self.groups_dict = {}           # Holds traffic info
        self.groups_collection = g_col_name
        
        # Even if not writing to db, need db connection to read input data
        self.db = trafcap.mongoSetup()
        return

    def updateGroupsDict(self, group_key, a_data, chunck_size, doc_win_start):
        pc = eval(a_data['pr'].capitalize() + "LpjPacket") 

        # Add item to the group dictionaries if needed
        try:
            a_group = self.groups_dict[group_key]
            # Update groups end time
  

        except KeyError:
            # No matching key, create a new session_groups entry
            a_group = pc.updateGroupsDict(a_data, chunck_size, doc_win_start)

            self.groups_dict[group_key] = a_group

            if trafcap.options.groups:
                print "New session_group items for: ", group_key

        a_group[pc.g_tem] = trafcap.secondsToMinute(a_data['se'])
        a_group[pc.g_lmin] = min(a_data['lmin'],  a_group[pc.g_lmin])
        a_group[pc.g_lmax] = max(a_data['lmax'],  a_group[pc.g_lmax])
        a_group[pc.g_req] += a_data['req']
        a_group[pc.g_rply] += a_data['rply']

        return



    def updateDb(self):

        # Remove zero data elements from the session groups byte array
        if not trafcap.options.quiet: print ""
        if trafcap.options.groups:
            print "Writing groups dict with ", len(self.groups_dict), " entries."
        for k in self.groups_dict:
            a_group = self.groups_dict[k]
            pc = eval(a_group[0].capitalize() + "LpjPacket") 

            end_of_list = a_group[pc.g_eol]

            # remove zero entries from the list 
            #for i in range(89, -1, -1):
                #if a_group[pc.g_rtl_list][i][pc.g_rtl] == 0:
                #    a_group[pc.g_rtl_list].pop(i)
                #if a_group[pc.g_pl_list][i][pc.g_pl] == 0:
                #    a_group[pc.g_pl_list].pop(i)

            # If there are no measurements, do not write to the DB
            #if len(a_group[pc.g_rtl_list]) == 0 and \
            #   len(a_group[pc.g_pl_list]) == 0:
            #    print "Group with zero rtl and pl entries..."
            #    continue

            # Prepare data for write to the database
            # Session Group dictionary data structure:
            if trafcap.options.mongo:

                #group_criteria, group_data = pc.buildGroupsDoc(a_group,
                #                                               end_of_list)
                group_data = pc.buildGroupsDoc(a_group, end_of_list)

                if trafcap.options.groups:
                    print "Update db, crit: ", group_criteria
                    print "Update db, data: ", group_data

                try:
                    #if insert_flag:
                    #    self.db[self.groups_collection].insert(
                    #            group_data, manipulate=False )
                    #else:
                    #self.db[self.groups_collection].update(
                    #        group_criteria , group_data, upsert=True )

                    # If _id field exists in dictionary, upsert is done
                    if a_group[pc.g_id] != None:
                        group_data['_id'] = a_group[pc.g_id]

                    _id = self.db[self.groups_collection].save(group_data)

                    # If new doc, insert was done.  Put _id in the dictionary
                    if a_group[pc.g_id] == None:
                        a_group[pc.g_id] = _id

                except Exception, e:
                    # Something went wrong. Save for analysis
                    trafcap.logException(e, group_data=group_data)

            if not trafcap.options.quiet:
                pass
                #print "\033[31m", k, "\t", a_group[pc.g_b1], \
                #                     "\t", a_group[pc.g_b2], \
                #                     "\t", a_group[pc.g_ns], \
                #                     "\t", a_group[pc.g_ne], \
                #                     "\t", a_group[pc.g_b],"\033[0m"
        return


class LpjEthernetPktContainer(LpjContainer):
    """
    Used by ingest script to pull packets off the wire and store them in a db 
    """
    def __init__(self, packet_class, i_col_name, d_col_name):
        LpjContainer.__init__(self, packet_class, i_col_name, d_col_name)

        self.info_dict = {}           # Holds traffic info
        self.data_dict = {}          # Holds traffic bytes

        # If not writing to db, no need to initiate db connection
        if trafcap.options.mongo:
            self.db = trafcap.mongoSetup()

        return

    def updateDb(self): 
        pc = self.pc                # pc = Packet Class
        return

class LpjIpPktContainer(LpjEthernetPktContainer):
    """
    Holds latency and packet loss measurements
    """
    def __init__(self, packet_class, i_col_name, d_col_name):
        LpjEthernetPktContainer.__init__(self, packet_class, i_col_name, 
                                          d_col_name)
        return

    def updateInfoDict(self, req_key, sess_key, data, c_id):
        pc = self.pc

        # Request / reply are single packets with specific seq nums.
        # Sessions are  a set of related requests / replys.

        # Request - store for later match.  Overwrite duplicate requests.
        if req_key[0] == data[pc.p_ip1][pc.p_addr]:
            self.requests[req_key] = (sess_key, data)
            request = data
            reply = None

        # Reply - pop request from dict.  Ignore unmatched reply.
        elif req_key[0] == data[pc.p_ip2][pc.p_addr]:
            reply = data

            try:
                request = self.requests.pop(req_key)[1]
            except KeyError:
                # Ignore reply with no matching requests.
                request = None
        else:
            raise Exception("Invalid data or request key.")

        if request and reply:
            try:
                a_info = self.info_dict[sess_key]
            except KeyError:
                raise Exception("Valid reply with no request stored doc.")

            trip_latency = reply[pc.p_etime] - request[pc.p_etime]
            # Clock drift corrections sometimes cause negative round-trip times.
            # This problem should go away if rdate is someday replace with NTP.
            if trip_latency <= 0:
                # drop this ping 
                a_info[pc.i_req] -= 1
                return None, None

            round_trip_latency = round(trip_latency*1000, 3)

            if round_trip_latency > a_info[pc.i_lmax]:
                a_info[pc.i_lmax] = round_trip_latency 
                
            if (round_trip_latency < a_info[pc.i_lmin]) or \
               (a_info[pc.i_lmin] == 0):
                a_info[pc.i_lmin] = round_trip_latency 

            a_info[pc.i_te] =  data[pc.p_etime]
            a_info[pc.i_rply] += 1
            a_info[pc.i_csldw] = True

        elif request and not reply:
            try:
                a_info = self.info_dict[sess_key]
                a_info[pc.i_te] =  data[pc.p_etime]
                a_info[pc.i_req] += 1
                a_info[pc.i_csldw] = True

            except KeyError:
                # c_id comes with the function arguments now
                #c_id = pc.getId(data)
                # Create new dictionary entry.
                new_info = [list(data[pc.p_ip1]), list(data[pc.p_ip2]),
                            data[pc.p_etime], data[pc.p_etime],
                            0, data[pc.p_proto],0,0,1,0,0,True, c_id, None]

                self.info_dict[sess_key] = new_info

        elif not request and reply:
            # Ignore unsolicited replies
            pass
        else:
            # Should never have this case
            raise Exception("No request or reply.")

        return request, reply


    def updateDataDict(self, sess_key, req, rply):
        pc = self.pc

        try:
            seq_begin_min = trafcap.secondsToMinute(int(req[pc.p_etime]))
        except Exception, e:
            # for debug
            print e
            print "key = ", sess_key 
            print "req = ", req
            print "rply = ", rply

        sess_key_list = list(sess_key)
        sess_key_list.append(seq_begin_min)
        sess_key_sbm = tuple(sess_key_list)

        try:
            a_data = self.data_dict[sess_key_sbm]

        except KeyError:
            # Create new dictionary entry.
            # One dictionary entry for each minute.
            c_id = pc.getId(req)
            init_rtl_list = []
            init_pl_list = []
            for offset in range(0,60):
                init_rtl_list.append([offset, 0])
                init_pl_list.append([offset, 0])
            a_data = [sess_key, int(req[pc.p_etime]), int(req[pc.p_etime]),
                      init_rtl_list, init_pl_list, 0,0,0,0, 
                      # set ldwt to prevent immediate db write
                      req[pc.p_proto],req[pc.p_etime],
                      True, c_id, None, 0]
            self.data_dict[sess_key_sbm] = a_data
            if not trafcap.options.quiet:  
                print "Created new lpj data dict entry..."
                print a_data
                print ''

        if req and not rply:
            a_data[pc.d_se] =  int(req[pc.p_etime])
            a_data[pc.d_req] += 1
            a_data[pc.d_csldw] = True

            offset = int(req[pc.p_etime]) - a_data[pc.d_sb]
            a_data[pc.d_curr_ptr] = offset
            a_data[pc.d_pl_list][offset] = [offset, 1]
        
        elif req and rply:
            trip_latency = rply[pc.p_etime] - req[pc.p_etime]
            round_trip_latency = round(trip_latency*1000, 3)

            a_data[pc.d_se] =  int(req[pc.p_etime])
            a_data[pc.d_rply] += 1
            a_data[pc.d_csldw] = True

            if round_trip_latency > a_data[pc.d_lmax]:
                a_data[pc.d_lmax] = round_trip_latency 

            if (round_trip_latency < a_data[pc.d_lmin]) or \
               (a_data[pc.d_lmin] == 0):
                a_data[pc.d_lmin] = round_trip_latency 

            offset = int(req[pc.p_etime]) - a_data[pc.d_sb]
            a_data[pc.d_curr_ptr] = offset
            a_data[pc.d_rtl_list][offset] = [offset,round_trip_latency]
            a_data[pc.d_pl_list][offset] = [offset,0]

        # Clean-up unanswered requests 
        keys_to_pop = []
        for a_req_key in self.requests:
            sess_key, req_data = self.requests[a_req_key]
            if (req_data[pc.p_etime] < (float(trafcap.last_seq_off_the_wire) -\
                                     float(trafcap.latency_expire_timeout))):
                keys_to_pop.append(a_req_key)

        for a_request_key in keys_to_pop:
            self.requests.pop(a_request_key)

        return

    def updateDb(self):
        pc = self.pc
        #current_time = time.time()     # very expensive
        current_time = float(trafcap.last_seq_off_the_wire)     # float

        #if not trafcap.options.quiet: 
        #    print 'Data dict size: ', len(self.data_dict)

        # find completed data dict entries 
        data_keys_to_write = []
        data_keys_to_pop = []
        for key in self.data_dict:
            a_data = self.data_dict[key]

            #if (a_data[pc.d_sb] < (int(current_time) - 60 - \
            #                          trafcap.latency_expire_timeout)):

            # If doc changed since last db write and
            if ((a_data[pc.d_csldw] == True) and
               # more than store_timeout seconds have passed since last write
               (current_time>a_data[pc.d_ldwt]+float(trafcap.store_timeout))):
                data_keys_to_write.append(key)

            # Expire session if older than timeout
            if (current_time > a_data[pc.d_se] + \
               float(trafcap.session_expire_timeout)):
                data_keys_to_pop.append(key)

                # move pl and rtl zero removal to buildDataDoc()
                #
                # eliminate zeros from the latency list
                #for item in a_data[pc.d_rtl_list][pc.d_curr_ptr::-1]:
                #    if item[1] == 0:
                #        a_data[pc.d_rtl_list].pop(item[0])

                # eliminate zeros from the packet loss list
                #for item in a_data[pc.d_pl_list][pc.d_curr_ptr::-1]:
                #    if item[1] == 0:
                #        a_data[pc.d_pl_list].pop(item[0])
        # data_keys_to_write is ready for write to mongo    

        # find completed info dict entries
        info_keys_to_write = []
        info_keys_to_pop = []
        for key in self.info_dict:
            a_info = self.info_dict[key]

            # If doc changed since last db write and
            if ((a_info[pc.i_csldw] == True) and
               # more than store_timeout seconds have passed since last write
               (current_time>a_info[pc.i_ldwt]+float(trafcap.store_timeout))):
                info_keys_to_write.append(key)

            # Expire session if older than timeout
            if (current_time > a_info[pc.i_te] + \
               float(trafcap.session_expire_timeout)):
                info_keys_to_pop.append(key)
        # info_keys_to_write is ready for write to mongo

        # Client_index (1 or 0) is always 0 for lpj packets
        ci = 0; si = 1
        for key in info_keys_to_write: 
            a_info = self.info_dict[key]
            if not trafcap.options.quiet: print "\rU:", a_info
            # Build the query document
            #session_criteria = pc.buildCriteriaDoc(ci, si, a_info)
            session_info_doc = pc.buildInfoDoc(ci, si, a_info)

            #if not session_criteria or not session_info_doc:
            if not session_info_doc:
                print "Matching target not found..."
                return 
 
            if self.db:

                try:
                    #self.db[self.info_collection].update(session_criteria,
                    #                           session_info_doc, upsert=True)

                    # If _id field exists in dictionary, upsert is done
                    if a_info[pc.i_id] != None:
                        session_info_doc['_id'] = a_info[pc.i_id]

                    _id=self.db[self.info_collection].save(session_info_doc)

                    # If new doc, insert was done. Put _id in dictionary
                    if a_info[pc.i_id] == None:
                        a_info[pc.i_id] = _id
    
                except Exception, e:
                    # Something went wrong. Save for analysis
                    trafcap.logException(e, session_info_doc=session_info_doc,
                                            a_info=a_info)
            a_info[pc.i_csldw] = False
            a_info[pc.i_ldwt] = current_time

         
        for key in data_keys_to_write:
            a_data = self.data_dict[key]
            if not trafcap.options.quiet: print "\rUd:", a_data
            # Build the query document
            session_data_doc = pc.buildDataDoc(ci, si, a_data)

            if not session_data_doc:
                print "Matching target not found..."
                return

            if not trafcap.options.quiet:
                #print "data: ", session_data_doc
                pass
    
            if self.db:
                try:

                    # used when data was written once per minute
                    #self.db[self.data_collection].insert(session_data_doc,
                    #                                  manipulate=False)

                    # If _id field exists in dictionary, upsert is done
                    if a_data[pc.i_id] != None:
                        session_data_doc['_id'] = a_data[pc.i_id]

                    _id=self.db[self.data_collection].save(session_data_doc)

                    # If new doc, insert was done. Put _id in dictionary
                    if a_data[pc.i_id] == None:
                        a_data[pc.i_id] = _id
    
                except Exception, e:
                    # Something went wrong. Save for analysis
                    trafcap.logException(e, session_data_doc=session_data_doc,
                                            a_data=a_data)
                #print session_data_doc

            a_data[pc.d_csldw] = False
            a_data[pc.d_ldwt] = current_time

            #if not trafcap.options.quiet:
            #    print "\rEd:", a_data

        # Remove expired sessions from the dictionaries
        for key in info_keys_to_pop:
            expired_session = self.info_dict.pop(key)
            if not trafcap.options.quiet:
                print "\rEi:", expired_session

        for key in data_keys_to_pop:
            expired_session = self.data_dict.pop(key)
            if not trafcap.options.quiet:
                print "\rEd:", expired_session

        return
