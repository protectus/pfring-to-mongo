#!/usr/bin/python
#
# Copyright (c) 2013 Protectus,LLC.  All Rights Reserved.
#
import sys, time, os, signal
from select import select
import socket
from datetime import datetime
import subprocess
from optparse import OptionParser
import math
import traceback
import trafcap
from trafcapIpPacket import *
from trafcapIpPacket cimport * 
from trafcapEthernetPacket import *
from trafcapContainer import *
import multiprocessing
import Queue
from collections import deque
from pymongo.bulk import InvalidOperation
import random
import operator

#CYTHON
from cpython cimport array
from libc.stdint cimport uint64_t, uint32_t, uint16_t, uint8_t, int64_t
from libc.string cimport memcpy, memset
from libc.stdlib cimport malloc
import ctypes
from cpf_ring cimport * 

trafcap.checkIfRoot()

def parseOptions():
    usage = "usage: %prog -t|u|i|o [-mq]"
    parser = OptionParser(usage)
    parser.add_option("-m", "--mongo", dest="mongo",
                      action="store_true", default=False,
                      help="write to mongo")
    parser.add_option("-q", "--quiet", dest="quiet",
                      action="store_true", default=False,
                      help="don't print status to stdout")
    parser.add_option("-t", "--tcp", dest="tcp",
                      action="store_true", default=False,
                      help="process tcp traffic")
    parser.add_option("-u", "--udp", dest="udp",
                      action="store_true", default=False,
                      help="process udp traffic")
    parser.add_option("-i", "--icmp", dest="icmp",
                      action="store_true", default=False,
                      help="process icmp traffic")
    parser.add_option("-o", "--other", dest="other",
                      action="store_true", default=False,
                      help="process other traffic")
    parser.add_option("-r", "--rtp", dest="rtp",
                      action="store_true", default=False,
                      help="process rtp traffic")
    (options, args) = parser.parse_args()
    return options
 
def exitNow(message):
    # Kill the childprocess sniffing packets
    print "Exiting now...", message
    global main_running
    main_running = False
    global packetParser_running
    packetParser_running = False
    global sessionUpdater_running
    sessionUpdater_running = False
    global sessionBookkeeper_running
    sessionBookkeeper_running = False
    global groupUpdater_running
    groupUpdater_running = False
    os.kill(os.getpid(), signal.SIGTERM)

# Hack to bypass error when importing macro from pfring.h
DEF PF_RING_LONG_HEADER = 4
DEF NO_ZC_BUFFER_LEN = 256 

cdef bint packetParser_running = True 
def packetParser(packet_cursor_pipe, parsed_packet_count, packet_ring_buffer, 
              recv_stats, drop_stats, proto_opts):

    # First, setup signal handling
    def packetParserCatchCntlC(signum, stack):
        print 'Caught CntlC in packetParser...'
        global packetParser_running
        packetParser_running = False
        #pfring_breakloop(pd)

    signal.signal(signal.SIGINT, packetParserCatchCntlC)
    signal.signal(signal.SIGTERM, packetParserCatchCntlC)
    
    # Give Cython code low-level access to the shared memory array
    cdef long packet_ring_buffer_addr = ctypes.addressof(packet_ring_buffer)
    cdef int packet_struct_size = ctypes.sizeof(packet_ring_buffer) / len(packet_ring_buffer)
    #cdef GenericPacketHeaders* ppshared = <GenericPacketHeaders*>packet_ring_buffer_addr
    cdef GenericPacketHeaders* current_pkt

    # Make the pipe data a raw buffer.  Enables cython later>
    py_packet_cursor_pipeable = ctypes.c_uint32()
    cdef long packet_cursor_addr = ctypes.addressof(py_packet_cursor_pipeable)
    cdef uint32_t* packet_cursor_p = <uint32_t*>packet_cursor_addr

    cdef char a_buffer[NO_ZC_BUFFER_LEN]
    cdef char* buffer_p = a_buffer
    cdef pfring_pkthdr hdr
    cdef pfring_extended_pkthdr* eh = &hdr.extended_hdr
    cdef pkt_parsing_info* pp = &hdr.extended_hdr.parsed_pkt
    cdef pfring_stat ringstats

    cdef pfring *pd
    cdef uint32_t flags = 0
    cdef char* device = trafcap.sniff_interface 
    cdef int snaplen = 128
    flags |= PF_RING_LONG_HEADER
    cdef int wait_for_packet = 1
    pd = pfring_open(device, snaplen, flags)

    pfring_set_bpf_filter(pd, proto_opts['bpf_filter'])
    pfring_enable_ring(pd)
    #pfring_loop(pd, processPacket, "", wait_for_packet) 
    cdef int last_pkt_time_sec = 0

    cdef parse_packet* parse_packet_function
    cdef long parse_packet_function_address
    parse_packet_function_address = <long>proto_opts['parse_packet']
    parse_packet_function = <parse_packet*>parse_packet_function_address

    try:
        while packetParser_running:
            pfring_recv(pd, &buffer_p, NO_ZC_BUFFER_LEN, &hdr, wait_for_packet)
    
            #if packet_cursor_p[0] == 0:
                #print "clen:", hdr.caplen, ", ", hdr.ts.tv_sec, ".", hdr.ts.tv_usec,
                #print ",tns:", eh.timestamp_ns,
                #print ",smac:", hex(pp.smac[0])[2:], hex(pp.smac[1])[2:], hex(pp.smac[2])[2:],
                #print ",dmac:", hex(pp.dmac[0])[2:], hex(pp.dmac[1])[2:], hex(pp.dmac[2])[2:],
                #print ",et:", pp.eth_type, ",vl:", pp.vlan_id, ",ipv:", pp.ip_version
                #print "if_index:", eh.if_index
                #pass
    
            # Update dropped packet counter approx every second
            if hdr.ts.tv_sec - last_pkt_time_sec > 1:
                pfring_stats(pd, &ringstats)
                #recv_stats.value = ringstats.recv
                drop_stats.value = ringstats.drop
                last_pkt_time_sec = hdr.ts.tv_sec
        
            # Since packet_ring_buffer is now generic, we need to do memory addresses ourselves.
            current_pkt = <GenericPacketHeaders*>(packet_ring_buffer_addr + (packet_cursor_p[0] * packet_struct_size))
            (parse_packet_function[0])(current_pkt, &hdr)
    
            parsed_packet_count.value += 1
            packet_cursor_pipe.send_bytes(py_packet_cursor_pipeable)  
            packet_cursor_p[0] = (packet_cursor_p[0] + 1) % RING_BUFFER_SIZE 

    except IOError: # Handle signal during pipe access
        if not trafcap.options.quiet: print 'packetParser handled IOError....'

    time.sleep(1)   # sample code included this - not sure if necessary
    pfring_close(pd)


cdef bint sessionUpdater_running = True
def sessionUpdater(packet_cursor_pipe, session_updater_pkt_count, packet_ring_buffer, live_session_buffer, live_session_locks, session_alloc_pipe, live_session_dealloc_pipe, session_updater_live_session_alloc_count, session_updater_live_session_dealloc_count, proto_opts):

    # Signal Handling
    def sessionUpdaterCatchCntlC(signum, stack):
        print 'Caught CntlC in sessionUpdater...'
        global sessionUpdater_running
        sessionUpdater_running = False

    signal.signal(signal.SIGINT, sessionUpdaterCatchCntlC)
    signal.signal(signal.SIGTERM, sessionUpdaterCatchCntlC)

    # Cythonize access to the shared packets
    #print "Shared Packet space based at:", str(ctypes.addressof(packet_ring_buffer))
    cdef long packet_ring_buffer_addr = ctypes.addressof(packet_ring_buffer)
    #cdef GenericPacketHeaders* ppshared = <GenericPacketHeaders*>packet_ring_buffer_addr
    cdef int packet_struct_size = ctypes.sizeof(packet_ring_buffer) / len(packet_ring_buffer)
    #print "Packet struct is of size", packet_struct_size

    # Cythonize access to the shared sessions
    #print "Shared session space based at:", str(ctypes.addressof(live_session_buffer))
    cdef long live_session_buffer_addr = ctypes.addressof(live_session_buffer)
    #cdef GenericSession* sessions_buffer = <GenericSession*>live_session_buffer_addr
    cdef int session_struct_size = ctypes.sizeof(live_session_buffer) / len(live_session_buffer)
    #print "Session struct is of size", session_struct_size

    # Make the outgoing pipe data a raw buffer.  Enables cython later>
    new_slot_number_pipeable = ctypes.c_uint32()
    cdef long new_slot_number_address = ctypes.addressof(new_slot_number_pipeable)
    cdef uint32_t* new_slot_number_p = <uint32_t*>new_slot_number_address

    # Make the incoming pipe data a raw buffer.  Enables cython later>
    py_packet_cursor_pipeable = ctypes.c_uint32()
    cdef long packet_cursor_addr = ctypes.addressof(py_packet_cursor_pipeable)
    cdef uint32_t* packet_cursor_p = <uint32_t*>packet_cursor_addr

    available_slots = deque(xrange(LIVE_SESSION_BUFFER_SIZE))
    cdef dict session_slot_map = {}
    cdef int session_slot
    cdef GenericSession* live_session

    cdef generate_session_key_from_pkt* generate_session_key_from_pkt_function
    cdef long generate_session_key_from_pkt_address
    generate_session_key_from_pkt_address = <long>proto_opts['generate_session_key_from_pkt']
    generate_session_key_from_pkt_function = <generate_session_key_from_pkt*>generate_session_key_from_pkt_address

    cdef generate_session_key_from_session* generate_session_key_from_session_function
    cdef long generate_session_key_from_session_address
    generate_session_key_from_session_address = <long>proto_opts['generate_session_key_from_session']
    generate_session_key_from_session_function = <generate_session_key_from_session*>generate_session_key_from_session_address

    cdef generate_session* generate_session_function
    cdef long generate_session_address
    generate_session_address = <long>proto_opts['generate_session']
    generate_session_function = <generate_session*>generate_session_address

    cdef update_session* update_session_function
    cdef long update_session_address
    update_session_address = <long>proto_opts['update_session']
    update_session_function = <update_session*>update_session_address

    # The primary packet loop
    # General Strategy:
    #   - Since we can't get C pointers right out of a python dictionary very
    #     well, we just store a slot number, and use that to reference the
    #     right place in shared memory.
    #
    #   - If we get a slot position from the dictionary, we update the struct
    #     in memory
    #
    #   - If key isn't in the dictionary, we make a new one, and add it.
    #
    #   - We don't keep track of when connections expire.  We let the "database
    #     phase" tell us when it's done with a connection.
    try:
        while sessionUpdater_running:
            packet_cursor_pipe.recv_bytes_into(py_packet_cursor_pipeable)
            session_updater_pkt_count.value += 1
    
            # Since packet_ring_buffer is now generic, we need to do memory addresses ourselves.
            packet = <GenericPacketHeaders*>(packet_ring_buffer_addr + (packet_cursor_p[0] * packet_struct_size))
            #print "Parsing Packet at", packet_ring_buffer_addr, "+", packet_cursor_p[0], "*", packet_struct_size, "=",  str(<long>packet)
            #print_tcp_packet(packet)
    
            # Get the session's key for lookup
            session_key = (generate_session_key_from_pkt_function[0])(packet)
    
            # Let the dictionary tell us where the session lives
            session_slot = session_slot_map.get(session_key,-1)
    
            # If no session existed already, we need to make one.
            if (session_slot == -1):
                # Create new session from packet
                # This is linked to new_slot_number_pipeable!
                new_slot_number_p[0] = available_slots.popleft()
                # Since session_buffer is now generic, we need to do memory addresses ourselves.
                live_session = <GenericSession *>(live_session_buffer_addr + (new_slot_number_p[0] * session_struct_size))
                # Put pkt data into shared memory space for the new session
                (generate_session_function[0])(live_session, packet)
    
                # Map the key to the new session
                session_slot_map[session_key] = new_slot_number_p[0]
                
                # Tell next phase about the new session
                session_alloc_pipe.send_bytes(new_slot_number_pipeable)
                #print "Created new session at slot", new_slot_number_p[0]
                session_updater_live_session_alloc_count.value += 1
            else:
                # Update existing session
                # Since session_buffer is now generic, we need to do memory addresses ourselves.
                live_session = <GenericSession *>(live_session_buffer_addr + (session_slot * session_struct_size))
                lock = live_session_locks[session_slot % SESSIONS_PER_LOCK] 
                lock.acquire()
                (update_session_function[0])(live_session, packet)
                lock.release()
    
            # Get released slots from next phase
            if live_session_dealloc_pipe.poll():
                live_session_dealloc_pipe.recv_bytes_into(new_slot_number_pipeable)
                session_updater_live_session_dealloc_count.value += 1
                available_slots.append(new_slot_number_pipeable.value)
                # Generate a key so we can delete it from the dictionary
                del session_slot_map[(generate_session_key_from_session_function[0])(<GenericSession *>(live_session_buffer_addr + (new_slot_number_p[0] * session_struct_size)))]
                #print "De-dictionary-ing session at slot", new_slot_number_p[0]

    except IOError: # Handle signal during pipe access
        if not trafcap.options.quiet: print 'sessionUpdater handled IOError....'
                   

cdef bint sessionBookkeeper_running = True
def sessionBookkeeper(live_session_buffer, live_session_locks, live_session_alloc_pipe, live_session_dealloc_pipe, session_keeper_live_session_alloc_count, session_keeper_live_session_dealloc_count, saved_session_cursor_pipe, saved_session_ring_buffer, session_keeper_saved_session_count, proto_opts):

    # Signal Handling
    def sessionBookkeeperCatchCntlC(signum, stack):
        print 'Caught CntlC in sessionBookkeeper...'
        global sessionBookkeeper_running
        sessionBookkeeper_running = False

    signal.signal(signal.SIGINT, sessionBookkeeperCatchCntlC)
    signal.signal(signal.SIGTERM, sessionBookkeeperCatchCntlC)

    # Mongo Database connection
    db = trafcap.mongoSetup(w=0)

    session_info_coll = db[proto_opts['session_info_coll_name']]
    session_bytes_coll = db[proto_opts['session_bytes_coll_name']]
    capture_info_coll = db[proto_opts['capture_info_coll_name']]
    capture_bytes_coll = db[proto_opts['capture_bytes_coll_name']]

    cdef int i

    cdef alloc_capture_session* alloc_capture_session_function
    cdef long alloc_capture_session_address
    alloc_capture_session_address = <long>proto_opts['alloc_capture_session']
    alloc_capture_session_function = <alloc_capture_session*>alloc_capture_session_address

    cdef write_session* write_session_function
    cdef long write_session_address
    write_session_address = <long>proto_opts['write_session']
    write_session_function = <write_session*>write_session_address

    # Initialize a capture session.
    cdef GenericSession* capture_session = <GenericSession*>(alloc_capture_session_function[0])()

    # We also initialize a dummy session to aid code reuse below.  Everything
    # that touches this variable is wasting time, but we only have to touch it
    # once every 20 seconds or so.
    cdef GenericSession* dummy_session = <GenericSession*>(alloc_capture_session_function[0])()

    # Bookkeeping data for capture
    cdef list capture_object_ids = [None] # Capture sessions are in a category of one
    cdef uint64_t capture_scheduled_checkup_time = int(time.time())

    # Cythonize access to the shared buffers 
    cdef long live_session_buffer_addr = ctypes.addressof(live_session_buffer)
    #cdef GenericSession* sessions_buffer = <GenericSession*>live_session_buffer_addr
    cdef int session_struct_size = ctypes.sizeof(live_session_buffer) / len(live_session_buffer)

    cdef long saved_session_ring_buffer_addr = ctypes.addressof(saved_session_ring_buffer)
    #cdef GenericSession* saved_session_ring_buffer = <GenericSession*>saved_session_ring_buffer_addr
    cdef int saved_session_struct_size = ctypes.sizeof(saved_session_ring_buffer) / len(saved_session_ring_buffer)

    # Create a corresponding bunch of slots for mongoids
    cdef list object_ids = [None for x in range(LIVE_SESSION_BUFFER_SIZE)]

    # Cythonize the current slot number for live_session_buffer
    # These slots are allocated by sessionUpdater and deallocated by sessionBookkeeper
    py_current_session_slot = ctypes.c_uint32()
    cdef long session_slot_address = ctypes.addressof(py_current_session_slot)
    cdef uint32_t* session_slot_p = <uint32_t*>session_slot_address

    # Cythonize the current slot number for saved_session_ring_buffer
    # These slots are incrementing and loop around back to zero when last slot is reached 
    py_current_saved_session_cursor = ctypes.c_uint32()
    cdef long saved_session_cursor_address = ctypes.addressof(py_current_saved_session_cursor)
    cdef uint32_t* saved_session_cursor_p = <uint32_t*>saved_session_cursor_address

    cdef GenericSession* session
    cdef GenericSession* session_copy = <GenericSession*>malloc(session_struct_size)
    cdef uint64_t session_start_second

    # Setup a bunch of queues for second-by-second scheduling of writes to the database
    cdef uint32_t schedule_sizes[BYTES_RING_SIZE]
    memset(schedule_sizes, 0, sizeof(schedule_sizes))

    cdef uint32_t *schedule[BYTES_RING_SIZE]
    for i in range(BYTES_RING_SIZE):
        schedule[i] = <uint32_t*>malloc(sizeof(uint32_t) * LIVE_SESSION_BUFFER_SIZE)

    # Variables during session check-ins
    cdef int schedule_number, next_schedule_number
    cdef uint32_t* slots_to_write
    cdef uint32_t slot

    cdef int bytes_cursor
    cdef uint32_t* bytes_subarray
    cdef int64_t seconds_since_last_bytes
    cdef int offset
    cdef uint64_t next_scheduled_checkup_time

    # Current second
    cdef uint64_t current_second = 0
    cdef uint64_t last_second_written = int(time.time()) - 1
    cdef uint64_t second_to_write, second_to_write_from

    cdef int mongo_session_writes = 0
    cdef int mongo_capture_writes = 0
    #cdef int session_count = 0
    
    ## Connection-Tracking Debugging ##
    #tracked_slots = set()

    # The primary loop
    # There are several tasks to accomplish:
    #   - Process new connections.  We'll receive word of new connections as
    #     slot numbers via the pipe.  We need to add country data and schedule
    #     a time for the first bytes document to be written to the database.
    #
    #   - Once a second, revisit connections that have been sitting around for
    #     20 seconds.  These can be written to the database, and can sometimes
    #     be closed out. If they're closed out, we need to send word back to
    #     the update process, and open the slot back up.
    try:
        while sessionBookkeeper_running:
            # Always check for new data.  If there is none, check the time
            # TODO: Better time/loop management
            if not live_session_alloc_pipe.poll(0.02):
                current_second = max(current_second, int(time.time()-2))
                #print 'Updating session_keeper current_second: ', current_second
                #time.sleep(0.02)
            
            while live_session_alloc_pipe.poll():
                # Read data from the pipe into a ctype, which is pointed to by
                # cython.  No type cohersion or translation required.
                # SIDE EFFECT: population of current_session_slot
                live_session_alloc_pipe.recv_bytes_into(py_current_session_slot)
                session_keeper_live_session_alloc_count.value += 1
    
                # Since session_buffer is now generic, we need to do memory addresses ourselves.
                session = <GenericSession *>(live_session_buffer_addr + (session_slot_p[0] * session_struct_size))
    
                # This is this session's first check-in.  We need to schedule the first check-up.
    
                # The schedule structure is BYTES_RING_SIZE (30) rows; one row per second  
                # The rows are # numbered time mod 30 seconds.  Add 20 to schedule for future
                # Bytes time series doc has max BYTES_DOC_SIZE (20) data items
                session_start_second = <uint64_t>session.tb
                # Place into session slot 20 seconds in the future
                schedule_number = (session_start_second + BYTES_DOC_SIZE) % BYTES_RING_SIZE
                
                #print "Scheduling",session_slot_p[0],"in",schedule_number,",",schedule_sizes[schedule_number], "( tb is ", int(session.tb),")"
                # schedule_number = row in the schedule
                # schedule_sizes[schedule_number] = first empty slot in the row
                schedule[schedule_number][schedule_sizes[schedule_number]] = session_slot_p[0]
                schedule_sizes[schedule_number] += 1
    
                #session_count += 1
    
                # Break out if we've crossed into a new second.  Session being handled has
                # already been scheduled
                if session_start_second > current_second:
                    current_second = session_start_second
                    break
    
                ## Connection-Tracking Debug ##
                #if len(tracked_slots) < 1:
                #    print "Tracking slot", session_slot_p[0]
                #    tracked_slots.add(session_slot_p[0])
    
            # Check for data to be written to the database
            # We want to write the seconds up to but not including the current second.
            # We use if, not while, as a throttling mechanism.
            if (last_second_written + 1) < current_second:
                second_to_write = last_second_written + 1
                second_to_write_from = second_to_write - BYTES_DOC_SIZE
                # Bytes cursor is the point in the bytes array to start looking for data.
                bytes_cursor = second_to_write_from % BYTES_RING_SIZE
    
                schedule_number = second_to_write % BYTES_RING_SIZE
                slots_to_write = schedule[schedule_number]
    
                #print "Processing",second_to_write,"( schedule #", int(schedule_number), ")"
    
                # Bytes ring data already written to db is set to zero by update_session.
                # Bookkeeper maintains capture bytes so something similar must be done here.
                # Upcoming session writes will write up to but not into second_to_write, 
                # so we set to zero so bytes don't grow indefinately.  
                capture_session.traffic_bytes[(second_to_write - 1) % BYTES_RING_SIZE][0] = 0
                capture_session.traffic_bytes[(second_to_write - 1) % BYTES_RING_SIZE][1] = 0
    
                # Iterate over all the slots scheduled to be dealt with this
                # second, and deal with them.
                #print "Initializing sessionInfo_bulk_writer..."
                info_bulk_writer = session_info_coll.initialize_unordered_bulk_op()
                #print "Initializing sessionBytes_bulk_writer..."
                bytes_bulk_writer = session_bytes_coll.initialize_unordered_bulk_op()
                #print "Starting loop..."
                for i in range(schedule_sizes[schedule_number]):
                    #print "Reading",schedule_number,i,":",schedule[schedule_number][i]
                    slot = slots_to_write[i]
                    # Since session_buffer is now generic, we need to do memory addresses ourselves.
                    session = <GenericSession *>(live_session_buffer_addr + (slot * session_struct_size))
                    lock = live_session_locks[slot % SESSIONS_PER_LOCK] 
                    lock.acquire()
                    # Get the data we need as quickly as possible so we can release the lock.
                    memcpy(session_copy, session, session_struct_size)
                    #memcpy(session_copy, session, sizeof(TCPSession)
                    lock.release()
    
                    #if slot in tracked_slots:
                        #print_tcp_session(session, second_to_write_from)
                    #print second_to_write,":",i,": slot", slot, ", last data", current_second - <uint64_t>session_copy.te
    
                    seconds_since_last_bytes = <int64_t>(second_to_write - <uint64_t>session_copy.te)
    
                    # Either reschedule the session for another check-in,
                    # or de-allocate the slot.
                    next_scheduled_checkup_time = 0
                    if (seconds_since_last_bytes) > trafcap.session_expire_timeout:
                        # We don't set next_scheduled_checkup_time, and deallocate below
                        pass
    
                    elif (seconds_since_last_bytes) > BYTES_DOC_SIZE:
                        # There's nothing to read, reschedule for 20 seconds from now
                        next_scheduled_checkup_time = second_to_write + BYTES_DOC_SIZE
    
                    elif session.traffic_bytes[bytes_cursor][0] > 0 or session.traffic_bytes[bytes_cursor][1] > 0:
                        # Write to database (or at least queue)
                        (write_session_function[0])(info_bulk_writer, bytes_bulk_writer, session_info_coll, 
                                                    object_ids, session_copy, slot, second_to_write_from, 
                                                    second_to_write, capture_session)
                         
                        mongo_session_writes += 2
                        next_scheduled_checkup_time = second_to_write + BYTES_DOC_SIZE
    
                        ## Connection-Tracking Debug ##
                        #if slot in tracked_slots:
                        #    print second_to_write,": Writing slot",slot
    
                        # Put saved_session into shared memory for subsequent groups processing.
                        # First get location in shared memory
                        current_saved_session = <GenericSession*>(saved_session_ring_buffer_addr + 
                                                                 (saved_session_cursor_p[0] * saved_session_struct_size))
                        # Copy session from live_session_buffer to saved_session_ring_buffer
                        # We own the session_copy so no need to acquire a lock
                        memcpy(current_saved_session, session_copy, saved_session_struct_size)

                        # Adjust saved_session timestamps to match the actual time of traffic bytes.
                        # This makes the saved_session into something like a poor-man's bytes_doc 
                        current_saved_session.tb = second_to_write_from
                        current_saved_session.te = min(second_to_write -1 , <uint64_t>current_saved_session.te) 
    
                        # Send saved_session_cursor to groupsUpdater
                        saved_session_cursor_pipe.send_bytes(py_current_saved_session_cursor)
                        session_keeper_saved_session_count.value += 1
                        # Increment saved_session_cursor
                        saved_session_cursor_p[0] = (saved_session_cursor_p[0] + 1) % RING_BUFFER_SIZE 
    
                    else:
                        # Find out where the next available byte is, and schedule a
                        # check-up for 20 seconds after that.
                        next_scheduled_checkup_time = second_to_write + BYTES_DOC_SIZE
                        for offset in range(BYTES_DOC_SIZE):
                            bytes_subarray = session.traffic_bytes[(bytes_cursor + offset) % BYTES_RING_SIZE]
                            if bytes_subarray[0] > 0 or bytes_subarray[1] > 0:
                                next_scheduled_checkup_time = second_to_write + offset
                                break
    
                    # Reschedule if we selected a time to do so.
                    if next_scheduled_checkup_time > 0:
                        next_schedule_number = next_scheduled_checkup_time % BYTES_RING_SIZE
                
                        schedule[next_schedule_number][schedule_sizes[next_schedule_number]] = slot
                        schedule_sizes[next_schedule_number] += 1
                        ## Connection-Tracking Debug ##
                        #if slot in tracked_slots:
                        #    print second_to_write,": Rescheduling", slot, "for", next_scheduled_checkup_time, "(", (next_scheduled_checkup_time - second_to_write), "seconds)"
    
                    else:
                        #print "Deallocating", slot
                        # Write to sessionUpdater about a newly freed slot.  On this
                        # end, all we have to do is free up the objectid slot and
                        # update the capture packets counter with all the packets
                        # from this session.
                        capture_session.packets += session.packets
                        # object_ids assigned in the write_session function
                        object_ids[slot] = None
    
                        # We're still linking to a python struct to get raw bytes
                        # into a python Pipe.
                        session_slot_p[0] = slot  # Linked to py_current_session_slot!
                        live_session_dealloc_pipe.send_bytes(py_current_session_slot)
                        session_keeper_live_session_dealloc_count.value += 1
    
                        ## Connection-Tracking Debug ##
                        #if slot in tracked_slots:
                        #    print second_to_write,": Deallocating", slot
                        #    tracked_slots.remove(slot)
    
    
                # Write pending bulk operations to mongo
                try:
                    #print "Doing sessionInfo_bulk_write..."
                    info_bulk_writer.execute()
                except InvalidOperation as e:
                    if e.message != "No operations to execute":
                        raise e
    
                try:
                    #print "Doing sessionBytes_bulk_write..."
                    bytes_bulk_writer.execute()
                except InvalidOperation as e:
                    if e.message != "No operations to execute":
                        raise e
    
    
                # Check to see if capture info/bytes should be written.  This only
                # happens once a second, so we're not super concerned about
                # efficiency.
                if capture_scheduled_checkup_time <= second_to_write:
                    # Not so unlike writing a normal session, but with some
                    # shortcuts and dummy data.
                    #print "Initializing captureInfo_bulk_writer..."
                    info_bulk_writer = capture_info_coll.initialize_unordered_bulk_op()
                    #print "Initializing captureBytes_bulk_writer..."
                    bytes_bulk_writer = capture_bytes_coll.initialize_unordered_bulk_op()
    
                    (write_session_function[0])(info_bulk_writer, bytes_bulk_writer, capture_info_coll, 
                                                capture_object_ids, capture_session, 0, 
                                                capture_scheduled_checkup_time - BYTES_DOC_SIZE - (BYTES_DOC_SIZE / 2), 
                                                capture_scheduled_checkup_time - BYTES_DOC_SIZE, dummy_session)
    
                    mongo_capture_writes += 2
                    capture_scheduled_checkup_time = second_to_write + (BYTES_DOC_SIZE / 2)
    
                    # Write pending bulk operations to mongo
                    try:
                        #print "Doing captureInfo_bulk_write..."
                        info_bulk_writer.execute()
                    except InvalidOperation as e:
                        if e.message != "No operations to execute":
                            raise e
    
                    try:
                        #print "Doing captureBytes_bulk_write..."
                        bytes_bulk_writer.execute()
                    except InvalidOperation as e:
                        if e.message != "No operations to execute":
                            raise e
                    
    
                #print mongo_capture_writes, "capture, ", mongo_session_writes, "session writes covering", session_count, "sessions"
    
                # Reset the now-finished schedule slot
                schedule_sizes[schedule_number] = 0
                # Mark that we've taken care of this second.
                last_second_written += 1

    except IOError: # Handle signal during pipe access
        if not trafcap.options.quiet: print 'sessionBookkeeper handled IOError....'

cdef bint groupUpdater_running = True
def groupUpdater(saved_session_cursor_pipe, group_updater_saved_session_count, 
                 saved_session_ring_buffer, group_buffer, group_locks, 
                 group_alloc_pipe,  group_dealloc_pipe, 
                 group_updater_group_alloc_count, group_updater_group_dealloc_count, 
                 group_updater_session_history_count, proto_opts):

    # Signal Handling
    def groupUpdaterCatchCntlC(signum, stack):
        print 'Caught CntlC in groupUpdater...'
        global groupUpdater_running
        groupUpdater_running = False

    signal.signal(signal.SIGINT, groupUpdaterCatchCntlC)
    signal.signal(signal.SIGTERM, groupUpdaterCatchCntlC)

    # Cythonize access to the shared saved_session 
    cdef long saved_session_ring_buffer_addr = ctypes.addressof(saved_session_ring_buffer)
    #cdef GenericSession* saved_session_ring_buffer = <GenericSession*>saved_session_ring_buffer_addr
    cdef int saved_session_struct_size = ctypes.sizeof(saved_session_ring_buffer) / len(saved_session_ring_buffer)

    # Cythonize access to the shared saved_session 
    cdef long group_buffer_addr = ctypes.addressof(group_buffer)
    cdef int group_struct_size = ctypes.sizeof(group_buffer) / len(group_buffer)

    # Make the incoming pipe data a raw buffer.
    # These slots are incrementing and loop around back to zero when last slot is reached 
    py_current_saved_session_cursor = ctypes.c_uint32()
    cdef long saved_session_cursor_address = ctypes.addressof(py_current_saved_session_cursor)
    cdef uint32_t* saved_session_cursor_p = <uint32_t*>saved_session_cursor_address

    # Make the outgoing pipe data a raw buffer.  Enables cython later>
    new_slot_number_pipeable = ctypes.c_uint32()
    cdef long new_slot_number_address = ctypes.addressof(new_slot_number_pipeable)
    cdef uint32_t* new_slot_number_p = <uint32_t*>new_slot_number_address

    cdef generate_session_key_from_session* generate_session_key_from_session_function
    cdef long generate_session_key_from_session_address
    generate_session_key_from_session_address = <long>proto_opts['generate_session_key_from_session']
    generate_session_key_from_session_function = <generate_session_key_from_session*>generate_session_key_from_session_address

    cdef generate_group_key_from_session* generate_group_key_from_session_function
    cdef long generate_group_key_from_session_address
    generate_group_key_from_session_address = <long>proto_opts['generate_group_key_from_session']
    generate_group_key_from_session_function = <generate_group_key_from_session*>generate_group_key_from_session_address

    cdef generate_group_key_from_group* generate_group_key_from_group_function
    cdef long generate_group_key_from_group_address
    generate_group_key_from_group_address = <long>proto_opts['generate_group_key_from_group']
    generate_group_key_from_group_function = <generate_group_key_from_group*>generate_group_key_from_group_address

    cdef generate_group* generate_group_function
    cdef long generate_group_address
    generate_group_address = <long>proto_opts['generate_group']
    generate_group_function = <generate_group*>generate_group_address

    cdef update_group* update_group_function
    cdef long update_group_address
    update_group_address = <long>proto_opts['update_group']
    update_group_function = <update_group*>update_group_address

    available_slots = deque(xrange(GROUP_BUFFER_SIZE))
    cdef dict group_slot_map = {}
    cdef int group_slot
    cdef GenericSession* saved_session
    cdef GenericGroup* group 
    cdef dict session_history_dict = {}

    keys_to_pop = deque() 
    #cdef list keys_to_pop = []    # using a list instead of a dict creates cython compile error

    # session_history items are of the form:  [te, counted_g1, counted_g2]
    cdef int sh_te=0, sh_counted_g1=1, sh_counted_g2=2
    cdef int session_status = 0
    cdef uint64_t approx_current_time = 0
    cdef int i = 0

    ## Connection-Tracking Debugging ##
    tracked_slots = set()
    tracked_group_slot = -1 
    tracked_slot_display_count = 0

    # The primary packet loop
    # General Strategy:
    #   - Since we can't get C pointers right out of a python dictionary very
    #     well, we just store a slot number, and use that to reference the
    #     right place in shared memory.
    #
    #   - If we get a slot position from the dictionary, we update the struct
    #     in memory
    #
    #   - If key isn't in the dictionary, we make a new one, and add it.
    #
    #   - We don't keep track of when connections expire.  We let the "database
    #     phase" tell us when it's done with a connection.
    try:
        while groupUpdater_running:
            if session_status == 0:
                # Get and process a new saved_session.  If the previous saved_session flowed
                # over a group boundary and is stil being processed, then skip steps in this if
                # clause and jump down to get new group_key and group_slot and finish processing
                # the previous saved_session.
                saved_session_cursor_pipe.recv_bytes_into(py_current_saved_session_cursor)
                group_updater_saved_session_count.value += 1
    
                # Find memory addresses in shared space
                saved_session = <GenericSession*>(saved_session_ring_buffer_addr + 
                                                  (saved_session_cursor_p[0] * saved_session_struct_size))
                # For debug
                #if group_updater_saved_session_count.value%10000 == 0: print_tcp_session(session, 0)
        
                # One session maps to one group if session is contained within group's time window.
                # One session maps to two groups if session crosses group's time window boundary.
        
                # Determine if session is existing or just started.  Needed for proper session acctng
                session_key = generate_session_key_from_session_function[0](saved_session)
                session_history = session_history_dict.get(session_key, -1)

            # Get the group key and let the dictionary tell us which slot the group occupies.
            group_key = generate_group_key_from_session_function[0](saved_session)
            group_slot = group_slot_map.get(group_key,-1)
    
            # If no group existed already, we need to make one.
            if (group_slot == -1):
                # Create new group from session 
                # This is linked to py_current_saved_session_cursor!
                new_slot_number_p[0] = available_slots.popleft()
                group = <GenericGroup*>(group_buffer_addr + (new_slot_number_p[0] * group_struct_size))
    
                # Session may fit into one group or may flow into a second group
                session_status = generate_group_function[0](group, saved_session)
 
                # Group just created and not yet being accessed elsewhere, no need to aquire lock
                if session_history == -1:
                    # Session not in history. Count as started and add to history
                    group.ns += 1
                    session_history_dict[session_key] = [<uint64_t>saved_session.te, True, False]
                    group_updater_session_history_count.value += 1
                else:
                    # Count existing session if not yet counted in this group.
                    if not session_history[sh_counted_g1]:
                        group.ne += 1
                        session_history[sh_counted_g1] = True

                # Map the key to the new group 
                group_slot_map[group_key] = new_slot_number_p[0] 
                
                # Tell next phase about the new group 
                group_alloc_pipe.send_bytes(new_slot_number_pipeable)
                #print "Created new session at slot", new_slot_number_p[0]
                group_updater_group_alloc_count.value += 1
            else:
                # Update existing session
                # Since session_buffer is now generic, we need to do memory addresses ourselves.
                group = <GenericGroup *>(group_buffer_addr + (group_slot * group_struct_size))
                # for debug
                #if group_slot == tracked_group_slot:
                #    tcp_group = <TCPGroup *>group
                #    print 'Seeing tracked_group_slot ', tracked_group_slot, ' before lock...', tcp_group.vlan_id
                lock = group_locks[group_slot % GROUPS_PER_LOCK] 
                lock.acquire()
                # for debug
                #if group_slot == tracked_group_slot:
                #    tcp_group = <TCPGroup *>group
                #    print 'Seeing tracked_group_slot ', tracked_group_slot, ' before update...', tcp_group.vlan_id
                session_status = update_group_function[0](group, saved_session)
                if session_history == -1:
                    # Session not in history. Count as started and add to history
                    group.ns += 1
                    session_history_dict[session_key] = [<uint64_t>saved_session.te, True, False]
                    group_updater_session_history_count.value += 1
                else:
                    # Count existing session if not yet counted in this group.
                    if not session_history[sh_counted_g1]:
                        group.ne += 1
                        session_history[sh_counted_g1] = True
                # for debug
                #if group_slot == tracked_group_slot:
                #    tcp_group = <TCPGroup *>group
                #    print 'Seeing tracked_group_slot ', tracked_group_slot, ' after update...', tcp_group.vlan_id
                lock.release()

                # for debug
                #if group_updater_saved_session_count.value%1000 == 0:
                #     print_tcp_group(group,0)

            ## Connection-Tracking Debug ##
            #if len(tracked_slots) < 1:
            #    if session_status == -1:
            #        if group_slot == -1:
            #            group_slot = new_slot_number_p[0] 
            #        print "groupUpdater tracking slot", group_slot
            #        tracked_slots.add(group_slot)
            #        tracked_group_slot = group_slot

            ## Connection-Tracking Debug ##
            #if len(tracked_slots) < 1:
            #    tcp_group = <TCPGroup *>group
            #    if tcp_group.port2 == 3389:
            #        if group_slot == -1:
            #            group_slot = new_slot_number_p[0] 
            #        print "groupUpdater tracking slot", group_slot
            #        tracked_slots.add(group_slot)
            #        tracked_group_slot = group_slot

            # for debug
            #if group_slot == -1: group_slot = new_slot_number_p[0]
            #if group_slot == tracked_group_slot:
            #    print "Showing results for group slot ", group_slot, "=============="
            #    print_tcp_session(saved_session, 0)
            #    print_tcp_group(group, 0)
            #    tcp_group = <TCPGroup *>group
            #    print 'Seeing tracked_group_slot ', tracked_group_slot, ' after print...', tcp_group.vlan_id
            #    print ""
    
            # For debug
            #for slot in tracked_slots:
            #    if tracked_slot_display_count <= 10:
            #        group = <GenericGroup *>(group_buffer_addr + (<uint32_t>slot * group_struct_size))
            #        if group_slot == <uint32_t>slot:
            #            print_tcp_session(saved_session, 0)
            #            print_tcp_group(group, 0)
            #        tracked_slot_display_count += 1

            # Get released slots from next phase
            if group_dealloc_pipe.poll():
                group_dealloc_pipe.recv_bytes_into(new_slot_number_pipeable)
                group_updater_group_dealloc_count.value += 1
                available_slots.append(new_slot_number_pipeable.value)
                # Generate a key so we can delete it from the dictionary
                del group_slot_map[generate_group_key_from_group_function[0](<GenericGroup *>(group_buffer_addr + 
                                                                             (new_slot_number_p[0] * group_struct_size)))]
                #print "De-dictionary-ing session at slot", new_slot_number_p[0]

            # Clean-up the session_dictionary. 
            try:
                expire_count = len(keys_to_pop)
                # Expire only some of the sessions for better performance
                for i in range(0,max(10, expire_count/10)):
                    a_session_key = keys_to_pop.popleft()
                    session_history_dict.pop(a_session_key)
                    group_updater_session_history_count.value -= 1
            except IndexError:
                # The queue is empty
                pass

            # Check for expired sessions.  sessionUpdater expires sessions 
            # more frequently so a session will live here a little longer but that is OK since
            # saved_sessions are processed at least 20 seconds later than live sessions.
            if saved_session.tb > approx_current_time:
                approx_current_time = <uint64_t>saved_session.tb
                # Precision not required when expiring these session.  Interate through the 
                # session_history dictionary every 10 (arbitrarily picked) approx_seconds.
                if approx_current_time % 10 == 0:
                    for a_session_key in session_history_dict:
                        # Add 60 seconds to ensure sufficient time for upstream processing.
                        if session_history_dict[a_session_key][sh_te] < approx_current_time - \
                                                                        trafcap.session_expire_timeout - 60:
                            #keys_to_pop.append[a_session_key]    # Cython compile error - not parsable as a type
                                                                  # when keys_to_pop is a list
                            keys_to_pop.append(a_session_key)     # Make keys_to_pop use a deque instead

                #print 'sessHist: ', len(session_history_dict), ', queued to remove:', len(keys_to_pop)
                
    except IOError: # Handle signal during pipe access
        if not trafcap.options.quiet: print 'groupUpdater handled IOError....'


cdef bint groupBookkeeper_running = True
def groupBookkeeper(group_buffer, group_locks, group_alloc_pipe, group_dealloc_pipe, 
                    group_keeper_group_alloc_count, group_keeper_group_dealloc_count, proto_opts):

    # Signal Handling
    def groupBookkeeperCatchCntlC(signum, stack):
        print 'Caught CntlC in groupBookkeeper...'
        global groupBookkeeper_running
        groupBookkeeper_running = False

    signal.signal(signal.SIGINT, groupBookkeeperCatchCntlC)
    signal.signal(signal.SIGTERM, groupBookkeeperCatchCntlC)

    # Mongo Database connection
    db = trafcap.mongoSetup(w=0)

    session_groups_coll = db[proto_opts['session_groups_name']]
    session_groups2_coll = db[proto_opts['session_groups2_name']]
    capture_groups_coll = db[proto_opts['capture_groups_name']]
    capture_groups2_coll = db[proto_opts['capture_groups2_name']]

    cdef int i

    cdef alloc_capture_group* alloc_capture_group_function
    cdef long alloc_capture_group_address
    alloc_capture_group_address = <long>proto_opts['alloc_capture_group']
    alloc_capture_group_function = <alloc_capture_group*>alloc_capture_group_address

    cdef write_group* write_group_function
    cdef long write_group_address
    write_group_address = <long>proto_opts['write_group']
    write_group_function = <write_group*>write_group_address

    # Initialize a capture group.
    cdef GenericGroup* capture_group = <GenericGroup*>(alloc_capture_group_function[0])()

    # We also initialize a dummy group to aid code reuse below.  Everything
    # that touches this variable is wasting time, but we only have to touch it
    # once every 20 seconds or so.
    cdef GenericGroup* dummy_group = <GenericGroup*>(alloc_capture_group_function[0])()

    # Bookkeeping data for capture
    cdef list capture_object_ids = [None] # Capture group is in a category of one
    cdef uint64_t capture_scheduled_checkup_time = int(time.time())

    # Cythonize access to the shared buffers 
    cdef long group_buffer_addr = ctypes.addressof(group_buffer)
    #cdef GenericSession* sessions_buffer = <GenericSession*>live_session_buffer_addr
    cdef int group_struct_size = ctypes.sizeof(group_buffer) / len(group_buffer)

    # Create a corresponding bunch of slots for mongoids
    cdef list object_ids = [None for x in range(GROUP_BUFFER_SIZE)]

    # Cythonize the current slot number for group_buffer
    # These slots are allocated by groupUpdater and deallocated by groupBookkeeper
    py_current_group_slot = ctypes.c_uint32()
    cdef long group_slot_address = ctypes.addressof(py_current_group_slot)
    cdef uint32_t* group_slot_p = <uint32_t*>group_slot_address

    # Cythonize the current slot number for saved_session_ring_buffer
    # These slots are incrementing and loop around back to zero when last slot is reached 
    #py_current_saved_session_cursor = ctypes.c_uint32()
    #cdef long saved_session_cursor_address = ctypes.addressof(py_current_saved_session_cursor)
    #cdef uint32_t* saved_session_cursor_p = <uint32_t*>saved_session_cursor_address

    cdef GenericGroup* group 
    cdef GenericGroup* group_copy = <GenericGroup*>malloc(group_struct_size)
    #cdef uint64_t group_start_second
    cdef uint64_t group_end_second

    # Setup a bunch of queues for second-by-second scheduling of writes to the database
    cdef uint32_t schedule_sizes[GROUP_SCHEDULE_SIZE]
    memset(schedule_sizes, 0, sizeof(schedule_sizes))

    cdef uint32_t *schedule[GROUP_SCHEDULE_SIZE]
    for i in range(GROUP_SCHEDULE_SIZE):
        schedule[i] = <uint32_t*>malloc(sizeof(uint32_t) * GROUP_BUFFER_SIZE)

    # Variables during session check-ins
    cdef int schedule_row_number, next_schedule_row_number
    cdef uint32_t* slots_to_write
    cdef uint32_t slot

    cdef int bytes_cursor
    cdef uint32_t* bytes_subarray
    cdef int64_t seconds_since_last_bytes
    cdef int offset
    cdef uint64_t next_scheduled_checkup_time

    # Current second
    cdef uint64_t current_second = 0
    cdef uint64_t last_second_written = int(time.time()) - 1
    cdef uint64_t second_to_write, second_to_write_from

    cdef int mongo_session_writes = 0
    cdef int mongo_capture_writes = 0
    #cdef int session_count = 0
    
    ## Connection-Tracking Debugging ##
    tracked_slots = set()

    # The primary loop
    # There are several tasks to accomplish:
    #   - Process new groups.  We'll receive word of new connections as
    #     slot numbers via the pipe.  We need to schedule a time for the first 
    #     group documents to be written to the database.
    #
    #   - Once a second, revisit groups that have been sitting around for
    #     20 seconds.  These can be written to the database, and can sometimes
    #     be closed out. If they're closed out, we need to send word back to
    #     the update process, and open the slot back up.
    try:
        while groupBookkeeper_running:
            # Always check for new data.  If there is none, check the time
            # TODO: Better time/loop management
            if not group_alloc_pipe.poll(0.02):
                current_second = max(current_second, int(time.time()-2))
                #print 'Updating session_keeper current_second: ', current_second
                #time.sleep(0.02)
            
            while group_alloc_pipe.poll():
                # Read data from the pipe into a ctype, which is pointed to by
                # cython.  No type cohersion or translation required.
                # SIDE EFFECT: population of current_group_slot
                group_alloc_pipe.recv_bytes_into(py_current_group_slot)
                group_keeper_group_alloc_count.value += 1
    
                # Since session_buffer is now generic, we need to do memory addresses ourselves.
                group = <GenericGroup *>(group_buffer_addr + (group_slot_p[0] * group_struct_size))
                
                # This is this session's first check-in.  We need to schedule the first check-up.
    
                # The schedule structure is GROUPS_SCHEDULE_SIZE (90) rows or slots.  Since group db writes
                # are not time critical and to keep the schedule balanced, groups are place randomly
                # into a schedule slot.  Schedule rows are numbered time mod GROUP_SCHEDULE_SIZE.
                # A group always remains in the slot it is originally placed in.  
                #group_start_second = <uint64_t>group.tbm
                # Use group_start_second falls on 15 minute or 3 hour intervals.  Use end_second to 
                # get more frequent timestamp. 
                group_end_second = <uint64_t>group.tem
                # Spread out assigned slots randomly to prevent a few slots corresponding to the 
                # start-up time from containing most groups.  Limited screen resolution in the UI 
                # gives some wiggle-room to timing of group updates.  
                schedule_row_number = random.randrange(0,GROUP_SCHEDULE_SIZE)
                
                #print "Scheduling",group_slot_p[0],"in",schedule_row_number,",",schedule_sizes[schedule_row_number], "( tem is ", int(group.tem),")"
                # schedule_row_number = row in the schedule
                # schedule_sizes[schedule_row_number] = first empty slot in the row
                schedule[schedule_row_number][schedule_sizes[schedule_row_number]] = group_slot_p[0]
                schedule_sizes[schedule_row_number] += 1
    
                # Alternative mechanism to ensure time is updated periodically.  Session being handled has
                # already been scheduled
################################# need to improve this.  It doesn't hurt anything but 
                # group_start_second is always on a minute boundary
                if group_end_second > current_second:
                    current_second = group_end_second
                    break

                ## Connection-Tracking Debug ##
                #if len(tracked_slots) < 1:
                #    tcp_group = <TCPGroup *>group
                #    if tcp_group.port2 == 3389:
                #        print "groupKeeper tracking slot", group_slot_p[0]
                #        tracked_slots.add(group_slot_p[0])

                ## For debug
                #if group_keeper_group_alloc_count.value % 1000 == 0:
                #    print 'group_start_second:', group_start_second,\
                #          'current_second:', current_second,\
                #          'schedule_row_number:', schedule_row_number,\
                #          'schedule_sizes[row]:',schedule_sizes[schedule_row_number]
    
            # For debug
            #for slot in tracked_slots:
            #    group = <GenericGroup *>(group_buffer_addr + (<uint32_t>slot * group_struct_size))
            #    if group.csldw == yes:
            #        lock = group_locks[slot % GROUPS_PER_LOCK] 
            #        lock.acquire()
            #        print_tcp_group(group, 0)
            #        lock.release()
            #        group.csldw = no

    
            # Check for data to be written to the database.  A few possibile scenarios:
            # - group is new and has not yet been saved to db, write it now
            # - group has been saved to the db but more bytes have been added, write/update
            # - group has been saved to the db but no more bytes have been added, no db write
            if (last_second_written + 1) < current_second:
                second_to_write = last_second_written + 1
                #second_to_write_from = second_to_write - GROUP_SCHEDULE_PERIOD
                # Bytes cursor is the point in the bytes array to start looking for data.
                #bytes_cursor = second_to_write_from % GROUP_SCHEDULE_SIZE 
    
                schedule_row_number = second_to_write % GROUP_SCHEDULE_SIZE
                slots_to_write = schedule[schedule_row_number]
    
                #print "Processing",second_to_write,"( schedule #", int(schedule_row_number), ")"
    
                # Bytes ring data already written to db is set to zero by update_session.
                # Bookkeeper maintains capture bytes so something similar must be done here.
                # Upcoming session writes will write up to but not into second_to_write, 
                # so we set to zero so bytes don't grow indefinately.  
                capture_group.traffic_bytes[(second_to_write - 1) % GROUP_SCHEDULE_SIZE][0] = 0
                capture_group.traffic_bytes[(second_to_write - 1) % GROUP_SCHEDULE_SIZE][1] = 0
                 
                # Iterate over all the slots scheduled to be dealt with this
                # second, and deal with them.
                #print "Initializing sessionInfo_bulk_writer..."
                session_groups_bulk_writer = session_groups_coll.initialize_unordered_bulk_op()
                #print "Initializing sessionBytes_bulk_writer..."
                capture_groups_bulk_writer = capture_groups_coll.initialize_unordered_bulk_op()
                #print "Starting loop..."
                for i in range(schedule_sizes[schedule_row_number]):
                    #print "Reading",schedule_row_number,i,":",schedule[schedule_row_number][i]
                    slot = slots_to_write[i]
                    # Get the group from the buffer
                    group = <GenericGroup *>(group_buffer_addr + (slot * group_struct_size))
                    lock = group_locks[slot % GROUPS_PER_LOCK] 
                    lock.acquire()
                    # Get the data we need as quickly as possible so we can release the lock.
                    memcpy(group_copy, group, group_struct_size)
                    #memcpy(session_copy, session, sizeof(TCPSession)
                    lock.release()
    
                    #if slot in tracked_slots:
                        #print_tcp_session(session, second_to_write_from)
                    #print second_to_write,":",i,": slot", slot, ", last data", current_second - <uint64_t>session_copy.te
    
                    #seconds_since_last_bytes = <int64_t>(second_to_write - <uint64_t>group_copy.tem)
    
                    # Either reschedule the session for another check-in,
                    # or de-allocate the slot.
                    next_scheduled_checkup_time = 0
                    #if (seconds_since_last_bytes) > 300:
                    #    # We don't set next_scheduled_checkup_time, and deallocate below
                    #    pass
                    # 
                    #elif (seconds_since_last_bytes) > BYTES_DOC_SIZE:
                    #    # There's nothing to read, reschedule for 20 seconds from now
                    #    next_scheduled_checkup_time = second_to_write + BYTES_DOC_SIZE
                    # 
                    
                    # Write to db if the group has changed since the last db write
                    if chr(group.csldw) == 'x':
#                        # Write to database (or at least queue)
#                        (write_group_function[0])(session_group_bulk_writer, capture_group_bulk_writer, 
#                                                  session_info_coll, object_ids, session_copy, slot, 
#                                                  second_to_write_from, second_to_write, capture_group)
#                         
#                        mongo_session_writes += 2
                        next_scheduled_checkup_time = second_to_write + GROUP_SCHEDULE_PERIOD 
#    
#                        ## Connection-Tracking Debug ##
#                        #if slot in tracked_slots:
#                        #    print second_to_write,": Writing slot",slot
#    
                    else:
                        # Reschedule if the group is not expired
######################################hack to test deallocate
                            if peg_to_15minute(current_second) <= group.tbm:
                                # Schedule another look at the group in about a minute
                                next_scheduled_checkup_time = second_to_write + GROUP_SCHEDULE_PERIOD 
                                #for offset in range(BYTES_DOC_SIZE):
                                #    bytes_subarray = session.traffic_bytes[(bytes_cursor + offset) % BYTES_RING_SIZE]
                                #    if bytes_subarray[0] > 0 or bytes_subarray[1] > 0:
                                #        next_scheduled_checkup_time = second_to_write + offset
                                #        break
    
                    # Reschedule if we selected a time to do so.
                    if next_scheduled_checkup_time > 0:
                        next_schedule_row_number = next_scheduled_checkup_time % GROUP_SCHEDULE_SIZE 
                                   
                        schedule[next_schedule_row_number][schedule_sizes[next_schedule_row_number]] = slot
                        schedule_sizes[next_schedule_row_number] += 1
                        ## Connection-Tracking Debug ##
                        #if slot in tracked_slots:
                        #    print second_to_write,": Rescheduling", slot, "for", next_scheduled_checkup_time, "(", (next_scheduled_checkup_time - second_to_write), "seconds)"
    
                    else:

                        #print "Deallocating", slot
                        # Write to groupUpdater about a newly freed slot.  On this
                        # end, all we have to do is free up the objectid slot and
                        # update the capture packets counter with all the packets
                        # from this session.
###############################  Group does not have a packet counter - should it ???
                        #capture_session.packets += session.packets
                        # object_ids assigned in the write_session function
                        object_ids[slot] = None

                        # We're still linking to a python struct to get raw bytes
                        # into a python Pipe.
                        group_slot_p[0] = slot  # Linked to py_current_session_slot!
                        group_dealloc_pipe.send_bytes(py_current_group_slot)
                        group_keeper_group_dealloc_count.value += 1
    
                        ## Connection-Tracking Debug ##
                        #if slot in tracked_slots:
                        #    print second_to_write,": Deallocating", slot
                        #    tracked_slots.remove(slot)
                 
                # Write pending bulk operations to mongo
                try:
                    #print "Doing sessionInfo_bulk_write..."
                    info_bulk_writer.execute()
                except InvalidOperation as e:
                    if e.message != "No operations to execute":
                        raise e
    
                try:
                    #print "Doing sessionBytes_bulk_write..."
                    bytes_bulk_writer.execute()
                except InvalidOperation as e:
                    if e.message != "No operations to execute":
                        raise e
    
    
                # Check to see if capture info/bytes should be written.  This only
                # happens once a second, so we're not super concerned about
                # efficiency.
                if capture_scheduled_checkup_time <= second_to_write:
                    # Not so unlike writing a normal session, but with some
                    # shortcuts and dummy data.
                    #print "Initializing captureInfo_bulk_writer..."
                    info_bulk_writer = capture_info_coll.initialize_unordered_bulk_op()
                    #print "Initializing captureBytes_bulk_writer..."
                    bytes_bulk_writer = capture_bytes_coll.initialize_unordered_bulk_op()
#    
#                    (write_group_function[0])(info_bulk_writer, bytes_bulk_writer, capture_info_coll, 
#                                              capture_object_ids, capture_session, 0, 
#                                              capture_scheduled_checkup_time - BYTES_DOC_SIZE - (BYTES_DOC_SIZE / 2), 
#                                              capture_scheduled_checkup_time - BYTES_DOC_SIZE, dummy_group)
#    
#                    mongo_capture_writes += 2
#                    capture_scheduled_checkup_time = second_to_write + (BYTES_DOC_SIZE / 2)
#    
#                    # Write pending bulk operations to mongo
#                    try:
#                        #print "Doing captureInfo_bulk_write..."
#                        info_bulk_writer.execute()
#                    except InvalidOperation as e:
#                        if e.message != "No operations to execute":
#                            raise e
#    
#                    try:
#                        #print "Doing captureBytes_bulk_write..."
#                        bytes_bulk_writer.execute()
#                    except InvalidOperation as e:
#                        if e.message != "No operations to execute":
#                            raise e
#                    
#    
#                #print mongo_capture_writes, "capture, ", mongo_session_writes, "session writes covering", session_count, "sessions"
    
                # Reset the now-finished schedule slot
                schedule_sizes[schedule_row_number] = 0
                # Mark that we've taken care of this second.
                last_second_written += 1

    except IOError: # Handle signal during pipe access
        if not trafcap.options.quiet: print 'groupBookkeeper handled IOError....'


start_bold = "\033[1m"
end_bold = "\033[0;0m"

cdef bint main_running = True
def main():
    # The main function is responsible for setting up and kicking off the parse
    # function and the ingest function.  It tries to be responsible for all
    # interupts, fatal errors, and cleanup.

    #TODO: Options processing should probably go here, as well as interrupt code.
    options = parseOptions()     # Could combine this line with next line
    trafcap.options = options

    option_check_counter = 0
    if options.tcp: option_check_counter += 1
    if options.udp: option_check_counter += 1
    if options.icmp: option_check_counter += 1
    if options.other: option_check_counter += 1
    if options.rtp: option_check_counter += 1
    if option_check_counter != 1:
        sys.exit("Must use one of -t, -u, -i, or -o to specify a protocol.")

    proto_opts = {}

    # Select protocol.  Note that packet_type variable must be set
    if options.tcp:
        proto_opts['bpf_filter'] = 'ip and tcp'
        proto_opts['parse_packet'] = <long>&parse_tcp_packet 
        proto_opts['generate_session_key_from_pkt'] = <long>&generate_tcp_session_key_from_pkt
        proto_opts['generate_session'] = <long>&generate_tcp_session
        proto_opts['update_session'] = <long>&update_tcp_session
        proto_opts['generate_session_key_from_session'] = <long>&generate_tcp_session_key_from_session
        proto_opts['alloc_capture_session'] = <long>&alloc_tcp_capture_session
        proto_opts['write_session'] = <long>&write_tcp_session
        proto_opts['packet_header_class_name'] = 'PythonTCPPacketHeaders'
        proto_opts['session_class_name'] = 'PythonTCPSession'
        proto_opts['group_class_name'] = 'PythonTCPGroup'
        proto_opts['session_info_coll_name'] = 'tcp_sessionInfo'
        proto_opts['session_bytes_coll_name'] = 'tcp_sessionBytes'
        proto_opts['capture_info_coll_name'] = 'tcp_captureInfo'
        proto_opts['capture_bytes_coll_name'] = 'tcp_captureBytes'
        proto_opts['capture_groups_name'] = 'tcp_captureGroups'
        proto_opts['capture_groups2_name'] = 'tcp_captureGroups2'
        proto_opts['session_groups_name'] = 'tcp_sessionGroups'
        proto_opts['session_groups2_name'] = 'tcp_sessionGroups2'
        proto_opts['write_group'] = <long>&write_tcp_group
        proto_opts['alloc_capture_group'] = <long>&alloc_tcp_capture_group
        proto_opts['generate_group'] = <long>&generate_tcp_group
        proto_opts['generate_group_key_from_session'] = <long>&generate_tcp_group_key_from_session
        proto_opts['generate_group_key_from_group'] = <long>&generate_tcp_group_key_from_group
        proto_opts['update_group'] = <long>&update_tcp_group

    elif options.udp:
        proto_opts['bpf_filter'] = 'ip and udp'
        proto_opts['parse_packet'] = <long>&parse_udp_packet 
        proto_opts['generate_session_key_from_pkt'] = <long>&generate_udp_session_key_from_pkt
        proto_opts['generate_session'] = <long>&generate_udp_session
        proto_opts['update_session'] = <long>&update_udp_session
        proto_opts['generate_session_key_from_session'] = <long>&generate_udp_session_key_from_session
        proto_opts['alloc_capture_session'] = <long>&alloc_udp_capture_session
        proto_opts['write_session'] = <long>&write_udp_session
        proto_opts['packet_header_class_name'] = 'PythonUDPPacketHeaders'
        proto_opts['session_class_name'] = 'PythonUDPSession'
        proto_opts['group_class_name'] = 'PythonUDPGroup'
        proto_opts['session_info_coll_name'] = 'udp_sessionInfo'
        proto_opts['session_bytes_coll_name'] = 'udp_sessionBytes'
        proto_opts['capture_info_coll_name'] = 'udp_captureInfo'
        proto_opts['capture_bytes_coll_name'] = 'udp_captureBytes'
        proto_opts['capture_groups_name'] = 'udp_captureGroups'
        proto_opts['capture_groups2_name'] = 'udp_captureGroups2'
        proto_opts['session_groups_name'] = 'udp_sessionGroups'
        proto_opts['session_groups2_name'] = 'udp_sessionGroups2'
        proto_opts['write_group'] = <long>&write_udp_group
        proto_opts['alloc_capture_group'] = <long>&alloc_udp_capture_group
        proto_opts['generate_group'] = <long>&generate_udp_group
        proto_opts['generate_group_key_from_session'] = <long>&generate_udp_group_key_from_session
        proto_opts['generate_group_key_from_group'] = <long>&generate_udp_group_key_from_group
        proto_opts['update_group'] = <long>&update_udp_group

    elif options.icmp:
        sys.exit("-i not implemeted yet.")
    elif options.other:
        sys.exit("-o not implemeted yet.")
    elif options.rtp:
        sys.exit("-r not implemeted yet.")
    else:
       sys.exit('Invalid protocol') 

    packet_header_class = eval(proto_opts['packet_header_class_name'])
    session_class = eval(proto_opts['session_class_name'])
    group_class = eval(proto_opts['group_class_name'])

    def catchSignal1(signum, stac):
        print 'Caught Signal1 in main....'

    def catchSignal2(signum, stack):
        print 'Caught Signal2 in main....'

    def catchCntlC(signum, stack):
        print 'Caught CntlC in main....'
        global main_running
        main_running = False

    signal.signal(signal.SIGUSR1, catchSignal1)
    signal.signal(signal.SIGUSR2, catchSignal2)
    signal.signal(signal.SIGINT, catchCntlC)
    signal.signal(signal.SIGTERM, catchCntlC)

    oldest_session_time = int(time.time()) - trafcap.session_expire_timeout

    # Will be replaced by ring stats 
    parser_packet_count = multiprocessing.Value(ctypes.c_uint64)
    parser_packet_count.value = 0

    packet_cursor_pipe = multiprocessing.Pipe(False)
    # Try to increase pipe buffer size
    #import fcntl  
    #fd = packet_cursor_pipe[1].fileno() 
    #fl = fcntl.fcntl(fd, fcntl.F_GETFL) 
    #print 'has_attr: ', hasattr(fcntl, 'F_SETPIPE_SZ')  ==> This is False
    #fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK) 
    packet_ring_buffer = multiprocessing.RawArray(packet_header_class, RING_BUFFER_SIZE)

    ring_stats_recv = multiprocessing.Value(ctypes.c_uint64)
    ring_stats_recv.value = 0
    ring_stats_drop = multiprocessing.Value(ctypes.c_uint64)
    ring_stats_drop.value = 0

    session_updater_packet_count = multiprocessing.Value(ctypes.c_uint64)
    session_updater_packet_count.value = 0
    session_updater_live_session_alloc_count = multiprocessing.Value(ctypes.c_uint64)
    session_updater_live_session_alloc_count.value = 0
    session_updater_live_session_dealloc_count = multiprocessing.Value(ctypes.c_uint64)
    session_updater_live_session_dealloc_count.value = 0
    session_keeper_live_session_alloc_count = multiprocessing.Value(ctypes.c_uint64)
    session_keeper_live_session_alloc_count.value = 0
    session_keeper_live_session_dealloc_count = multiprocessing.Value(ctypes.c_uint64)
    session_keeper_live_session_dealloc_count.value = 0
    session_keeper_saved_session_count = multiprocessing.Value(ctypes.c_uint64)
    session_keeper_saved_session_count.value = 0

    live_session_buffer = multiprocessing.RawArray(session_class, LIVE_SESSION_BUFFER_SIZE)
    live_session_alloc_pipe = multiprocessing.Pipe(False)
    live_session_dealloc_pipe = multiprocessing.Pipe(False)
    live_session_locks = tuple((multiprocessing.Lock() for i in xrange(LIVE_SESSION_BUFFER_SIZE/SESSIONS_PER_LOCK)))

    saved_session_cursor_pipe = multiprocessing.Pipe(False)
    saved_session_ring_buffer = multiprocessing.RawArray(session_class, RING_BUFFER_SIZE)
    group_buffer = multiprocessing.RawArray(group_class, GROUP_BUFFER_SIZE)
    group_alloc_pipe = multiprocessing.Pipe(False)
    group_dealloc_pipe = multiprocessing.Pipe(False)
    group_locks = tuple((multiprocessing.Lock() for i in xrange(GROUP_BUFFER_SIZE/GROUPS_PER_LOCK)))
    group_updater_saved_session_count = multiprocessing.Value(ctypes.c_uint64)
    group_updater_saved_session_count.value = 0
    group_updater_group_alloc_count = multiprocessing.Value(ctypes.c_uint64)
    group_updater_group_alloc_count.value = 0
    group_updater_group_dealloc_count = multiprocessing.Value(ctypes.c_uint64)
    group_updater_group_dealloc_count.value = 0
    group_updater_session_history_count = multiprocessing.Value(ctypes.c_uint64)
    group_updater_session_history_count.value = 0
    group_keeper_group_alloc_count = multiprocessing.Value(ctypes.c_uint64)
    group_keeper_group_alloc_count.value = 0
    group_keeper_group_dealloc_count = multiprocessing.Value(ctypes.c_uint64)
    group_keeper_group_dealloc_count.value = 0

    packet_parser = multiprocessing.Process(target = packetParser, 
        args=(packet_cursor_pipe[1], parser_packet_count, 
              packet_ring_buffer, 
              ring_stats_recv, ring_stats_drop, proto_opts))
    session_updater = multiprocessing.Process(target = sessionUpdater, 
        args=(packet_cursor_pipe[0], session_updater_packet_count, 
              packet_ring_buffer, live_session_buffer, live_session_locks, 
              live_session_alloc_pipe[1],  live_session_dealloc_pipe[0], 
              session_updater_live_session_alloc_count, session_updater_live_session_dealloc_count, proto_opts))
    session_keeper = multiprocessing.Process(target = sessionBookkeeper,
        args=(live_session_buffer, live_session_locks, 
              live_session_alloc_pipe[0], live_session_dealloc_pipe[1], 
              session_keeper_live_session_alloc_count, session_keeper_live_session_dealloc_count, 
              saved_session_cursor_pipe[1], saved_session_ring_buffer, session_keeper_saved_session_count, proto_opts))
    group_updater = multiprocessing.Process(target = groupUpdater,
        args=(saved_session_cursor_pipe[0], group_updater_saved_session_count, 
              saved_session_ring_buffer, group_buffer, group_locks, 
              group_alloc_pipe[1],  group_dealloc_pipe[0], 
              group_updater_group_alloc_count, group_updater_group_dealloc_count, 
              group_updater_session_history_count, proto_opts))
    group_keeper = multiprocessing.Process(target = groupBookkeeper,
        args=(group_buffer, group_locks, group_alloc_pipe[0], group_dealloc_pipe[1], 
              group_keeper_group_alloc_count, group_keeper_group_dealloc_count, proto_opts))

    packet_parser.start()
    session_updater.start()
    session_keeper.start()
    group_updater.start()
    group_keeper.start()

    prev_parser_packet_count = 0
    prev_session_updater_live_session_alloc_count = 0
    prev_group_updater_saved_session_count = 0
    loop_count = 0
    while main_running:
        time.sleep(1)
        #rsr = ring_stats_recv.value
        rsd = ring_stats_drop.value

        ppc = parser_packet_count.value
        pps = ppc - prev_parser_packet_count
        supc = session_updater_packet_count.value
        ppql = ppc - supc  # parser-to-updater q length
        
        ulsac = session_updater_live_session_alloc_count.value
        ulsps = ulsac - prev_session_updater_live_session_alloc_count
        klsac = session_keeper_live_session_alloc_count.value
        saql = ulsac - klsac  # allocate (updater-to-keeper) q length

        ulsdc = session_updater_live_session_dealloc_count.value
        klsdc = session_keeper_live_session_dealloc_count.value
        sdql = klsdc - ulsdc # deallocate (keeper-to-updater) q length
        klsc = klsac - klsdc # live session count

        kssc = session_keeper_saved_session_count.value
        gussc = group_updater_saved_session_count.value
        ssps = gussc - prev_group_updater_saved_session_count
        ssql = kssc - gussc  # saved_session queue length
        gugac = group_updater_group_alloc_count.value
        gugdc = group_updater_group_dealloc_count.value
        gushc = group_updater_session_history_count.value

        gkgac = group_keeper_group_alloc_count.value
        gkgdc = group_keeper_group_dealloc_count.value
        gklgc = gkgac - gkgdc # live group count
        gaql = gugac - gkgac # group allocate q length
        gdql = gkgdc - gugdc # group de-allocate q length

        prev_parser_packet_count = ppc
        prev_session_updater_live_session_alloc_count = ulsac
        prev_group_updater_saved_session_count = gussc 

        #print '{0:9d} {1:6d} > {2:3d} > {3:10d} {4:7d} > {5:4d}  {6:4d} < {7:8d} {8:7d}'.format(rsd, pps, ppql, supc, ulsps, saql, sdql, klsac, klsc)
        #if loop_count % 10 == 0:
        #    print '{0:>10}{1:>5}{2:>21}{3:>5}{4:>5}{5:^10}{6:>11}{7:>5}{8:>3}'.format('---parser:', parser.pid, '--     -----updater:', session_updater.pid, '---- ',loop_count,' ---keeper:',session_keeper.pid,'---')
        #    print '{0:>9} {1:>6}    {2:^3}  {3:>10} {4:>7}    {5:^4}   {6:^4} {7:>8} {8:>7}'.format('drop', 'pps', ' ', 'pkts', 'ulsps', ' ',' ', 'sess', 'live')
        #    global main_running
        #    if pps == 0: main_running = False

        if loop_count % 10 == 0:
            if loop_count % 20 == 0:
                print '{0:>10}{1:>5}{2:>14}{3:>5}{4:>14}{5:>5}{6:>11}{7:>5}{8:>11}{9:>5}'.format(
                '---parser:', packet_parser.pid, 
                '---    -updtr:', session_updater.pid, 
                '-       --kpr:', session_keeper.pid,
                '-  -gUpdtr:',group_updater.pid,
                '-     gKpr:', group_keeper.pid)
            else:
                print str(datetime.today().strftime("%a %m/%d/%y %H:%M:%S"))+' ----- d:h:m:s '+str(loop_count/86400)+':'+str((loop_count/3600)%24)+':'+str((loop_count/60)%60)+':'+str(loop_count%60)+' ---------------- sessionHist: '+str(gushc)
            print start_bold,
            print '{0:>8} {1:>6} {2:^4}  {3:>7}  {4:^4}  {5:^4}  {6:>7} {7:^4}  {8:>7} {9:^4}  {10:^4} {11:>8}'.format(
                  'drop', 'pps',   ' ', 'lsps',   ' ',    ' ', 'liveSns', ' ',  'ssps',  ' ',    ' ', 'liveGrps'),
            print end_bold

        print '{0:9d} {1:6d} {2:4d}> {3:7d} {4:4d}>  {5:4d}< {6:7d} {7:4d}> {8:7d} {9:4d}> {10:4d}< {11:7d}'.format(
                rsd,   pps,   ppql,  ulsps,  saql,    sdql,   klsc,  ssql,   ssps,  gaql,    gdql,   gklgc)

        loop_count += 1
        sys.stdout.flush()

    # Handle shutdown 
    packet_parser.join(1)
    session_updater.join(1)
    session_keeper.join(1)
    group_updater.join(1)
    group_keeper.join(1)
    
    # Just in case...
    if packet_parser.is_alive(): 
        print 'parser still alive...';sys.stdout.flush()
        #packet_parser.terminate()
    if session_updater.is_alive(): 
        print 'updater still alive...';sys.stdout.flush()
        #session_updater.terminate()
    if session_keeper.is_alive(): 
        print 'keeper still alive...';sys.stdout.flush()
        #session_keeper.terminate()
    if group_updater.is_alive(): 
        print 'group_updater still alive...';sys.stdout.flush()
        #group_updater.terminate()
    if group_keeper.is_alive(): 
        print 'group_keeper still alive...';sys.stdout.flush()
        #group_keeper.terminate()


if __name__ == "__main__":
    main()
