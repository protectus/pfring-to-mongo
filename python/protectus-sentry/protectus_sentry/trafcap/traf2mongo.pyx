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
#from trafcapIpPacket cimport BYTES_RING_SIZE, BYTES_DOC_SIZE, GenericPacketHeaders, TCPPacketHeaders, GenericSession, TCPSession, parse_tcp_packet, generate_tcp_session, update_tcp_session, print_tcp_packet, print_tcp_session, generate_tcp_session_key_from_pkt, generate_tcp_session_key_from_session, write_tcp_session, alloc_tcp_capture_session, generate_udp_session_key_from_pkt, parse_udp_packet
from trafcapIpPacket cimport * 
from trafcapEthernetPacket import *
from trafcapContainer import *
import multiprocessing
import Queue
from collections import deque
from pymongo.bulk import InvalidOperation

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
    global parsePkts_running
    parsePkts_running = False
    global updateDict_running
    updateDict_running = False
    global bookkeeper_running
    bookkeeper_running = False
    os.kill(os.getpid(), signal.SIGTERM)

# Hack to bypass error when importing macro from pfring.h
DEF PF_RING_LONG_HEADER = 4
DEF NO_ZC_BUFFER_LEN = 256 

cdef bint parsePkts_running = True 
def parsePkts(parsed_packet_pipe, parsed_packet_count, python_ppshared, 
              recv_stats, drop_stats, proto_opts, options):

    # First, setup signal handling
    def parsePktsCatchCntlC(signum, stack):
        print 'Caught CntlC in parsePkts...'
        global parsePkts_running
        parsePkts_running = False
        #pfring_breakloop(pd)

    signal.signal(signal.SIGINT, parsePktsCatchCntlC)
    signal.signal(signal.SIGTERM, parsePktsCatchCntlC)
    
    # Give Cython code low-level access to the shared memory array
    cdef long ppshared_address = ctypes.addressof(python_ppshared)
    cdef int packet_struct_size = ctypes.sizeof(python_ppshared) / len(python_ppshared)
    #cdef TCPPacketHeaders* ppshared = <TCPPacketHeaders*>ppshared_address
    cdef GenericPacketHeaders* ppshared = <GenericPacketHeaders*>ppshared_address
    #cdef TCPPacketHeaders* current_shared_pkt
    cdef GenericPacketHeaders* current_shared_pkt

    # Make the pipe data a raw buffer.  Enables cython later>
    python_shared_packet_cursor_in = ctypes.c_uint32()
    cdef long shared_packet_cursor_in_address = ctypes.addressof(python_shared_packet_cursor_in)
    cdef uint32_t* shared_packet_cursor_in_p = <uint32_t*>shared_packet_cursor_in_address

    #cdef int shared_packet_cursor_in = 0
    #cdef int parse_return_code

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

    if options.tcp:
        parse_packet = parse_tcp_packet
    elif options.udp:
        parse_packet = parse_udp_packet
    else:
        # TODO - exitNow not working from subprocesses
        exitNow('Invalid protocol.')

    while parsePkts_running:
        pfring_recv(pd, &buffer_p, NO_ZC_BUFFER_LEN, &hdr, wait_for_packet)

        #if shared_packet_cursor_in_p[0] == 0:
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
    
        # Since ppshared is now generic, we need to do memory addresses ourselves.
        current_shared_pkt = <GenericPacketHeaders*>(ppshared_address + (shared_packet_cursor_in_p[0] * packet_struct_size))
        # Here is the old way of finding the current_shared_packet
        #current_shared_pkt = &ppshared[shared_packet_cursor_in_p[0]]

        parse_packet(current_shared_pkt, &hdr)

        #current_shared_pkt.ip1 = pp.ip_src.v4
        #current_shared_pkt.ip2 = pp.ip_dst.v4
        #current_shared_pkt.port1 = pp.l4_src_port 
        #current_shared_pkt.port2 = pp.l4_dst_port 
        #current_shared_pkt.base.timestamp = <double>hdr.ts.tv_sec + (<double>hdr.ts.tv_usec / 1000000.0)
        #current_shared_pkt.vlan_id = pp.vlan_id 
        #current_shared_pkt.bytes = hdr.c_len 
        #current_shared_pkt.flags = pp.tcp.flags 
    
        parsed_packet_count.value += 1
        parsed_packet_pipe.send_bytes(python_shared_packet_cursor_in)  
        shared_packet_cursor_in_p[0] = (shared_packet_cursor_in_p[0] + 1) % 100000

    time.sleep(1)   # sample code included this - not sure if necessary
    pfring_close(pd)


DEF GET_WAIT = 0.01
cdef bint updateDict_running = True
def updateDict(parsed_packet_pipe, updater_pkt_count, python_ppshared, python_sessions_shared, session_locks, session_alloc_pipe, sessions_dealloc_pipe, updater_session_count, updater_dealloc_session_count, options):

    # Signal Handling
    def updateDictCatchCntlC(signum, stack):
        print 'Caught CntlC in updateDict...'
        global updateDict_running
        updateDict_running = False

    signal.signal(signal.SIGINT, updateDictCatchCntlC)
    signal.signal(signal.SIGTERM, updateDictCatchCntlC)

    # Cythonize access to the shared packets
    #print "Shared Packet space based at:", str(ctypes.addressof(python_ppshared))
    cdef long ppshared_address = ctypes.addressof(python_ppshared)
    cdef GenericPacketHeaders* ppshared = <GenericPacketHeaders*>ppshared_address
    cdef int packet_struct_size = ctypes.sizeof(python_ppshared) / len(python_ppshared)
    #print "Packet struct is of size", packet_struct_size

    # Cythonize access to the shared sessions
    #print "Shared session space based at:", str(ctypes.addressof(python_sessions_shared))
    cdef long sessions_address = ctypes.addressof(python_sessions_shared)
    cdef GenericSession* sessions_shared = <GenericSession*>sessions_address
    cdef int session_struct_size = ctypes.sizeof(python_sessions_shared) / len(python_sessions_shared)
    #print "Session struct is of size", session_struct_size

    # Make the outgoing pipe data a raw buffer.  Enables cython later>
    new_slot_number_pipeable = ctypes.c_uint32()
    cdef long new_slot_number_address = ctypes.addressof(new_slot_number_pipeable)
    cdef uint32_t* new_slot_number_p = <uint32_t*>new_slot_number_address

    # Loop Variables
    cdef int get_loop_counter = 0
    cdef bint update_db = False

    # Make the incoming pipe data a raw buffer.  Enables cython later>
    python_shared_packet_cursor_out = ctypes.c_uint32()
    cdef long shared_packet_cursor_out_address = ctypes.addressof(python_shared_packet_cursor_out)
    cdef uint32_t* shared_packet_cursor_out_p = <uint32_t*>shared_packet_cursor_out_address

    available_slots = deque(xrange(1000000))
    cdef dict session_slot_map = {}
    cdef int session_slot
    cdef GenericSession* session

    if options.tcp:
        generate_session_key_from_pkt = generate_tcp_session_key_from_pkt
        generate_session = generate_tcp_session
        update_session = update_tcp_session
        generate_session_key_from_session = generate_tcp_session_key_from_session
    elif options.udp:
        generate_session_key_from_pkt = generate_udp_session_key_from_pkt
        generate_session = generate_udp_session
        update_session = update_udp_session
        generate_session_key_from_session = generate_udp_session_key_from_session
    else:
        # TODO - exitNow not working from subprocesses
        exitNow('Invalid protocol.')

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
    while updateDict_running:
        try:
            parsed_packet_pipe.recv_bytes_into(python_shared_packet_cursor_out)
            updater_pkt_count.value += 1
        except IOError:
            # Exception occurs if signal handled during get
            continue

        # Since ppshared is now generic, we need to do memory addresses ourselves.
        packet = <GenericPacketHeaders*>(ppshared_address + (shared_packet_cursor_out_p[0] * packet_struct_size))
        #print "Parsing Packet at", ppshared_address, "+", shared_packet_cursor_out_p[0], "*", packet_struct_size, "=",  str(<long>packet)
        #print_tcp_packet(packet)

        # Get the session's key for lookup
        session_key = generate_session_key_from_pkt(packet)

        # Let the dictionary tell us where the session lives
        session_slot = session_slot_map.get(session_key,-1)

        # If no session existed already, we need to make one.
        if (session_slot == -1):
            # Create new session from packet
            # This is linked to new_slot_number_pipeable!
            new_slot_number_p[0] = available_slots.popleft()
            # Since sessions_shared is now generic, we need to do memory addresses ourselves.
            session = <GenericSession *>(sessions_address + (new_slot_number_p[0] * session_struct_size))
            generate_session(session, packet)

            # Map the key to the new session
            session_slot_map[session_key] = new_slot_number_p[0]
            
            # Tell next phase about the new session
            session_alloc_pipe.send_bytes(new_slot_number_pipeable)
            #print "Created new session at slot", new_slot_number_p[0]
            updater_session_count.value += 1
        else:
            # Update existing session
            # Since sessions_shared is now generic, we need to do memory addresses ourselves.
            session = <GenericSession *>(sessions_address + (session_slot * session_struct_size))
            lock = session_locks[session_slot % 100]  # orig %1000
            lock.acquire()
            update_session(session, packet)
            lock.release()

        # Get released slots from next phase
        if sessions_dealloc_pipe.poll():
            sessions_dealloc_pipe.recv_bytes_into(new_slot_number_pipeable)
            updater_dealloc_session_count.value += 1
            available_slots.append(new_slot_number_pipeable.value)
            # Generate a key so we can delete it from the dictionary
            del session_slot_map[generate_session_key_from_session(<GenericSession *>(sessions_address + (new_slot_number_p[0] * session_struct_size)))]
            #print "De-dictionary-ing session at slot", new_slot_number_p[0]
               

cdef bint bookkeeper_running = True
def bookkeeper(python_sessions_shared, session_locks, sessions_alloc_pipe, sessions_dealloc_pipe, keeper_session_count, keeper_dealloc_session_count, proto_opts, options):

    # Signal Handling
    def bookkeeperCatchCntlC(signum, stack):
        print 'Caught CntlC in bookkeeper...'
        global bookkeeper_running
        bookkeeper_running = False

    signal.signal(signal.SIGINT, bookkeeperCatchCntlC)
    signal.signal(signal.SIGTERM, bookkeeperCatchCntlC)

    # Mongo Database connection
    #db = trafcap.mongoSetup()
    db = trafcap.mongoSetup(w=0)

    cdef int i

    if options.tcp:
        alloc_capture_session = alloc_tcp_capture_session
        write_session = write_tcp_session
    elif options.udp:
        alloc_capture_session = alloc_udp_capture_session
        write_session = write_udp_session
    else:
        # TODO - exitNow not working from subprocesses
        exitNow('Invalid protocol.')

    # Initialize a capture session.
    cdef GenericSession* capture_session = <GenericSession*>alloc_capture_session()

    # We also initialize a dummy session to aid code reuse below.  Everything
    # that touches this variable is wasting time, but we only have to touch it
    # once every 20 seconds or so.
    cdef GenericSession* dummy_session = <GenericSession*>alloc_capture_session()

    # Bookkeeping data for capture
    cdef list capture_object_ids = [None] # Capture sessions are in a category of one
    cdef uint64_t capture_scheduled_checkup_time = int(time.time())

    # Cythonize access to the shared sessions
    cdef long sessions_address = ctypes.addressof(python_sessions_shared)
    cdef GenericSession* sessions_shared = <GenericSession*>sessions_address
    cdef int session_struct_size = ctypes.sizeof(python_sessions_shared) / len(python_sessions_shared)

    # Create a corresponding bunch of slots for mongoids
    cdef list object_ids = [None for x in range(1000000)]

    # Cythonize the current slot number
    py_current_slot = ctypes.c_uint32()
    cdef long session_slot_address = ctypes.addressof(py_current_slot)
    cdef uint32_t* session_slot_p = <uint32_t*>session_slot_address

    cdef GenericSession* session
    cdef GenericSession* session_copy = <GenericSession*>malloc(session_struct_size)
    cdef uint64_t session_start_second

    # Setup a bunch of queues for second-by-second scheduling of writes to the database
    cdef uint32_t schedule_sizes[BYTES_RING_SIZE]
    memset(schedule_sizes, 0, sizeof(schedule_sizes))

    cdef uint32_t *schedule[BYTES_RING_SIZE]
    for i in range(BYTES_RING_SIZE):
        schedule[i] = <uint32_t*>malloc(sizeof(uint32_t) * 1000000)

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
    cdef int session_count = 0
    
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
    while bookkeeper_running:
        # Always check for new data.  If there is none, check the time
        # TODO: Better time/loop management
        if not sessions_alloc_pipe.poll(0.02):
            current_second = max(current_second, int(time.time()-2))
            #print 'Updating keeper current_second: ', current_second
        #    #time.sleep(0.02)
        
        session_info_coll = db[proto_opts['session_info_coll_name']]
        session_bytes_coll = db[proto_opts['session_bytes_coll_name']]
        capture_info_coll = db[proto_opts['capture_info_coll_name']]
        capture_bytes_coll = db[proto_opts['capture_bytes_coll_name']]

        while sessions_alloc_pipe.poll():
            # Read data from the pipe into a ctype, which is pointed to by
            # cython.  No type cohersion or translation required.
            # SIDE EFFECT: population of current_session_slot
            sessions_alloc_pipe.recv_bytes_into(py_current_slot)
            keeper_session_count.value += 1

            # Since sessions_shared is now generic, we need to do memory addresses ourselves.
            session = <GenericSession *>(sessions_address + (session_slot_p[0] * session_struct_size))

            # This is this session's first check-in.  We need to schedule the
            # first check-up.

            # The schedule structure is BYTES_RING_SIZE (30) rows; one row per second  
            # The rows are # numbered time mod 30 seconds.  Add 20 to schedule for future
            # Bytes time series doc has max BYTES_DOC_SIZE (20) data items
            session_start_second = <uint64_t>session.tb
            schedule_number = (session_start_second + BYTES_DOC_SIZE) % BYTES_RING_SIZE
            
            #print "Scheduling",session_slot_p[0],"in",schedule_number,",",schedule_sizes[schedule_number], "( tb is ", int(session.tb),")"
            # schedule_number = row in the schedule
            # schedule_sizes[schedule_number] = first empty slot in the row
            schedule[schedule_number][schedule_sizes[schedule_number]] = session_slot_p[0]
            schedule_sizes[schedule_number] += 1

            session_count += 1

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

            # Upcoming session writes will write up to but not into
            # second_to_write, so we clear that out.
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
                # Since sessions_shared is now generic, we need to do memory addresses ourselves.
                session = <GenericSession *>(sessions_address + (slot * session_struct_size))
                lock = session_locks[slot % 100]   # orig %1000
                lock.acquire()
                # Get the data we need as quickly as possible so we can
                # release the lock.
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
                if (seconds_since_last_bytes) > 300:
                    # We don't set next_scheduled_checkup_time, and deallocate below
                    pass

                elif (seconds_since_last_bytes) > BYTES_DOC_SIZE:
                    # There's nothing to read, reschedule for 20 seconds from now
                    next_scheduled_checkup_time = second_to_write + BYTES_DOC_SIZE

                elif session.traffic_bytes[bytes_cursor][0] > 0 or session.traffic_bytes[bytes_cursor][1] > 0:
                    # Write to database (or at least queue)
                    write_session(info_bulk_writer, bytes_bulk_writer, session_info_coll, object_ids, session_copy, slot, second_to_write_from, second_to_write, capture_session)
                    
                    mongo_session_writes += 2
                    next_scheduled_checkup_time = second_to_write + BYTES_DOC_SIZE

                    ## Connection-Tracking Debug ##
                    #if slot in tracked_slots:
                    #    print second_to_write,": Writing slot",slot

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
                    # Write to updateDict about a newly freed slot.  On this
                    # end, all we have to do is free up the objectid slot and
                    # update the capture packets counter with all the packets
                    # from this session.
                    capture_session.packets += session.packets
                    object_ids[slot] = None

                    # We're still linking to a python struct to get raw bytes
                    # into a python Pipe.
                    session_slot_p[0] = slot  # Linked to py_current_slot!
                    sessions_dealloc_pipe.send_bytes(py_current_slot)
                    keeper_dealloc_session_count.value += 1

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

                write_session(info_bulk_writer, bytes_bulk_writer, capture_info_coll, capture_object_ids, capture_session, 0, capture_scheduled_checkup_time - BYTES_DOC_SIZE - (BYTES_DOC_SIZE / 2), capture_scheduled_checkup_time - BYTES_DOC_SIZE, dummy_session)

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


                
cdef bint main_running = True
def main():
    # The main function is responsible for setting up and kicking off the parse
    # function and the ingest function.  It tries to be responsible for all
    # interupts, fatal errors, and cleanup.

    #TODO: Options processing should probably go here, as well as interrupt code.
    options = parseOptions()     # Could combine this line with next line
    trafcap.options = options
    running = True

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
        proto_opts['packet_header_class_name'] = 'PythonTCPPacketHeaders'
        proto_opts['session_class_name'] = 'PythonTCPSession'
        proto_opts['session_info_coll_name'] = 'tcp_sessionInfo'
        proto_opts['session_bytes_coll_name'] = 'tcp_sessionBytes'
        proto_opts['capture_info_coll_name'] = 'tcp_captureInfo'
        proto_opts['capture_bytes_coll_name'] = 'tcp_captureBytes'

    elif options.udp:
        proto_opts['bpf_filter'] = 'ip and udp'
        proto_opts['packet_header_class_name'] = 'PythonUDPPacketHeaders'
        proto_opts['session_class_name'] = 'PythonUDPSession'
        proto_opts['session_info_coll_name'] = 'udp_sessionInfo'
        proto_opts['session_bytes_coll_name'] = 'udp_sessionBytes'
        proto_opts['capture_info_coll_name'] = 'udp_captureInfo'
        proto_opts['capture_bytes_coll_name'] = 'udp_captureBytes'

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

    updater_packet_count = multiprocessing.Value(ctypes.c_uint64)
    updater_packet_count.value = 0
    updater_session_count = multiprocessing.Value(ctypes.c_uint64)
    updater_session_count.value = 0
    updater_dealloc_session_count = multiprocessing.Value(ctypes.c_uint64)
    updater_dealloc_session_count.value = 0
    keeper_session_count = multiprocessing.Value(ctypes.c_uint64)
    keeper_session_count.value = 0
    keeper_dealloc_session_count = multiprocessing.Value(ctypes.c_uint64)
    keeper_dealloc_session_count.value = 0
    ring_stats_recv = multiprocessing.Value(ctypes.c_uint64)
    ring_stats_recv.value = 0
    ring_stats_drop = multiprocessing.Value(ctypes.c_uint64)
    ring_stats_drop.value = 0

    parsed_packet_pipe = multiprocessing.Pipe(False)
    # Try to increase pipe buffer size
    #import fcntl  
    #fd = parsed_packet_pipe[1].fileno() 
    #fl = fcntl.fcntl(fd, fcntl.F_GETFL) 
    #print 'has_attr: ', hasattr(fcntl, 'F_SETPIPE_SZ')  ==> This is False
    #fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK) 

    parsed_packet_buffer = multiprocessing.RawArray(packet_header_class, 100000)
    sessions_buffer = multiprocessing.RawArray(session_class, 1000000)
    sessions_alloc_pipe = multiprocessing.Pipe(False)
    sessions_dealloc_pipe = multiprocessing.Pipe(False)
    #allocated_session_slot_q = multiprocessing.Queue(1000000)
    #deallocated_session_slot_q = multiprocessing.Queue(1000000)
    session_locks = tuple((multiprocessing.Lock() for i in xrange(10000)))

    parser = multiprocessing.Process(target = parsePkts, 
        args=(parsed_packet_pipe[1], parser_packet_count, 
              parsed_packet_buffer, 
              ring_stats_recv, ring_stats_drop, proto_opts, options))
    updater = multiprocessing.Process(target = updateDict, 
        args=(parsed_packet_pipe[0], updater_packet_count, 
              parsed_packet_buffer, sessions_buffer, session_locks, 
              sessions_alloc_pipe[1],  sessions_dealloc_pipe[0], 
              updater_session_count, updater_dealloc_session_count, options))
    keeper = multiprocessing.Process(target = bookkeeper,
        args=(sessions_buffer, session_locks, 
              sessions_alloc_pipe[0], sessions_dealloc_pipe[1], 
              keeper_session_count, keeper_dealloc_session_count, proto_opts, options))

    parser.start()
    updater.start()
    keeper.start()

    prev_packet_count = 0
    prev_session_count = 0
    loop_count = 0
    while main_running:
        time.sleep(1)
        #rsr = ring_stats_recv.value
        rsd = ring_stats_drop.value

        ppc = parser_packet_count.value
        pps = ppc - prev_packet_count
        upc = updater_packet_count.value
        ppq = ppc - upc  # parser-to-updater q length
        
        usc = updater_session_count.value
        sps = usc - prev_session_count
        ksc = keeper_session_count.value
        saq = usc - ksc  # allocate (updater-to-keeper) q length

        udc = updater_dealloc_session_count.value
        kdc = keeper_dealloc_session_count.value
        sdq = kdc - udc # deallocate (keeper-to-updater) q length
        klc = ksc - kdc # live session count

        prev_packet_count = ppc
        prev_session_count = usc

        print '{0:9d} {1:6d} > {2:3d} > {3:10d} {4:7d} > {5:4d}  {6:4d} < {7:8d} {8:7d}'.format(rsd, pps, ppq, upc, sps, saq, sdq, ksc, klc)

        if loop_count % 10 == 0:
            print '{0:>10}{1:>5}{2:>21}{3:>5}{4:>5}{5:^10}{6:>11}{7:>5}{8:>3}'.format('---parser:', parser.pid, '--     -----updater:', updater.pid, '---- ',loop_count,' ---keeper:',keeper.pid,'---')
            print '{0:>9} {1:>6}    {2:^3}  {3:>10} {4:>7}    {5:^4}   {6:^4} {7:>8} {8:>7}'.format('drop', 'pps', ' ', 'pkts', 'sps', ' ',' ', 'sess', 'live')
            global main_running
            #if pps == 0: main_running = False
        loop_count += 1
        sys.stdout.flush()

    # Handle shutdown -- send signals?
    parser.join(1)
    updater.join(1)
    keeper.join(1)
    
    if parser.is_alive(): parser.terminate()
    if updater.is_alive(): updater.terminate()
    if keeper.is_alive(): keeper.terminate()


if __name__ == "__main__":
    main()
