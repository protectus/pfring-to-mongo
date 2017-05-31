from libc.stdint cimport uint64_t,uint32_t,uint16_t,int16_t, uint8_t
from cpython.ref cimport PyObject
from cpf_ring cimport *

# For a compiled constant, we can apparently use enum.
# http://docs.cython.org/src/userguide/language_basics.html#c-variable-and-type-definitions
cdef enum:
    BYTES_RING_SIZE = 30
    BYTES_DOC_SIZE = 20

    # Buffer sizes moved to trafcap.conf - allows Sentry
    # config tuning for smaller memory footprint
    # 
    # Size of ring_buffers for packets and saved_sessions
    #PACKET_RING_BUFFER_SIZE = 100000 
    #SAVED_SESSION_RING_BUFFER_SIZE = 10000 
    #LIVE_SESSION_BUFFER_SIZE = 1000000 
    # Group buffer slot can be occupied for up to 3 hours (length of groups2).
    #GROUP_BUFFER_SIZE = 500000 
    #GROUP2_BUFFER_SIZE = 2000000 

    SESSIONS_PER_LOCK = 100    # originally 1000
    GROUPS_PER_LOCK = 100 
    
    CAPTURE_GROUP_BUFFER_SIZE = 10 
    CAPTURE_GROUPS_PER_LOCK = 1

    # Groups equivalent of  BYTES_RING_SIZE and BYTES_DOC_SIZE 
    GROUP_SCHEDULE_SIZE = 40 
    GROUP_SCHEDULE_PERIOD = 30 

# Heads up: These structs are defined twice so that both pure python and
# lower-level cython can know about them.  Useful for shared memory stuff.
cdef struct GenericPacketHeaders:
    double timestamp

cdef struct TCPPacketHeaders:
    GenericPacketHeaders base

    uint32_t ip1
    uint16_t port1

    uint32_t ip2
    uint16_t port2

    int16_t vlan_id

    uint64_t bytes
    uint16_t flags

cdef struct UDPPacketHeaders:
    GenericPacketHeaders base

    uint32_t ip1
    uint16_t port1

    uint32_t ip2
    uint16_t port2

    int16_t vlan_id

    uint64_t bytes


cdef struct GenericSession:
    double tb
    double te

    uint64_t packets
    uint32_t[BYTES_RING_SIZE][2] traffic_bytes

cdef struct TCPSession:
    GenericSession base

    uint32_t ip1
    uint16_t port1
    uint64_t bytes1
    uint64_t pkts1
    uint16_t flags1
    char[2] cc1
    uint32_t asn1

    uint32_t ip2
    uint16_t port2
    uint64_t bytes2
    uint64_t pkts2
    uint16_t flags2
    char[2] cc2
    uint32_t asn2

    int16_t vlan_id

cdef struct UDPSession:
    GenericSession base

    uint32_t ip1
    uint16_t port1
    uint64_t bytes1
    uint64_t pkts1
    char[2] cc1
    uint32_t asn1

    uint32_t ip2
    uint16_t port2
    uint64_t bytes2
    uint64_t pkts2
    char[2] cc2
    uint32_t asn2

    int16_t vlan_id

cdef struct GenericGroup:
    uint64_t tbm
    uint64_t tem
    uint32_t[90][2] traffic_bytes 
    uint32_t ns 
    uint32_t ne 
    # Change_Since_Last_Database_Write flag, 1=yes, 0=no
    uint8_t csldw 

cdef struct TCPGroup:
    GenericGroup base

    uint32_t ip1
    uint64_t bytes1
    char[2] cc1
    uint32_t asn1

    uint32_t ip2
    uint16_t port2
    uint64_t bytes2
    char[2] cc2
    uint32_t asn2

    int16_t vlan_id

cdef struct UDPGroup:
    GenericGroup base

    uint32_t ip1
    uint64_t bytes1
    char[2] cc1
    uint32_t asn1

    uint32_t ip2
    uint16_t port2
    uint64_t bytes2
    char[2] cc2
    uint32_t asn2

    int16_t vlan_id


ctypedef int (*parse_packet)(GenericPacketHeaders*, pfring_pkthdr*) except -1
cdef int parse_tcp_packet(GenericPacketHeaders* pkt, pfring_pkthdr* hdr) except -1
cdef int parse_udp_packet(GenericPacketHeaders* pkt, pfring_pkthdr* hdr) except -1

ctypedef object (*generate_session_key_from_pkt)(GenericPacketHeaders*)
cdef object generate_tcp_session_key_from_pkt(GenericPacketHeaders* pkt)
cdef object generate_udp_session_key_from_pkt(GenericPacketHeaders* pkt)

ctypedef object (*generate_session_key_from_session)(GenericSession* session)
cdef object generate_tcp_session_key_from_session(GenericSession* session)
cdef object generate_udp_session_key_from_session(GenericSession* session)

ctypedef object (*generate_group_key_from_session)(GenericSession* session, uint8_t)
cdef object generate_tcp_group_key_from_session(GenericSession* session, uint8_t group_type)
cdef object generate_udp_group_key_from_session(GenericSession* session, uint8_t group_type)

ctypedef object (*generate_group_key_from_group)(GenericGroup* group)
cdef object generate_tcp_group_key_from_group(GenericGroup* group)
cdef object generate_udp_group_key_from_group(GenericGroup* group)

cdef int print_tcp_packet(GenericPacketHeaders* packet) except -1
cdef int print_tcp_session(GenericSession* session, uint64_t time_cursor) except -1
cdef int print_tcp_group(GenericGroup* session, uint64_t time_cursor, uint8_t group_type) except -1

ctypedef GenericSession* (*alloc_capture_session)()
cdef GenericSession* alloc_tcp_capture_session()
cdef GenericSession* alloc_udp_capture_session()

ctypedef int (*generate_session)(GenericSession*, GenericPacketHeaders*)
cdef int generate_tcp_session(GenericSession* session, GenericPacketHeaders* packet)
cdef int generate_udp_session(GenericSession* session, GenericPacketHeaders* packet)

ctypedef int (*update_session)(GenericSession*, GenericPacketHeaders*)
cdef int update_tcp_session(GenericSession* session, GenericPacketHeaders* packet)
cdef int update_udp_session(GenericSession* session, GenericPacketHeaders* packet)

ctypedef int (*write_session)(object, object, object, list, GenericSession*, int, uint64_t, uint64_t, GenericSession*, GenericSession*, object, int) except -1
cdef int write_tcp_session(object info_bulk_writer, object bytes_bulk_writer, object info_collection, list object_ids, GenericSession* session, int slot, uint64_t second_to_write_from, uint64_t second_to_write_to, GenericSession* capture_session, GenericSession* live_session, object live_session_locks, int live_session_locks_len) except -1
cdef int write_udp_session(object info_bulk_writer, object bytes_bulk_writer, object info_collection, list object_ids, GenericSession* session, int slot, uint64_t second_to_write_from, uint64_t second_to_write_to, GenericSession* capture_session, GenericSession* live_session, object live_session_locks, int live_session_locks_len) except -1

#ctypedef GenericGroup* (*alloc_capture_group)()
#cdef GenericGroup* alloc_tcp_capture_group()
#cdef GenericGroup* alloc_udp_capture_group()

ctypedef int (*init_capture_group)(GenericGroup*, uint8_t, uint64_t)
cdef int init_tcp_capture_group(GenericGroup* group, uint8_t group_type, uint64_t session_tb)
cdef int init_udp_capture_group(GenericGroup* group, uint8_t group_type, uint64_t session_tb)

ctypedef int (*write_group)(object, object, list, GenericGroup*, int, uint8_t) except -1
cdef int write_tcp_group(object group_bulk_writer, object group_collection, list object_ids, GenericGroup* group, int slot, uint8_t group_type) except -1
cdef int write_udp_group(object group_bulk_writer, object group_collection, list object_ids, GenericGroup* group, int slot, uint8_t group_type) except -1

ctypedef int (*generate_group)(GenericGroup*, GenericSession*, GenericGroup*, int)
cdef int generate_tcp_group(GenericGroup* group, GenericSession* session, GenericGroup* c_group, uint8_t group_type)
cdef int generate_udp_group(GenericGroup* group, GenericSession* session, GenericGroup* c_group, uint8_t group_type) 

ctypedef int (*update_group)(GenericGroup*, GenericSession*, GenericGroup*, int)
cdef int update_tcp_group(GenericGroup* group, GenericSession* session, GenericGroup* c_group, uint8_t group_type)
cdef int update_udp_group(GenericGroup* group, GenericSession* session, GenericGroup* c_group, uint8_t group_type) 

cdef inline uint64_t peg_to_15minute(uint64_t timestamp)
cdef inline uint64_t peg_to_180minute(uint64_t timestamp)

cdef int update_group_counts(object session_key, object session_history, uint8_t set_tbm, GenericGroup* group, object counter) except -1
