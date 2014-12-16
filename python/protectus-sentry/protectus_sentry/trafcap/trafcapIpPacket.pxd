from libc.stdint cimport uint64_t,uint32_t,uint16_t,int16_t
from cpython.ref cimport PyObject

# For a compiled constant, we can apparently use enum.
# http://docs.cython.org/src/userguide/language_basics.html#c-variable-and-type-definitions
cdef enum:
    BYTES_RING_SIZE = 30
    BYTES_DOC_SIZE = 20
    

# Heads up: These structs are defined twice so that both pure python and
# lower-level cython can know about them.  Useful for shared memory stuff.
cdef struct TCPPacketHeaders:
    uint32_t ip1
    uint16_t port1

    uint32_t ip2
    uint16_t port2

    int16_t vlan_id
    double timestamp

    uint64_t bytes
    uint16_t flags

cdef struct TCPSession:
    uint32_t ip1
    uint16_t port1
    uint64_t bytes1
    uint16_t flags1

    uint32_t ip2
    uint16_t port2
    uint64_t bytes2
    uint16_t flags2

    int16_t vlan_id
    double tb
    double te
    uint64_t packets

    uint32_t[BYTES_RING_SIZE][2] traffic_bytes

cdef int parse_tcp_packet(TCPPacketHeaders* pkt_struct, pkt, doc) except -1

cdef object generate_tcp_session_key_from_pkt(TCPPacketHeaders* pkt)

cdef object generate_tcp_session_key_from_session(TCPSession* session)

cdef int print_tcp_session(TCPSession* session, uint64_t time_cursor) except -1

cdef int init_tcp_capture_session(TCPSession* session)

cdef int generate_tcp_session(TCPSession* session, TCPPacketHeaders* packet)

cdef int update_tcp_session(TCPSession* session, TCPPacketHeaders* packet)

cdef int write_tcp_session(object info_bulk_writer, object bytes_bulk_writer, object info_collection, list object_ids, TCPSession* session, int slot, uint64_t second_to_write_from, uint64_t second_to_write_to, TCPSession* capture_session) except -1

