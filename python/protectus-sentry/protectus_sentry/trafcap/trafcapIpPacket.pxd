from libc.stdint cimport uint64_t,uint32_t,uint16_t,int16_t
from cpython.ref cimport PyObject

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

    uint32_t[30][2] traffic_bytes

cdef int parse_tcp_packet(TCPPacketHeaders* pkt_struct, pkt, doc) except -1

cdef object generate_tcp_session_key_from_pkt(TCPPacketHeaders* pkt)

cdef int print_tcp_session(TCPSession* session) except -1

cdef int generate_tcp_session(TCPSession* session, TCPPacketHeaders* packet)

cdef int update_tcp_session(TCPSession* session, TCPPacketHeaders* packet)

