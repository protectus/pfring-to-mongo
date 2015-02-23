from libc.stdint cimport uint64_t,uint32_t,uint16_t,int16_t, uint8_t
from cpython.ref cimport PyObject
from cpf_ring cimport *

# For a compiled constant, we can apparently use enum.
# http://docs.cython.org/src/userguide/language_basics.html#c-variable-and-type-definitions
cdef enum:
    BYTES_RING_SIZE = 30
    BYTES_DOC_SIZE = 20
    

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
    uint16_t flags1
    char[2] cc1

    uint32_t ip2
    uint16_t port2
    uint64_t bytes2
    uint16_t flags2
    char[2] cc2

    int16_t vlan_id

cdef struct UDPSession:
    GenericSession base

    uint32_t ip1
    uint16_t port1
    uint64_t bytes1
    char[2] cc1

    uint32_t ip2
    uint16_t port2
    uint64_t bytes2
    char[2] cc2

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

cdef int print_tcp_packet(GenericPacketHeaders* packet) except -1

cdef int print_tcp_session(GenericSession* session, uint64_t time_cursor) except -1

ctypedef GenericSession* (*alloc_capture_session)()
cdef GenericSession* alloc_tcp_capture_session()
cdef GenericSession* alloc_udp_capture_session()

ctypedef int (*generate_session)(GenericSession*, GenericPacketHeaders*)
cdef int generate_tcp_session(GenericSession* session, GenericPacketHeaders* packet)
cdef int generate_udp_session(GenericSession* session, GenericPacketHeaders* packet)

ctypedef int (*update_session)(GenericSession*, GenericPacketHeaders*)
cdef int update_tcp_session(GenericSession* session, GenericPacketHeaders* packet)
cdef int update_udp_session(GenericSession* session, GenericPacketHeaders* packet)

ctypedef int (*write_session)(object, object, object, list, GenericSession*, int, uint64_t, uint64_t, GenericSession*) except -1
cdef int write_tcp_session(object info_bulk_writer, object bytes_bulk_writer, object info_collection, list object_ids, GenericSession* session, int slot, uint64_t second_to_write_from, uint64_t second_to_write_to, GenericSession* capture_session) except -1
cdef int write_udp_session(object info_bulk_writer, object bytes_bulk_writer, object info_collection, list object_ids, GenericSession* session, int slot, uint64_t second_to_write_from, uint64_t second_to_write_to, GenericSession* capture_session) except -1

