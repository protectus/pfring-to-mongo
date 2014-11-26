from libc.stdint cimport uint64_t,uint32_t,uint16_t,int16_t

# Heads up: These structs are defined twice so that both pure python and
# lower-level cython can know about them.  Useful for shared memory stuff.
cdef struct TCPPacketHeaders:
    uint32_t timestamp
    int16_t vlan_id

    uint32_t ip1
    uint16_t port1

    uint32_t ip2
    uint16_t port2

    uint64_t bytes
    uint16_t flags

cdef int parseTCPPacket(TCPPacketHeaders* pkt_struct, pkt, doc) except -1

