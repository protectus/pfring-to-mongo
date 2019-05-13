from libc.stdint cimport uint64_t,uint32_t,uint16_t,uint8_t,int16_t
from posix.time cimport timeval
from cpython.ref cimport PyObject

cdef extern from "linux/in6.h":
    cdef union in6_u:
        uint8_t u6_addr8[16]
        uint16_t u6_addr16[8]
        uint32_t u6_addr32[4]

    # May not need this - try without
    cdef struct in6_addr:
        in6_u in6_union

cdef extern from "linux/pf_ring.h":
    struct pkt_offset:
        int16_t eth_offset
        int16_t vlan_offset
        int16_t l3_offset
        int16_t l4_offset
        int16_t payload_offset
 
    cdef union ip_addr:
        in6_addr v6
        uint32_t v4

    cdef struct tcp_struct:
        uint8_t flags
        uint32_t seq_num
        uint32_t ack_num

    cdef struct tunnel_info:
        uint32_t tunnel_id
        uint8_t tunneled_ip_version
        uint8_t tunneled_proto
        ip_addr tunneled_ip_src
        ip_addr tunneled_ip_dst
        uint16_t tunneled_l4_src_port
        uint16_t tunneled_l4_dst_port

    cdef struct pkt_parsing_info:
        uint8_t dmac[6]
        uint8_t smac[6]
        uint16_t eth_type
        uint16_t vlan_id
        uint16_t qinq_vlan_id
        uint8_t ip_version
        uint8_t l3_proto
        uint8_t ip_tos
        ip_addr ip_src
        ip_addr ip_dst
        uint16_t l4_src_port
        uint16_t l4_dst_port
        uint8_t icmp_type
        uint8_t icmp_code
        tcp_struct tcp
        tunnel_info tunnel
        int last_matched_rule_id
        pkt_offset offset

    cdef struct tx_struct:
        int bounce_interface
        void* reserved             # should be sk_buff*

    cdef struct pfring_extended_pkthdr:
        uint64_t timestamp_ns
        uint32_t flags
        uint8_t rx_direction
        uint32_t if_index
        uint32_t pkt_hash
        tx_struct tx
        pkt_parsing_info parsed_pkt

    # Removed from struct above
        #uint16_t parsed_header_len

    cdef struct pfring_pkthdr:
        timeval ts
        uint32_t caplen
        uint32_t c_len "len"
        pfring_extended_pkthdr extended_hdr

#ctypedef void (*pfringProcesssPacket)(const pfring_pkthdr *h, const char *p, const char *user_bytes)

cdef extern from "pfring.h":
    ctypedef struct pfring:
        pass

    ctypedef struct pfring_stat:
        uint64_t recv
        uint64_t drop
        uint64_t shunt 

    pfring* pfring_open(const char *device_name, uint32_t caplen, uint32_t flags)
    int pfring_enable_ring(pfring *ring)
    #int pfring_loop(pfring *ring, pfringProcesssPacket looper,
    #                 char *user_bytes, uint8_t wait_for_packet)
    #void pfring_breakloop(pfring *ring)
    int pfring_recv(pfring *ring, char **a_buffer, int buffer_len, 
                    pfring_pkthdr *hdr, uint8_t wait_for_incoming_packet)
    void pfring_close(pfring *ring)
    int pfring_stats(pfring *ring, pfring_stat *stats)
    int pfring_set_bpf_filter(pfring *ring, char *filter_str)

