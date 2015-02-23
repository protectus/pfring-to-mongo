from libc.stdint cimport uint64_t,uint32_t,uint16_t,uint8_t,int16_t
from posix.time cimport timeval
from cpython.ref cimport PyObject

cdef extern from "linux/pf_ring.h":
    cdef union ip_addr:
        uint32_t v4

    cdef struct tcp_struct:
        uint8_t flags
        uint32_t seq_num
        uint32_t ack_num
 
    cdef struct pkt_parsing_info:
        uint8_t dmac[6]
        uint8_t smac[6]
        uint16_t eth_type
        uint16_t vlan_id
        uint8_t ip_version
        uint8_t l3_proto
        uint8_t ip_tos
        ip_addr ip_src
        ip_addr ip_dst
        uint16_t l4_src_port
        uint16_t l4_dst_port
        tcp_struct tcp

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
        uint16_t parsed_header_len
        pkt_parsing_info parsed_pkt

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

