// SPDX-License-Identifier: GPL-2.0
#include <linux/if_packet.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/if.h>


struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, long);
	__uint(max_entries, 256);
} my_map SEC(".maps");

SEC("tc")
int bpf_prog1(struct __sk_buff *skb)
{
	  struct ethhdr eth_header;
    struct iphdr ip_header;
    bpf_skb_load_bytes(skb, 0, &eth_header, sizeof(eth_header));
    if (eth_header.h_proto != bpf_htons(ETH_P_IP))
        return 0;

    bpf_skb_load_bytes(skb, sizeof(eth_header), &ip_header, sizeof(ip_header));
    int index = ip_header.protocol;

    long *value;
	if (skb->pkt_type != PACKET_OUTGOING)
		return 0;

	value = bpf_map_lookup_elem(&my_map, &index);
	if (value)
		__atomic_add_fetch(value, skb->len, __ATOMIC_RELAXED);

	return 0;
}
char _license[] SEC("license") = "GPL";
