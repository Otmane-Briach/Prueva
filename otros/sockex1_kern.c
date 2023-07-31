#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_legacy.h>


struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, long);
	__uint(max_entries, 1);
} my_map SEC(".maps");

SEC("socket1")
int bpf_prog1(struct __sk_buff *skb)
{

 bpf_printk("hola");
	return TC_ACT_OK;
}
char _license[] SEC("license") = "GPL";
