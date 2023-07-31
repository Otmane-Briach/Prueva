/* SPDX-License-Identifier: GPL-2.0 */
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



//---------------------------------DEFINES------------------------------------//
// últimos valores de retardo de cola para calcular el mínimo
#define LAST_QDS 10
#define MAX_LONG_LONG 9223372036854775803LL
//----------------------------VVARIABLES GLOBALES-----------------------------//
// almacena hasta los últimos 20 valores de qds, se puede cambiar fácilmente con LAST_QDS
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, long long);
	__uint(max_entries, 20);
} last_qd_values_map SEC(".maps");
// current pointer to last_qd_values
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, long long);
	__uint(max_entries, 1);
} qd_values_pointer_map SEC(".maps");

static int t=0;
  struct eth_hdr {
  	unsigned char   h_dest[ETH_ALEN];
  	unsigned char   h_source[ETH_ALEN];
  	unsigned short  h_proto;
  };

//--------------------------FUNCIONES-----------------------------------------//

static inline void prueva(int i){
  int b=i;
  bpf_printk("Valor de a: %d\n", b);
  t=t+1;
  bpf_printk("Valor de t: %d\n", t);
}

  /*
  le llega el ultimo retraso de cola medido, lo guarda
  en la matriz de los ultimos 20 y calcula cual es el minimo.
  y eso es lo que devuelve.
  */



//---------------------------------TESTEO-------------------------------------//
SEC("tc")
int tc_drop1(struct __sk_buff *skb) {
    __u32 key = 0;
    long long *value;
    long long new_value;

    // Print and update last_qd_values_map
    value = bpf_map_lookup_elem(&last_qd_values_map, &key);
    if (value) {
        bpf_printk("last_qd_values_map[0]: %lld\n", *value);
        new_value = *value + 1;
        bpf_map_update_elem(&last_qd_values_map, &key, &new_value, BPF_ANY);
    }

    // Print and update qd_values_pointer_map
    value = bpf_map_lookup_elem(&qd_values_pointer_map, &key);
    if (value) {
        bpf_printk("qd_values_pointer_map[0]: %lld\n", *value);
        new_value = *value + 1;
        bpf_map_update_elem(&qd_values_pointer_map, &key, &new_value, BPF_ANY);
    }

    return TC_ACT_OK;
}
//---------------------Conc-----------------//
char _license[] SEC("license") = "GPL";
int _version SEC("version") = 1;
