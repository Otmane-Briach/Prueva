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
#include <stdio.h>

#define NANOS_PER_MS 1000000LL //un millon de nanosegundos en un ms
#define MAX_LONG_LONG 9223372036854775803LL
#define MAX_WINDOW 65535

// should be the same as for the module rewriting outgoing packets,
// kernel/xt_TWIN.c
#define mss 1448 //unidad de ventana
// this is the minimum value (bytes) the window may have in any reduction
// (either periodic or delay-triggered)
// 2* mss
#define MIN_REDUCTION_BYTES 2896
// will be set to MIN_REDUCTION_BYTES / window_scale:
static __u16 minimum_window = 0;


#define INIT_WINDOW 1*mss  //ventana inicial

// Remote port of connections for which rledbat is applied
// Only one connection using this port should be started
// I.e., rledbat is applied to connections with remote port 49000
// To change the port, must also modify install_rledbat.sh
#define RLEDBAT_WATCH_PORT 49000

// rledbat target
#define TARGET 60LL*NANOS_PER_MS //60ms
// Data specific for RLEDBAT2
#ifdef RLEDBAT2
// replaces TARGET in some computations
static long long target2 = 0;
#endif // RLEDBAT2

// mus be changed also in xt_TWIN.c, if needed
#define MAX_COUNT_RTT 10000

//gain is defined as 1/min(gain_constant,ceil((2*target)/base))               -0
#define GAIN_CONSTANT 16
// Constant for multiplicative decrease computation
#define CONSTANT_MULTIPLIER 1
#define CONSTANT_DIVIDER 1

// Variables that must keep state between the executions of hook function
// (activated per packet)

// To hook module ?????????????????????????????????
//static struct nf_hook_ops nfho;


// effective reception window
static unsigned long long rcwnd_ok = INIT_WINDOW;
// Can be used for debug. The write module imports it but doesn't use it
static unsigned long long rcwnd_ok_before = INIT_WINDOW;
static long last_seq = 0;
// rcwnd_ok, rcwnd_ok_before and last_seq are exported to the write module

static long tsval_rtt = 0;

// xt_TWIN (processing outgoing packets) module uses it, need to update the write module first
static unsigned int flag_dup_ack = 0;


//values needed to compute the queueing delay
static long long queue_delay = 0;
static long long rtt = MAX_LONG_LONG;
static long long rtt_min = MAX_LONG_LONG;


// to know if we are reducing the window
static int reduction = 0;

// _time values are ns
// time to maintain the window
static long long keep_window_time = 0;

// periodic reduction
static unsigned long long periodic_reduction_time=0;
static unsigned long long begin_periodic_reduction_time=0;
static unsigned long long end_periodic_reduction_time=0;

// do not decrease until this time
static unsigned long long next_decrease_time=0;

// to allow computing RTT information
static long tsval_rtt_array[MAX_COUNT_RTT];
static long time_rtt_array[MAX_COUNT_RTT];
// ts_val_array and time_rtt_array are exported to the write module

static long tsval_rtt_old = 0;

//sequence number of the previous packet, to detect retransmissions
static long last_seq_old=0;
static int is_retransmission=0;

static long tsecr = 0;   //que es?
static long tsecr_already_checked = 0;
//holaaaaaaaaaaaaaaaaa aqui aqui aqui 
// number bytes acked
static unsigned int acked = 0;
// number of bytes the window must be reduced
static signed long long rcwnd_scale = 0;

static unsigned long to_increase_CA;

//slow start threshold
static unsigned long long ssthresh=MAX_WINDOW;

// first slow start is different, we need to control that case
static int is_first_ss=1;
// to disable temporarily slow start
static int is_ss_allowed=1;
// to know if we have to freeze the window after a periodic reduction
static int freeze_ended=1;
// indicates if a retransmission occurred close to this time (only react with the first)
static int recent_retransmission=0;

//used to know if periodic_reduction_time is from the previous or the next one
static int periodic_reduction_scheduled=0;

// últimos valores de retardo de cola para calcular el mínimo
#define LAST_QDS 10
// almacena hasta los últimos 20 valores de qds, se puede cambiar fácilmente con LAST_QDS
static long long last_qd_values[20] = {MAX_LONG_LONG, MAX_LONG_LONG, MAX_LONG_LONG, MAX_LONG_LONG, MAX_LONG_LONG, MAX_LONG_LONG, MAX_LONG_LONG, MAX_LONG_LONG,
MAX_LONG_LONG, MAX_LONG_LONG, MAX_LONG_LONG, MAX_LONG_LONG, MAX_LONG_LONG, MAX_LONG_LONG, MAX_LONG_LONG, MAX_LONG_LONG,
MAX_LONG_LONG, MAX_LONG_LONG, MAX_LONG_LONG, MAX_LONG_LONG
};
// current pointer to last_qd_values
struct bpf_map_def SEC("maps") qd_values_pointer = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 1,
};



// acceso al número de bytes disponibles para el buffer del receptor (TCP)
extern int sysctl_tcp_rmem[3];
extern __u32 sysctl_rmem_max;

//scaling factor (exponent)
static __u16 rcv_wscale=0;
//scaling factor (bytes)
static int window_scale=1;
static int increase_bytes=0;

//number of packet
static int packet_number=0;

static char state[15] = "undef";
// initialize, must be overwritten with first packet
// other values for state (describing the effect after processing the received packet)
//
// "slow" - window was grown according to slow start
// "slow1_end" - slow start for the first time reached 3/4 of the TARGET (60ms)
//          so this packet made slow start finishing; go to Congestion Avoidance mode.
// "slow1_fix" - slow start for the first time reached ssthresh (normal condition for ss
//          to stop), but not 3/4 of the TARGET. This packet made slow start finishing,
//          go to Congestion Avoidance mode
//
// "CA" - window grew according to congestion avoidance mode
// "decrease" - this packet exceeded the delay condition, compute window to reduce in next
//          packets
// "decr2big" - as decrease, but the amount to reduce is too high (more than half window)
// "declessWS" - as decrease, but the amount to reduce is too small, less than the size of 1
//          window unit. Anyway, decrease one window unit
// "min_window" - as decrease, but the amount to reduce would result in a final window of
//          less than min window, so cap the value to min_window
// "growb4red" - as decrease, but the result of the window formula is to grow, not decrease.
//          This may happen for small differences between queuing delay and target
//
// "reducing" - previous packets resulting in a window reduction request, window is reduced
//          with the acked data for this packet
// "waitrtt2dec" - this packet is received when a reduction operation has completed. However,
//          we want to wait an RTT until the queuing delay is computed either to grow or decrease
//          further
//
// "retrans" - this packet was a retransmission, reduce window to half, activate slow start
//          for later grow
//
// "perio_red" - when processing this packet, we realize its time for a periodic_reduction
// "perio_red+retr" - a retransmission was detected when also scheduling a periodic reduction.
// "freezing" - the reduction of a periodic slowdown has just finished with this packet.
//          Ensure that no window update occur in the next 2*RTT period
// "frozen" - waiting for the 2*RTT period after a periodic slowdown to complete.
// "freezing+retrans" - as freezing, but the packet was a retrans, updated slow start threshold
//          for next slow start
// "frozen+retrans" - as frozen, but the packet was a retrans, updated slow start threshold
//          for next slow start

// Recibe el último retraso de cola (qd) medido.
// Almacena el último qd medido para su uso futuro
// Devuelve el mínimo de los últimos valores de LAST_QDS (incluyendo last_qd (el que acabo de recibir)) y last_qd




  struct eth_hdr {
  	unsigned char   h_dest[ETH_ALEN];
  	unsigned char   h_source[ETH_ALEN];
  	unsigned short  h_proto;
  };


  /*
  le llega el ultimo retraso de cola medido, lo guarda
  en la matriz de los ultimos 20 y calcula cual es el minimo.
  y eso es lo que devuelve.
  */



  static inline long long qd_min_lastN(long long last_qd)
  {
      int i;
      long long qd_min;
      if (LAST_QDS == 1)
      {
          return last_qd;
      }
      //lo de que la posicion sea el resto, es para que la suma qd_vueles_pointer++ sea
      //modulo LAST_QDS.

  __u32 key = 0;
  __u32 *value;

  value = bpf_map_lookup_elem(&qd_values_pointer, &key);
/*
  if (value != NULL) {
      last_qd_values[*value % LAST_QDS] = last_qd;
      __u32 new_value = *value + 1;
      bpf_map_update_elem(&qd_values_pointer, &key, &new_value, BPF_ANY);
  } else {
      // Trata el caso en el que value es NULL si es necesario
  }
    qd_min = last_qd_values[0];
      for (i = 1; i < LAST_QDS; i++) //LAST_QDS
      {
          //calcula el minimo y lo guarda en qd_min.
          if (last_qd_values[i] < qd_min)

          {
              qd_min = last_qd_values[i];
          }
      }*/
      return qd_min;
  }


SEC("classifier1")
int tc_drop(struct __sk_buff *skb) {

  void *data = (void *)(long)skb->data;
  struct eth_hdr *eth = data;
  struct iphdr *iph = data + sizeof(*eth);
  struct ipv6hdr *ip6h = data + sizeof(*eth);
  struct tcphdr *tcp = data + sizeof(*eth) + sizeof(*iph);
  void *data_end = (void *)(long)skb->data_end;


  if (data + sizeof(*eth) + sizeof(*iph) + sizeof(*tcp) > data_end){
    return 0;
  }
  if (data + sizeof(*eth) + sizeof(*ip6h) + sizeof(*tcp) > data_end){
    return 0;
  }

  if (eth->h_proto == bpf_htons(ETH_P_IP))
{

  if (tcp->dest==bpf_ntohs(2000)) {
    bpf_printk("Puerto destino ENTRADA: %d\n", bpf_ntohs(tcp->dest));
    tcp->dest = bpf_htons(bpf_ntohs(tcp->dest) - 1);
    bpf_printk("Puerto destino restado ENTRADA: %d\n", bpf_ntohs(tcp->dest));
  }

}else if(eth->h_proto == bpf_htons(ETH_P_IPV6)){

  struct tcphdr *tcp6 = data + sizeof(*eth) + sizeof(*ip6h);
  if (data + sizeof(*eth) + sizeof(*ip6h) + sizeof(*tcp6) > data_end)
    return 0;
    if (tcp->dest==bpf_ntohs(2000)) {
      bpf_printk("Puerto destino ENTRADA: %d\n", bpf_ntohs(tcp->dest));
      tcp->dest = bpf_htons(bpf_ntohs(tcp->dest) - 1);
      bpf_printk("Puerto destino restado ENTRADA: %d\n", bpf_ntohs(tcp->dest));
    }
}

return TC_ACT_OK;
}
SEC("test")
int tc_drop2(struct __sk_buff *skb) {

int i;
int count=20;
 for (i = 0; i < count; i++) {
   last_qd_values[i]=bpf_get_prandom_u32();
 }
 for (i = 0; i < count; i++) {
   bpf_printk("last_qd_values[%d]: %u", i, last_qd_values[i]);
 }
  //long long dev=last_qd_values[i];
  //bpf_printk("last_qd_values[%d]: %lld", i, last_qd_values[i]);
  long long dev=qd_min_lastN(55551515515);
  bpf_printk("last_qd_values[%d]: %llu", dev);
return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
