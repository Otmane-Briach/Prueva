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
#include <string.h>
#include "stdbool.h"


//---------------------------------DEFINES------------------------------------//
// últimos valores de retardo de cola para calcular el mínimo
#define LAST_QDS 10
#define MAX_LONG_LONG 9223372036854775803LL
//----------------------------VVARIABLES GLOBALES-----------------------------//

//almacena hasta los últimos 20 valores de qds, se puede cambiar fácilmente con LAST_QDS
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, long long);
    __uint(max_entries, 20);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} values_map SEC(".maps");
// current pointer to last_qd_values
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, long long);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} pointer_map SEC(".maps");

struct tcp_ts_option {
    __u32 tsval;
    __u32 tsecr;
};

  struct eth_hdr {
  	unsigned char   h_dest[ETH_ALEN];
  	unsigned char   h_source[ETH_ALEN];
  	unsigned short  h_proto;
  };


//--------------------------FUNCIONES CALLBACK-----------------------------------------//
// bucle para calcular el minimo
static long qd_min_lastN_loop(__u32 i, void *min_value_ptr) {

    long long *value = bpf_map_lookup_elem(&values_map, &i);
    if (!value)
        return 1;  // Si bpf_map_lookup_elem falla, detenemos el bucle

    long long *min_value = min_value_ptr;

    if (*value < *min_value) {
        *min_value = *value;
    }

    return 0;  // Continúa el bucle
}

static inline long print_loop_callback(__u32 key, void *ctx) {
  long long *value;
  value = bpf_map_lookup_elem(&values_map, &key);
  if (value) {
      bpf_printk("last_qd_values_map[%u] = %lld\n", key, *value);
  }
  return 0; // El valor de retorno indica si la función debe continuar (0) o detenerse (1)
}
//---------------------------FUNCIONES---------------------------------------//

/*
le llega el ultimo retraso de cola medido, lo guarda
en la matriz de los ultimos 20 y calcula cual es el minimo.
y eso es lo que devuelve.
*/
static long long qd_min_lastN(long long last_qd) {

    __u32 key_0 = 0;
    __u32 key = 0;
    __u64 *pointer = bpf_map_lookup_elem(&pointer_map, &key_0);
    if (!pointer)
        return -1;

    key = ((*pointer)%LAST_QDS); //Para que el infice sea modulo 10.

    // Actualiza values_map
    if (bpf_map_update_elem(&values_map, &key, &last_qd, BPF_ANY)) {
        bpf_printk("Update values_map failed\n");
    }
    // Actualiza pointer_map
    (*pointer)++;
    if (bpf_map_update_elem(&pointer_map, &key_0, pointer, BPF_ANY)) {
        bpf_printk("Update pointer_map failed\n");
    }

    // Prepara el valor mínimo para bpf_loop
    __u64 *temp = bpf_map_lookup_elem(&values_map, &key_0);
    if (!temp)
      return -1;
    long long min_value = *temp;

    // Ejecuta bpf_loop para actualizar min_value
    long loops = bpf_loop(LAST_QDS, qd_min_lastN_loop, &min_value, 0);
    if (loops < 0) {
        bpf_printk("bpf_loop error: %ld\n", loops);
        return -1;
    }
    return min_value;
}

const int MAX_OPTIONS = 100;

static void get_TSecr(struct tcphdr *tcph, void *data, void *data_end) {
struct tcp_ts_option timestamp = {0, 0};
bool timestamp_encontrado = false;
__u8 size;
__u8 *end;
__u8 *p;

//get the TSecr from the received packet
// debe ir a la dirección en la que está el ts val
//la intencion es que p apunte al inicio de las opciones
//TCP (si las hay), que estarán justo despues de la cabera TCP.
p = (__u8 *)tcph + sizeof(*tcph);
end = (__u8 *)tcph + tcph->doff * 4;

// Me aseguro de que 'p' y 'end' estén dentro del rango de 'data' y 'data_end'

//   || (void *)p < data || (void *)end < data
if ((void *)p >= data_end || (void *)end > data_end) {
    return;
}

for (int i = 0; (i < 11 && p < end); i++) { //-------EN ESTE BUCLE TIENE QUE HABER SI O SI LA CONDICION &&P<END.
    __u8 kind;

    // Me aseguro de que 'p' esté dentro del rango de 'data' y 'data_end'

    //(void *)p < data ||
    if ((void *)p >= data_end) {
        return;
    }

    // Me aseguro de que tenga al menos un byte para leer el "kind"
    if (p + 1 > end || p + 1 > data_end) {
        return;
    }

    kind = *p++; //ya puedo avanzar

    if (kind == 0)
        break;

    if (kind == 1)
        continue;

    // Me aseguro de que tengas al menos un byte para el campo size
    if (p + 1 > end || p + 1 > data_end) {
        return;
    }

    size = *p++; //ya puedo avanzar

    if (size < 2 || p + size > end || p + size > data_end) {
        return;
    }

    if (kind == 8 && size == 10) { // Opción de timestamp
      timestamp_encontrado=true;
        if (p + 8 > end || p + 8 > data_end) { // Comprobar que hay suficientes bytes para TSval y TSecr
            return;
        }

        timestamp.tsval = bpf_ntohl(*(__u32 *)(p)); //ya puedo avanzar
        timestamp.tsecr = bpf_ntohl(*(__u32 *)(p + 4));

        break; // Terminar el bucle después de encontrar la opción de timestamp
    }
    p += (size - 2);
}

if (timestamp_encontrado) {
  bpf_printk("TSval: %u, TSecr: %u", timestamp.tsval, timestamp.tsecr);
} else {
  bpf_printk("El paquete recibido no tiene opciones");
}
  return;
}


static int getSyn(struct tcphdr *tcph){
	return tcph->syn;
}

//---------------------------------TESTEO-------------------------------------//
// Función principal
SEC("tc")
int tc_drop1(struct __sk_buff *skb) {

  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

// COMPROBACIONES INICIALES DE SEGURIDAD DE LIMITES DE MEMORIA

  if (data + sizeof(struct eth_hdr) > data_end)
    return TC_ACT_OK;

  struct eth_hdr *eth = data;

  if (eth->h_proto != bpf_htons(ETH_P_IP))
    return TC_ACT_OK;

  struct iphdr *iph = data + sizeof(struct eth_hdr);

  if ((void*)iph + sizeof(struct iphdr) > data_end)
    return TC_ACT_OK;

  if (iph->protocol != IPPROTO_TCP)
    return TC_ACT_OK;

  struct tcphdr *tcph = data + sizeof(*eth) + sizeof(*iph);

  if ((void*)tcph + sizeof(struct tcphdr) > data_end)
    return TC_ACT_OK;


//----------------------ANALISIS OPCIONES DEL PAQUETE RECIBIDO-----------------//

  get_TSecr(tcph, data, data_end);
  int syn=getSyn(tcph);
  bpf_printk("El sin es: %d\n", syn);
// Continuar con el resto del procesamiento...

return TC_ACT_OK;
}
///----------------------------//

char _license[] SEC("license") = "GPL";
