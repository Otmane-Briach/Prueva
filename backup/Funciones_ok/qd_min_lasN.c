// pruevas del funcionamineto del calculo del minimo
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
//eth_hdr
static int t=0;
  struct eth_hdr {
  	unsigned char   h_dest[ETH_ALEN];
  	unsigned char   h_source[ETH_ALEN];
  	unsigned short  h_proto;
  };


//--------------------------FUNCIONES CALLBACK-----------------------------------------//
// bucle para calcular el minimo
static long min_loop_callback(__u32 i, void *min_value_ptr) {

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
    long loops = bpf_loop(LAST_QDS, min_loop_callback, &min_value, 0);
    if (loops < 0) {
        bpf_printk("bpf_loop error: %ld\n", loops);
        return -1;
    }
    return min_value;
}
//---------------------------------TESTEO-------------------------------------//
// Tu función principal
SEC("tc")
int tc_drop1(struct __sk_buff *skb) {
    __u32 top=10;
    long long ret =qd_min_lastN(400);

    // Llamada a bpf_loop con print_loop_callback como función de devolución de llamada
    long loops = bpf_loop(top, print_loop_callback, NULL, 0);

/*    if (loops < 0) {
        bpf_printk("bpf_loop error: %ld\n", loops);
        return TC_ACT_SHOT; // Si hay un error, descarta el paquete
    }*/

    bpf_printk("El menor es: %lld\n", ret);

    return TC_ACT_OK;
}
//---------------------Conc-----------------//
char _license[] SEC("license") = "GPL";
