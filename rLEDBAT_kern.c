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
#define NANOS_PER_MS 1000000LL //un millon de nanosegundos en un ms
#define MAX_LONG_LONG 9223372036854775803LL
#define MAX_COUNT_RTT 10000
#define MAX_OPTIONS 11
// rledbat target
#define TARGET 60000000 //60ms
//gain is defined as 1/min(gain_constant,ceil((2*target)/base))               -0
#define GAIN_CONSTANT 16
// Constant for multiplicative decrease computation
#define CONSTANT_MULTIPLIER 1
#define CONSTANT_DIVIDER 1
// Data specific for RLEDBAT2
#ifdef RLEDBAT2
// replaces TARGET in some computations
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __s64);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} target2_map SEC(".maps");
#endif // RLEDBAT2
#define RLEDBAT_WATCH_PORT 49000
#define MAX_WINDOW 65535
// should be the same as for the module rewriting outgoing packets,
// kernel/xt_TWIN.c
#define MSS 1448 //unidad de ventana
#define INIT_WINDOW 1*MSS  //ventana inicial
// this is the minimum value (bytes) the window may have in any reduction
// (either periodic or delay-triggered)
// 2* mss
#define MIN_REDUCTION_BYTES 2896
#define SENDING 1
#define RECIEVING 2

#define max_t(type, x, y) ({    \
    type __x = (x);             \
    type __y = (y);             \
    __x > __y ? __x : __y;      \
})

#define MAX_SIZE 15 // Asigna el tamaño adecuado para tus estados




//--------------------PARTE SENDING




//----------------------------VVARIABLES GLOBALES-----------------------------//

//----------------------------INICIALIZADOS A CERO----------------------------//

// current pointer to last_qd_values
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} pointer_map SEC(".maps");

struct eth_hdr {
  	unsigned char   h_dest[ETH_ALEN];
  	unsigned char   h_source[ETH_ALEN];
  	unsigned short  h_proto;
  };

struct tcp_ts_option {
    __u64 tsval;
    __u64 tsecr;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct tcp_ts_option);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} timestamps_map SEC(".maps");

// to allow computing RTT information
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, MAX_COUNT_RTT);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} tsval_rtt_array_map SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} tsval_rtt_old_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, MAX_COUNT_RTT);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} time_rtt_array_map SEC(".maps");
// ts_val_array and time_rtt_array are exported to the write moduleS
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} tsecr_already_checked_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __s64);
    __uint(max_entries, 1);
} queue_delay_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} packet_number_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} is_retransmission_map SEC(".maps");


struct seq {
  __u64 last_seq;
  __u64 last_seq_old;
};
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct seq);
    __uint(max_entries, 1);
} seq_map SEC(".maps");

// number bytes acked
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} acked_map SEC(".maps");

struct tcp_rmem {
  __u32 min_buff;
  __u32 def_buff;
  __u32 max_buff;
};
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct tcp_rmem);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} tcp_rmem_map SEC(".maps");



// will be set to MIN_REDUCTION_BYTES / window_scale:
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} min_w_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __s32);
    __uint(max_entries, 1);
} increase_bytes_map SEC(".maps");

// to know if we are reducing the window
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} reduction_map SEC(".maps");



// number of bytes the window must be reduced
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __s64);
    __uint(max_entries, 1);
} rcwnd_scale_map SEC(".maps");



// _time values are ns
// time to maintain the window
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __s64);
    __uint(max_entries, 1);
} keep_window_time_map SEC(".maps");

// periodic reduction

struct periodic_reduction_str{
  __u64 periodic_reduction_time;
  __u64 begin_periodic_reduction_time;
  __u64 end_periodic_reduction_time;
};
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct periodic_reduction_str);
    __uint(max_entries, 1);
} periodic_reduction_map SEC(".maps");

// do not decrease until this time
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} next_decrease_time_map SEC(".maps");

// indicates if a retransmission occurred close to this time (only react with the first)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __s32);
    __uint(max_entries, 1);
} recent_retransmission_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, char[MAX_SIZE]);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} state_map SEC(".maps");

//used to know if periodic_reduction_time is from the previous or the next one
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __s32);
    __uint(max_entries, 1);
} periodic_reduction_scheduled_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} to_increase_CA_map SEC(".maps");






//--------------------------INICIALIZADOS NO ZERO-----------------------------//



//--------------------------INICIALIZADOS A MAX_LONG_LONG---------------------//
//values needed to compute the queueing delay
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rtt_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rtt_min_map SEC(".maps");
//almacena hasta los últimos 20 valores de qds, se puede cambiar fácilmente con LAST_QDS
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __s64);
    __uint(max_entries, 20);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} values_map SEC(".maps");

//-------------------------INICIALIZADO A INIT WINDOW-------------------------//

struct rcwnd_ok_str {
  // Ventana de repción efectiva
  __u64 rcwnd_ok; //Solo este valor se inicializa a INIT_WINDOW.
  // Puede ser usado para depurar.
  __u64 rcwnd_ok_before;
};
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct rcwnd_ok_str);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rcwnd_ok_map SEC(".maps");


//-------------------------INICIALIZADOS A 1----------------------------------//
// first slow start is different, we need to control that case
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __s32);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} is_first_ss_map SEC(".maps");
// to disable temporarily slow start
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __s32);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} is_ss_allowed_map SEC(".maps");
// to know if we have to freeze the window after a periodic reduction
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __s32);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} freeze_ended_map SEC(".maps");

struct w_scale{
  //Factor de escalado(exponent)
  __u16 rcv_wscale;
  //Factor de escalado(bytes)
  __u32 window_scale; //Este valor se inicializa a 1
};
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct w_scale);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} window_scales_map SEC(".maps");


//-------------------------INICIALIZADOS A MAX_WINDOW-------------------------//
//slow start threshold
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ssthresh_map SEC(".maps");




//-----------------------variables exlusivas de los paquetes salientes--------//



struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} count_ack_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} current_ack_map SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} last_ack_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __s32);
    __uint(max_entries, 1);
} tcp_rcwnd_map SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __s64);
    __uint(max_entries, 1);
} check_ack_map SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} time_tsval_rtt_map SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} flag_dup_ack_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} key_timestamps SEC(".maps");





//--------------------------FUNCIONES CALLBACK--------------------------------//
// bucle para calcular el minimo
static long qd_min_lastN_loop(__u32 i, void *min_value_ptr) {

    __s64 *value = bpf_map_lookup_elem(&values_map, &i);
    if (!value)
        return 1;  // Si bpf_map_lookup_elem falla, detenemos el bucle

    __u64 *min_value = min_value_ptr;

    if (*value < *min_value) {
        *min_value = *value;
    }

    return 0;  // Continúa el bucle
}

static inline long print_loop_callback(__u32 key, void *ctx) {
  __u64 *value, *value2;
  value = bpf_map_lookup_elem(&tsval_rtt_array_map, &key);
  value2 = bpf_map_lookup_elem(&time_rtt_array_map, &key);
  if (!value || !value2) {
      return 1;
  }
  bpf_printk("[%u]  [tsval= %lld, time=  %llu\n]", key, *value, *value2);
  return 0; // El valor de retorno indica si la función debe continuar (0) o detenerse (1)
}

static inline long clear_rtt_table_callback(__u32 index, void *ctx) {
  __u64 zero = 0;

  // Limpiar tsval_rtt_array_map
  if (bpf_map_update_elem(&tsval_rtt_array_map, &index, &zero, BPF_ANY)) {
        bpf_printk("Failed to clear tsval_rtt_array_map\n");
        return 1;
  }
  // Limpiar time_rtt_array_map
  if (bpf_map_update_elem(&time_rtt_array_map, &index, &zero, BPF_ANY)) {
        bpf_printk("Failed to clear time_rtt_array_map\n");
        return 1;
  }
  // Si llegamos al final del bucle, limpiar tsval_rtt_old_map
  if (index == MAX_COUNT_RTT - 1) {
      __u32 key = 0;
      if(bpf_map_update_elem(&tsval_rtt_old_map, &key, &zero, BPF_ANY)){
        bpf_printk("Failed to clear tsval_rtt_old_map\n");
        return 1;
      }
  }
  return 0; // El valor de retorno indica si la función debe continuar (0) o detenerse (1)
}
//Estructura auxiliriar usada para adaptar el bucle a la funcion bpf_loop.
struct min_rtt_loop_ctx {
    __u64 tsecr;
    __u64 reception_time;
    __u64 rtt;
    __u64 rtt_min;
    __u64 tsecr_already_checked;
};
static long min_rtt_callback(__u32 index, void *ctx) {
    struct min_rtt_loop_ctx *loop_context = (struct min_rtt_loop_ctx *)ctx;
    __u64 tsecr = loop_context->tsecr;
    __u64 reception_time = loop_context->reception_time;

    __u64 *tsval_rtt = bpf_map_lookup_elem(&tsval_rtt_array_map, &index);
    __u64 *time_rtt = bpf_map_lookup_elem(&time_rtt_array_map, &index);

    if (!tsval_rtt || !time_rtt)
        return 0;
/*
//Cuando el host A envia un segmento, inlcuye la hora actual en el ts_val
//eso lo guarda en el array tsval_rtt.
//Cuando el host B  recibe el paquete, y envia un ack,
//en este segmento incluye el TSecr, y le da un valor igual al de TSval que recibió.
//De esta manera el host A teniendo el TSval=hora de envio y Tla hora registrada de
//cuando le llego el el segmento de TSecr=Tsvall,
//Ya tiene la hora de ida y la hora de recepción. Se hace la resta y eso es el rtt.
  */
    if (*tsval_rtt == tsecr) {
        if (tsecr != loop_context->tsecr_already_checked) {
            __u64 new_rtt = reception_time - *time_rtt;
            loop_context->tsecr_already_checked = tsecr;
            loop_context->rtt = new_rtt;

            if (new_rtt < loop_context->rtt_min) {
                loop_context->rtt_min = new_rtt;
                bpf_printk("RTT_MIN ESTABlISHED");
            }
            return 1; // Finalizar la iteración del bucle
        } else {
            bpf_printk("receive_REPEATED");
            return 1; // Finalizar la iteración del bucle
        }
    }

    return 0; // Continuar con la siguiente iteración
}

//---------------------------FUNCIONES---------------------------------------//

/*
le llega el ultimo retraso de cola medido, lo guarda
en la matriz de los ultimos 20 y calcula cual es el minimo.
y eso es lo que devuelve.
*/
static __s64 qd_min_lastN(__s64 last_qd) {

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
    __s64 min_value = *temp;

    // Ejecuta bpf_loop para actualizar min_value
    long loops = bpf_loop(LAST_QDS, qd_min_lastN_loop, &min_value, 0);
    if (loops < 0) {
        bpf_printk("bpf_loop error: %ld\n", loops);
        return -1;
    }
    return min_value;
}

static inline void get_TSecr(struct tcphdr *tcph, void *data, void *data_end) {

    __u32 key_0=0;
    struct tcp_ts_option *timestamp = bpf_map_lookup_elem(&timestamps_map, &key_0);
    if(!timestamp){
      bpf_printk("Failed to read timestamp_map");
      return;
    }
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
        bpf_printk("Estoy dentro");
        return;
    }

    for (int i = 0; (i < MAX_OPTIONS && p < end); i++) { //-------EN ESTE BUCLE TIENE QUE HABER SI O SI LA CONDICION &&P<END.
        __u8 kind;

        // Me aseguro de que 'p' esté dentro del rango de 'data' y 'data_end' en cada vuelta.
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

        if (kind == 8 && size == 10) { // Opción de timestamp

                timestamp_encontrado=true;

                if (p + 8 > end || p + 8 > data_end) { // Comprobar que hay suficientes bytes para TSval y TSecr
                     bpf_printk("Fuera de limites p+8");
                    return;
                }

                 timestamp->tsecr = bpf_ntohl(*(__u32 *)(p + 4));
                 break;
        }
        p += (size - 2);
    }

        if (timestamp_encontrado) {
              //bpf_printk("TSval: %u, TSecr: %u", timestamp->tsval, timestamp->tsecr);
        } else {
              bpf_printk("El paquete recibido no tiene opciones");
        }
}

static inline void get_TSval(struct tcphdr *tcph, void *data, void *data_end) {

    __u32 key_0=0;
    struct tcp_ts_option *timestamp = bpf_map_lookup_elem(&timestamps_map, &key_0);
    if(!timestamp){
      bpf_printk("Failed to read timestamp_map");
      return;
    }
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
        bpf_printk("Estoy dentro");
        return;
    }

    for (int i = 0; (i < MAX_OPTIONS && p < end); i++) { //-------EN ESTE BUCLE TIENE QUE HABER SI O SI LA CONDICION &&P<END.
        __u8 kind;

        // Me aseguro de que 'p' esté dentro del rango de 'data' y 'data_end' en cada vuelta.
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

        if (kind == 8 && size == 10) { // Opción de timestamp

                timestamp_encontrado=true;

                if (p + 8 > end || p + 8 > data_end) { // Comprobar que hay suficientes bytes para TSval y TSecr
                     bpf_printk("Fuera de limites p+8");
                    return;
                }

                        if(timestamp->tsval!=bpf_ntohl(*(__u32 *)(p))){


                                //solo actualiza time_tsval_rtt_ptr para el primer paquete con el mismo TSVAL
                                timestamp->tsval = bpf_ntohl(*(__u32 *)(p)); //ya puedo avanzar

                                 __u32 *key_timestamps_ptr= bpf_map_lookup_elem(&key_timestamps,&key_0);
                                 if(!key_timestamps_ptr){
                                    bpf_printk("Failed to read map key_timestamps_ptr ");
                                    return;
                                 }
                                  //avanzamos en modulo, nos aseguramos de que el valor esté en el rango [0, MAX_COUNT_RTT-1].

                                __u64 tsval_value = timestamp->tsval;
                                __u64 time_value = bpf_ktime_get_ns();

                                // Actualizar tsval_rtt_array_map
                                int ret1 = bpf_map_update_elem(&tsval_rtt_array_map, key_timestamps_ptr, &tsval_value, BPF_ANY);
                                if (ret1 != 0) {
                                    bpf_printk("Failed to update map tsval_rtt_array_map ");
                                }

                                // Actualizar time_rtt_array_map
                                int ret2 = bpf_map_update_elem(&time_rtt_array_map, key_timestamps_ptr, &time_value, BPF_ANY);
                                if (ret2 != 0) {
                                    bpf_printk("Failed to update map tsval_rtt_array_map ");
                                }

                                (*key_timestamps_ptr)++;
                                *key_timestamps_ptr %= MAX_COUNT_RTT;

                          }
          break; // Terminar el bucle después de encontrar la opción de timestamp
        }
        p += (size - 2);
    }

        if (timestamp_encontrado) {
              //bpf_printk("TSval: %u, TSecr: %u", timestamp->tsval, timestamp->tsecr);
        } else {
              bpf_printk("El paquete recibido no tiene opciones timestamp");
        }
}

static int getSyn(struct tcphdr *tcph){
	return tcph->syn;
}
// Is there WS window scale option?
static int isWSoption(struct tcphdr *tcph, void *data, void *data_end){

  __u8 size;
  __u8 *end;
  __u8 *p;

    //para ver si la parte de WS esta habilidad vamos a la parte de OPTIONES, que esta en el byte 20.
    //y vemos los tres parámetros.
    //    +---------+---------+---------+
    //    | Kind=3  |Length=3 |shift.cnt|
    //    +---------+---------+---------+
    //         1         1         1
    //se tiene que cumplir que  Kind=3 y length=3.
    p = (__u8 *)tcph + sizeof(*tcph);
    end = (__u8 *)tcph + tcph->doff * 4;
    // Me aseguro de que tenga al menos un byte para leer el "kind"
    if ((void *)p >= data_end || (void *)end > data_end) {
        return 0;
    }

    for (int i = 0; (i < MAX_OPTIONS  && p < end); i++) {  //-------------SOLUCION AL WHILE(P<END)
        __u8 kind;
        // Me aseguro de que 'p' esté dentro del rango de 'data' y 'data_end' en cada vuelta.
        if ((void *)p >= data_end) {
            return 0;
        }
        // Me aseguro de que tenga al menos un byte para leer el "kind"
        if (p + 1 > end || p + 1 > data_end) {
            return 0;
        }
        kind = *p++;

        if (kind == 0)
            break;

    // No-op option with no length.
        if (kind == 1)
            continue;

        // Me aseguro de que tengas al menos un byte para el campo size
        if (p + 1 > end || p + 1 > data_end) {
            return 0;
        }

        size = *p++; //en el sigueinte byte esta el size.


        if(kind == 3){
              return 1; //si es tres, es que la opcion WS esta activada.
        }



        p += (size - 2);
    }

	return 0;
}

static void min_rtt(__u64 tsecr, __u64 reception_time) {
    __u32 key = 0;
    __u64 *rtt_ptr = bpf_map_lookup_elem(&rtt_map, &key);
    __u64 *rtt_min_ptr = bpf_map_lookup_elem(&rtt_min_map, &key);
    __u32 *tsecr_already_checked_ptr = bpf_map_lookup_elem(&tsecr_already_checked_map, &key);

    if (!rtt_ptr || !rtt_min_ptr || !tsecr_already_checked_ptr)
        return;

    struct min_rtt_loop_ctx ctx = {
        .tsecr = tsecr,
        .reception_time = reception_time,
        .rtt = *rtt_ptr,
        .rtt_min = *rtt_min_ptr,
        .tsecr_already_checked = *tsecr_already_checked_ptr,
    };

    long loops=bpf_loop(MAX_COUNT_RTT, min_rtt_callback, &ctx, 0);
    if (loops < 0) {
        bpf_printk("bpf_loop error: %ld\n", loops);
        return;
    }

    *rtt_ptr = ctx.rtt;
    *rtt_min_ptr = ctx.rtt_min;
    *tsecr_already_checked_ptr = ctx.tsecr_already_checked;
    // Caso en el que el valor no está en el array
    //Para manejar este caso, después de
    //que bpf_loop haya terminado su ejecución, en este caso verifico si el valor de rtt
    //en el contexto sigue siendo el mismo después de terminar el bucle de bpf_loop.
    //Si es así, esto indica que el valor no fue encontrado y, por lo tanto, establecemos rtt al valor de rtt_min.
    //Tenemos que separar el caso de "Encontrado y ya inspeccionado" del caso"NO ENCONTRADO", por ello
    //hay que verificar que también *tsecr_already_checked_ptr!=tsecr
    if (ctx.rtt == *rtt_ptr && *tsecr_already_checked_ptr!=tsecr) {
        *rtt_ptr = ctx.rtt_min;
        bpf_printk("NOT_FOUND: rtt: %lld, tsecr: %ld, tsecr_already_checked %ld", *rtt_ptr, tsecr, *tsecr_already_checked_ptr);
    }
}

static void clear_rtt_table(void) {

    __u64 zero = 0;

    long ret = bpf_loop(MAX_COUNT_RTT, clear_rtt_table_callback, &zero, 0);
    if (ret < 0) {
    // bpf_trace_printk("Error in bpf_loop: %ld\n", ret);
    }
      bpf_printk("RTT table CLEARED ");
}

//auxiliary function to calculate ceil, lo que hace ceil es
//redondear un número hacia arriba hasta el próximo número entero
static __u64 ceil_rledbat(__u64 num, __u64 den){
    if(num>den){ //si el numerador es mayor que el numerador, el numero que vamos a redondear va a ser >=2
        __u64 rest= num%den;
        __u64 lacking= den - rest;

        return (__u64) (num +lacking)/den;
    }
    else { //si no, siempre va a ser entreo cero y 1, por lo que siempre redondeamos a 1.
      return 1;
    }
}

// gain DIVIDER (the divider of GAIN=1/gain)
static __u64 gain(__u64 rtt_min){
	__u32 gain_aux=0;
    // according to LEDBAT++ draft  GAIN = 1 / (min (16, CEIL (2*TARGET/base))
    gain_aux=ceil_rledbat(2*TARGET,rtt_min);
	if (GAIN_CONSTANT>gain_aux) //retorna el minimo
		return gain_aux;
	else return GAIN_CONSTANT;
}

//El objetivo es calcular cuántos bytes se deben reducir de la ventana
//de congestión basándose en el retraso de la cola y otros parámetros.
__s64 custom_divide(__s64 num, __s64 den) {
    // Paso 1: Determina el signo del resultado
    int sign = 1;
    if (num < 0) {
        sign *= -1;
        num = -num; // Convierte num en positivo
    }

    // Paso 2: Realiza la división usando números sin signo
    unsigned long long u_num = (unsigned long long) num;
    unsigned long long u_den = (unsigned long long) den;
    unsigned long long u_result = u_num / u_den;

    // Paso 3: Ajusta el signo del resultado
    long long result = (long long) u_result * sign;

    return result;
}

static __s64 bytes_to_decrease_rledbat(__u64 window,__u64 scale, __u64 queue_delay,__u64 rtt_min){

    /*
      // la formula estander de LEDBAT para reducir la ventana es:
    	//W += max( (GAIN - Constant * W * (delay/target - 1)), -W/2) )
      // (notar que RLEDBAT2 modifica esto)
      // Como no se pueden usar operaciones de punto flotante en el kernel,
      //la función reorganiza la fórmula para evitar la necesidad de operaciones de punto flotante.
    	// asumimos que gain siempre sera 1/x x>0
      //y tenemos:
    	// (Constant_divider*Target - gain_divider*constant_num*window*(delay-target))/(gain_divider*constant_divider*target)
    */

  __u64 window_size=window*scale;
	__s64 diff=0;
	__u64 gain_val=0;
	__s64 aux=0;
	__s64 num=0;
	__s64 den=0;
	__s64 decrease=0;
	__s64 window_half=0;

    //diff es la diferencia entre el queue_delay actual y un valor
    //objetivo (TARGET o target2 dependiendo de si RLEDBAT2 está definido o no).
    //Esta diferencia indica cuánto excede el retraso actual el objetivo deseado.


    #ifdef RLEDBAT2

    __u64 *target2=bpf_map_lookup_elem(&target2_map, &key_0);
    if(!target2)
      return TC_ACT_OK;

        diff = queue_delay - *target2;
    #else
        diff=queue_delay-TARGET; //el target es 60 ms
    #endif

	gain_val=gain(rtt_min);   //gain = 1 / (min (16,(2*TARGET/base))
	aux=gain_val*CONSTANT_MULTIPLIER*window_size; //CONST_MULTI=1

    //Calculamos numerador y denominador de la fraccion:
    //(Constant_divider*Target - gain_divider*constant_num*window*(delay-target))/(gain_divider*constant_divider*target)

    #ifdef RLEDBAT2
      num=CONSTANT_DIVIDER* (*target2) -aux*diff; //si el delay es mayor que el target se hace negativa en propocion a la diferencia.
	    den=gain_val*CONSTANT_DIVIDER* (*target2);
    #else
	    num=CONSTANT_DIVIDER*TARGET-aux*diff;
	    den=gain_val*CONSTANT_DIVIDER*TARGET;
    #endif

  decrease=custom_divide(num,den);
	window_half=-1*(window_size/2); //limite inferior para la disminución de la ventana

    bpf_printk("decrease_rledbat aux:%lld num:%lld, den:%lld window_size:%llu gain:%llu window_half:%lld \n", aux, num, den, window_size, gain_val, window_half);

    if (decrease>=window_half){
  //  bpf_printk("Mayor que half");
      return decrease;
	  }else{
    //bpf_printk("Menor que half, retornamos half %ld\n", window_half);
      return window_half;
    }
}

static void update_state(char *new_state) {
    __u32 key = 0;
    char *current_state;

    current_state = bpf_map_lookup_elem(&state_map, &key);
    if (!current_state) {
      bpf_printk("No se pudo obtener el estado actual");
        return;
    }

    #pragma clang loop unroll(full)
    for (int i = 0; i < MAX_SIZE; i++) {
        current_state[i] = new_state[i];
        if (!new_state[i]) {
            break; // Paramos de copiar
    }
  }
}

char *get_current_state() {
    __u32 key = 0;
    return bpf_map_lookup_elem(&state_map, &key);
}



//---------------------------------TESTEO-------------------------------------//

SEC("tc-out")
int twin_tg(struct __sk_buff *skb){

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



//------------------------------------------------
  __u32 key_0=0;
  struct w_scale *window_scales_ptr=bpf_map_lookup_elem(&window_scales_map,&key_0);
  __u32 *current_ack_ptr=bpf_map_lookup_elem(&current_ack_map,&key_0);
  __u32 *tcp_rcwnd_ptr= bpf_map_lookup_elem(&tcp_rcwnd_map,&key_0);
  __u64 *last_ack_ptr= bpf_map_lookup_elem(&last_ack_map,&key_0);
  __u32 *count_ack_ptr= bpf_map_lookup_elem(&count_ack_map,&key_0);
  __u32 *flag_dup_ack_ptr= bpf_map_lookup_elem(&flag_dup_ack_map,&key_0);
  struct rcwnd_ok_str *rcwnd_ok_ptr=bpf_map_lookup_elem(&rcwnd_ok_map,&key_0);
  struct seq *seq_values = bpf_map_lookup_elem(&seq_map, &key_0);
  struct tcp_ts_option *timestamp_ptr = bpf_map_lookup_elem(&timestamps_map, &key_0);



  if(!window_scales_ptr  || !current_ack_ptr
    || !tcp_rcwnd_ptr    ||!seq_values
    ||!last_ack_ptr      || !count_ack_ptr
    || !flag_dup_ack_ptr ||!rcwnd_ok_ptr ||!timestamp_ptr){
    bpf_printk("Failed to read map SENDING");
        return TC_ACT_OK;
  }



  __u64 RECWND_MSS;
  RECWND_MSS = MSS / (1<<(window_scales_ptr->rcv_wscale)) + 1;
  //compute min between the cp crwnd and the one we compute
  *current_ack_ptr = (__u32)bpf_ntohl(tcph->ack_seq);
  //bpf_printk("current_ack: %llu", *current_ack_ptr);

  // Read parameters of packet sent to pass them to the read module
  get_TSval(tcph, data, data_end);

  *tcp_rcwnd_ptr =  bpf_ntohs(tcph->window);

   if(*current_ack_ptr==*last_ack_ptr){
          (*count_ack_ptr)++;
      }


  if(*count_ack_ptr==4){
      *flag_dup_ack_ptr=1;
      *count_ack_ptr=0;
  }


      if (rcwnd_ok_ptr->rcwnd_ok > (long long)*tcp_rcwnd_ptr){
        bpf_printk("TCP is LIMITING the RATE, rledbat wanted:%lld;tcp:%d;scale(bits):%u\n",  rcwnd_ok_ptr->rcwnd_ok, *tcp_rcwnd_ptr, window_scales_ptr->rcv_wscale);
          rcwnd_ok_ptr->rcwnd_ok=*tcp_rcwnd_ptr;

      }
      if (  rcwnd_ok_ptr->rcwnd_ok>65535){
            rcwnd_ok_ptr->rcwnd_ok=65535;
      }
      //change with MSS from the read module in the syn/ack
      if (  rcwnd_ok_ptr->rcwnd_ok < 2* RECWND_MSS){
          if ((long long)*tcp_rcwnd_ptr >= 2 * RECWND_MSS)
          {  rcwnd_ok_ptr->rcwnd_ok = 2 *RECWND_MSS;}
          else if (   rcwnd_ok_ptr->rcwnd_ok < RECWND_MSS) {
            rcwnd_ok_ptr->rcwnd_ok= RECWND_MSS; }
          // else, between MSS and 2*MSS, rcwnd_ok = same value as TCP window
      }


      *last_ack_ptr=*current_ack_ptr;



// Ajustar la ventana TCP.
tcph->window = bpf_htons(rcwnd_ok_ptr->rcwnd_ok);

// Recalcular el checksum de la capa 4.
// Necesitamos calcular la diferencia entre el valor anterior y el nuevo valor
// de la ventana para poder actualizar el checksum de manera incremental.
int delta = bpf_htons(rcwnd_ok_ptr->rcwnd_ok) - bpf_htons(*tcp_rcwnd_ptr);
bpf_l4_csum_replace(skb,
                    offsetof(struct tcphdr, check),
                    0,
                    delta,
                    0);

// Si tuvieras otros campos que modificar, como la dirección IP o el puerto,
// necesitarías llamar a `bpf_l4_csum_replace` nuevamente con los valores adecuados.
// Pero dado que sólo estás modificando la ventana TCP, una llamada es suficiente.

// Ya no es necesario ajustar skb->ip_summed en eBPF como se hace en C.

__u64 *time_tsval_rtt_ptr=bpf_map_lookup_elem(&time_tsval_rtt_map, &key_0);
if(!time_tsval_rtt_ptr){
    bpf_printk("Failed to read time_tsval_rtt_ptr in SENDING");
    return TC_ACT_OK;
}
//bpf_printk("write;%llu;%llu;%d;%d;%llu;%d;", rcwnd_ok_ptr->rcwnd_ok, *last_ack_ptr, seq_values->last_seq, *tcp_rcwnd_ptr, *time_tsval_rtt_ptr, *flag_dup_ack_ptr);
//bpf_printk("%llu \n", window_scales_ptr->rcv_wscale);

    return TC_ACT_OK;
}



/*
// Función principal
SEC("tc-in")
int tc_dropTEST(struct __sk_buff *skb){

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

  __u64 reception_time=bpf_ktime_get_ns();;
  __u32 key_0=0;

  get_TSecr(tcph, data, data_end);
  get_TSval(tcph, data, data_end);
  struct tcp_ts_option *timestamp = bpf_map_lookup_elem(&timestamps_map, &key_0);
  if(!timestamp){
    return TC_ACT_OK;
  }

//antes de llamar a min rtt imprimr lo que haya dentro del mapa:
__u32 *key_timestamps_ptr= bpf_map_lookup_elem(&key_timestamps,&key_0);
if(!key_timestamps_ptr)
  return TC_ACT_OK;

  bpf_printk("tsval: %llu, tsecr: %llu", timestamp->tsval,timestamp->tsecr);

  bpf_printk("key_timestamps_ptr %u", *key_timestamps_ptr);
  bpf_loop(*key_timestamps_ptr, print_loop_callback, 0, 0);
  min_rtt(timestamp->tsecr,reception_time);

    return TC_ACT_OK;
}
*/

SEC("tc-in")
int rledbat_incoming_exit(struct __sk_buff *skb) {

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





//-----------------
  __u32 key_0=0;
  __u64 denominator_CA;
  __u32 space;
  //time when the packet was received
  __u64 reception_time;
  // Convert network endianness to host endianness
    /* Source and destination addresses */
  __u32 saddr = bpf_ntohl(iph->saddr);
  __u32 daddr = bpf_ntohl(iph->daddr);
    /* Source and destination ports */
  __u16 sport = bpf_ntohs(tcph->source);
  __u16 dport = bpf_ntohs(tcph->dest);
  //last seq recieved
  struct seq *seq_values=bpf_map_lookup_elem(&seq_map, &key_0);
    if(!seq_values){
         bpf_printk("Failed to read a map in line 1223 SEQ_VALUES");
        return TC_ACT_OK;
    }

  seq_values->last_seq = bpf_ntohl(tcph->seq); // numero de secuencia del paquete entrante.

  //si el puerto destino es difente al que escuchamos en ledbat, skipea(para paquetes que llegan)
  if (dport != RLEDBAT_WATCH_PORT)
      return TC_ACT_OK;

  //hace la funcion de todo el proceso de do_gettimeofday y time_to_tm
  //nos devuelve el tiempo en nanosegundos directamente desde el inicio del sistema.
  reception_time = bpf_ktime_get_ns();



  // Print and update qd_values_pointer_map
  __u32 *packet_number = bpf_map_lookup_elem(&packet_number_map, &key_0);
  if (!packet_number)
    return TC_ACT_OK;


  //bpf_printk("packet_number: %lld\n", *packet_number);
  *packet_number = *packet_number + 1;
  bpf_map_update_elem(&packet_number_map, &key_0, packet_number, BPF_ANY);

  bpf_printk("Soy el paquete: %lld", *packet_number);


  get_TSecr(tcph, data, data_end);
  get_TSval(tcph, data, data_end);
  //check if this packet is a retransmission
  //nos fijamos en el numero de secuencia y el valor de ts_val
  /*de entre los que recibimos con un numero de secuencia menor o igual que el ultimo
    parquete recibido, los que tienen un tsval mayor que el del ultimo es que son retranmisiones.
    */

//Preparamos puntero a mapa target2, para los proximas lineas de rledbat
#ifdef RLEDBAT2
  __u64 *target2=bpf_map_lookup_elem(&target2_map, &key_0);
  if(!target2)
    return TC_ACT_OK;
#endif
  //obtenemos los punteros que apuntan a los mapas.
  //struct seq *seq_values = bpf_map_lookup_elem(&seq_map, &key_0);
  __u32 *is_retransmission = bpf_map_lookup_elem(&is_retransmission_map, &key_0);
    struct tcp_ts_option *timestamp = bpf_map_lookup_elem(&timestamps_map, &key_0);
  __u64 *tsval_rtt_old = bpf_map_lookup_elem(&tsval_rtt_old_map, &key_0);
  __u64 *to_increase_CA_ptr = bpf_map_lookup_elem(&to_increase_CA_map, &key_0);
  __u64 *next_decrease_time_ptr=bpf_map_lookup_elem(&next_decrease_time_map, &key_0);
  __s32 *increase_bytes_ptr=bpf_map_lookup_elem(&increase_bytes_map, &key_0);

  //Check para el acceso
  if(!is_retransmission || !timestamp || !tsval_rtt_old || !to_increase_CA_ptr || !next_decrease_time_ptr ||  !increase_bytes_ptr){
    bpf_printk("Failed to read a map in line 1273 ");
    return TC_ACT_OK;
  }


if(*packet_number!=3){
  if((seq_values->last_seq <= seq_values->last_seq_old) && (timestamp->tsval >= *tsval_rtt_old)){
    //  bpf_printk("Es una retransmision, last_seq: %lu, last_seq_old: %lu", seq_values->last_seq, seq_values->last_seq_old );
      bpf_printk("last_seq %llu, last_seq_old: %llu, TSval %llu, tsval_old: %llu", seq_values->last_seq, seq_values->last_seq_old, timestamp->tsval, *tsval_rtt_old);
    	*is_retransmission=1;
  }else{
      //bpf_printk("No una retransmision, last_seq: %lu, last_seq_old: %lu", seq_values->last_seq, seq_values->last_seq_old);
      *is_retransmission=0;
      }
}
  	  seq_values->last_seq_old=seq_values->last_seq;


 if ( timestamp->tsval != *tsval_rtt_old){
      *tsval_rtt_old = timestamp->tsval;  //TSVAL_RTT = TSVAL_RTT_ARRAY[I]--------------------------------------EL ERROR AQUI
  }

  //update global variables rtt and rtt_min
  min_rtt(timestamp->tsecr,reception_time);

  //acked= #bytes de datos que han venido en el paquete.
  //doff suele ser igual a 5, es la cantidad de palabras de 32 bits que tenemos.
  __u32 *acked=bpf_map_lookup_elem(&acked_map, &key_0);
  if(!acked){
     bpf_printk("Failed to read a map in line 1299");
    return TC_ACT_OK;
  }

  *acked = bpf_ntohs(iph->tot_len) - (tcph->doff * 4) - (iph->ihl * 4);

// bpf_printk("Acked: %d\n", *acked);
//  bpf_printk("iph->tot_len: %d\n",  bpf_ntohs(iph->tot_len) );
//  bpf_printk("tcph->doff * 4: %d\n",(tcph->doff * 4) );
//  bpf_printk("iph->ihl * 4:  %d\n",(iph->ihl * 4));


  __u64 *rtt=bpf_map_lookup_elem(&rtt_map, &key_0);
  __u64 *rtt_min=bpf_map_lookup_elem(&rtt_min_map, &key_0);
  __u64 *queue_delay_ptr=bpf_map_lookup_elem(&queue_delay_map, &key_0);

  if(!rtt_min || !rtt || !queue_delay_ptr){
    bpf_printk("Failed to read a map in line 1315");
    return TC_ACT_OK;
  }


  *queue_delay_ptr = *rtt - *rtt_min;
  //bpf_printk("queue_delay: %lu", *queue_delay);
  //bpf_printk("rtt:  %lu\n",*rtt);
 //bpf_printk("rtt_min  %lu\n",*rtt_min);

  #ifdef RLEDBAT2
      // compute RLEDBAT2-specific target2 variable

      if (*rtt_min < TARGET) {
          *target2 = *rtt_min;
      }
      else {
          *target2 = TARGET;
      }
  #endif

  // Take the min of the last LAST_QDS values
  *queue_delay_ptr = qd_min_lastN(*queue_delay_ptr);


  // Next we consider all the cases relevant for rledbat behavior: first packet,
  // there is a retransmission, qd is too high, periodic slowdown to measure rttmin, etc.

  // Check in the first packet (that should be a SYN) that there is an WS option included.
  // The value used is discarded, compute a new value according to the available memory.
  // The value is exported to the module rewriting outgoing packets, so that it changes it for
  // all packets sent.

  // window_scale= scaling factor (bytes)
  // rcwnd_scale= number of bytes the window must be reduced
  // rcv_wscale= scaling factor (exponent)

  struct tcp_rmem *tcp_rmem_ptr=  bpf_map_lookup_elem(&tcp_rmem_map,&key_0);
  struct w_scale *window_scales_ptr=bpf_map_lookup_elem(&window_scales_map,&key_0);
  struct rcwnd_ok_str *rcwnd_ok_ptr=bpf_map_lookup_elem(&rcwnd_ok_map,&key_0);
  __u16 *min_w_ptr=bpf_map_lookup_elem(&min_w_map,&key_0);



  if(!tcp_rmem_ptr || !window_scales_ptr || !rcwnd_ok_ptr || !min_w_ptr){
     bpf_printk("Failed to read a map Line 1357");
     return TC_ACT_OK;
  }

 //bpf_printk(" PRIMERO window :%lld",rcwnd_ok_ptr->rcwnd_ok);
if(1==*packet_number){

      if(getSyn(tcph) && isWSoption(tcph, data, data_end)){
            __u32 rest=0;
            __u32 tcp_rmem=0;
            __u32 sysctl_rmem_max;


            tcp_rmem=tcp_rmem_ptr->def_buff;
            sysctl_rmem_max=tcp_rmem_ptr->max_buff;
            space = max_t(__u32, tcp_rmem, sysctl_rmem_max); //---he creado una macro de max_t

            //A continuacion, calculamos la escala de la ventana para tcp
            //si el tamaño de la ventana deseada es mayor que 65535
            //(el maximo representable con 16 bits de la ventana )
            //trataremos de encontrar un factor de escala que pueda
            //representar ese valor.

            bpf_printk("Space:%d", space);
             while (space > 65535 && (window_scales_ptr->rcv_wscale) < 14) {
                 space >>= 1; //(dividir por 2) porque ocupamos el doble en cada incremento.
                 (window_scales_ptr->rcv_wscale)++;
              }
               bpf_printk("window_scales_ptr->rcv_wscale:%d", window_scales_ptr->rcv_wscale);
            //Calcula el factor de escala de ventana.
            window_scales_ptr->window_scale=1<<(window_scales_ptr->rcv_wscale); // = 2^rcv_wscale

            //Establacemos la ventana en función del escalado.
            //rcwnd_ok expresada en unidades de ventana escalada.
            //la idea aqui es reducir el valor real de la ventana dividiendolo por el factor de escala
            //antes de colocarlo en la cabecera TCP. El host receptor, solo multiplica por el factor de escala
            //para obtener la ventan real.
            rcwnd_ok_ptr->rcwnd_ok=INIT_WINDOW/window_scales_ptr->window_scale;  //init_window=1448---> expresamos crwnd_ok en unidades de ventana.
            //Redondeamos hacia arriba
            rest=INIT_WINDOW%window_scales_ptr->window_scale;
            if(rest!=0){
              rcwnd_ok_ptr->rcwnd_ok++;
            //De esta manera, caundo windows scale sea 2^11=2048 o mas, dara
            //cero, y rcwnd_ok valdrá su minimo que es 1.
            }

            bpf_printk("rcwnd_ok_ptr->rcwnd_ok:%d", rcwnd_ok_ptr->rcwnd_ok);

            // set minimum window depending on scaling
            rest=MIN_REDUCTION_BYTES%window_scales_ptr->window_scale;
            *min_w_ptr=MIN_REDUCTION_BYTES/window_scales_ptr->window_scale; //min reduction, 2 segmentos, 2896.

            //rounding (ceil)
            if(rest!=0){
              (*min_w_ptr)++;
            }

      }else {
              bpf_printk("WARNING: first packet received is not a SYN, and it should!");
              bpf_printk("get syn: %d:", tcph->syn);
               __u8 i= isWSoption(tcph, data, data_end);
              bpf_printk("IsWoption:: %d:", i);

              return TC_ACT_OK;
      }
}

//------------------------------------------------cheked


  __u32 *reduction_ptr= bpf_map_lookup_elem(&reduction_map, &key_0);
  __s32 *rcwnd_scale_ptr= bpf_map_lookup_elem(&rcwnd_scale_map, &key_0);
  __u32 *recent_retransmission_ptr= bpf_map_lookup_elem(&recent_retransmission_map, &key_0);
  __s64 *keep_window_time_ptr= bpf_map_lookup_elem(&keep_window_time_map, &key_0);
  __s32 *is_first_ss_ptr= bpf_map_lookup_elem(&is_first_ss_map, &key_0);
  struct periodic_reduction_str *periodic_reduction_ptr= bpf_map_lookup_elem(&periodic_reduction_map, &key_0);

  if(!reduction_ptr || !rcwnd_scale_ptr || !recent_retransmission_ptr ||!keep_window_time_ptr || !periodic_reduction_ptr || !is_first_ss_ptr){
     bpf_printk("Failed to read a map Line 1425");
    return TC_ACT_OK;
}
    //window_scales_ptr->rcv_wscale es el exponente del factor de escala (que va hasta el 14)
    //window_scales_ptr->window_scale el factor de escala (numero por el que se multiplica la ventana que se envia en tcp)
    //rcwnd_ok_ptr la ventana que se envia en tcp
    //rcwnd_scale_ptr numero de bytes que la ventana tiene que ser reducida.

  __s32 *periodic_reduction_scheduled_ptr= bpf_map_lookup_elem(&periodic_reduction_scheduled_map, &key_0);
  __s32 *freeze_ended_ptr= bpf_map_lookup_elem(&freeze_ended_map, &key_0);
  __s32 *ssthresh_ptr= bpf_map_lookup_elem(&ssthresh_map, &key_0);
  __s32 *is_ss_allowed_ptr= bpf_map_lookup_elem(&is_ss_allowed_map, &key_0);
  __u64 *rtt_ptr = bpf_map_lookup_elem(&rtt_map, &key_0);
  __u64 *rtt_min_ptr = bpf_map_lookup_elem(&rtt_min_map, &key_0);


    if(!periodic_reduction_scheduled_ptr || !freeze_ended_ptr || !ssthresh_ptr || !is_ss_allowed_ptr ||!rtt_ptr ||!rtt_min_ptr){
         bpf_printk("Failed to read a map Line 1425");
      return TC_ACT_OK;
    }



  if(*reduction_ptr){
    /* we are within an RTT for which window is being reduced, do not change window,
      but try to reduce the amount of data previously decided (rcwnd_scale) */

            if (*rcwnd_scale_ptr > 0){ /* adjust window with received packets */
                  //how much we have to reduce the window according to ws
                  int decrease_ws=0;
                  int rest=0;
                      //creo que rcwnd_scale es lo que calculamos que hay que quitar pero
                      //que no podemos quitar de una porque no podemos superar acked. para no encojer la ventana.
                      //entonces vamos haciendo paquete por paquete.

                      if(*acked >= *rcwnd_scale_ptr){
                              //esto es porque no podemos reducir más que la cantidad de bytes
                              //del paquete que recibimos.
                              //si esta canditdad de bytes es mayor que la cantydad de bytes que se desea reducir
                              //Entonces reducimos todos los bytes deseados de golpe.

                            decrease_ws=*rcwnd_scale_ptr/window_scales_ptr->window_scale;
                            rcwnd_ok_ptr->rcwnd_ok=decrease_ws;
                            *reduction_ptr=0; //hemos terminado la reduccion! (lo dejamos indicado paq no entre en este if)
                            *recent_retransmission_ptr=0;
                            //rounding
                            rest=*rcwnd_scale_ptr%(window_scales_ptr->window_scale);
                            if((rest>0)&&(rcwnd_ok_ptr->rcwnd_ok-1>=*min_w_ptr)){
                                      (rcwnd_ok_ptr->rcwnd_ok)--;
                                      //aqui se aplica el caso en el que, el total a reducir es menos que windows_scale, entonces quitamos solo 1.
                                      //porque al ser windows_scale>rcwnd_scañe entonces decrease_ws=0.
                                      bpf_printk("1547: rcwnd_scale_ptr: %lld",*rcwnd_scale_ptr);
                                      bpf_printk("1547: rcwnd_ok: %lld",rcwnd_ok_ptr->rcwnd_ok );
                                      bpf_printk("1547: min_w_prt: %lld",*min_w_ptr );
                                      bpf_printk("rest %u", rest);
                            }

                            *rcwnd_scale_ptr=0;	//ya no nos faltan bytes por reducir
                            bpf_printk("Soy packet: %lld, rcwnd_ok: %lld, min: %lld, decrease: %lld", *packet_number, rcwnd_ok_ptr->rcwnd_ok, *min_w_ptr, decrease_ws );

                            }else{
                              //si el paquete que nos llega tiene menos bytes de los que debemos reducir, nos ajutamos
                              //a esa cantidad. (notar que ahora la que ponemos es acked, no rcwnd_scale y que la oprecaion de dividir, es para la estrategia de escalado.)
                				      decrease_ws=*acked/window_scales_ptr->window_scale;
                              rest=*acked%window_scales_ptr->window_scale;

                              if((rest>0)&&(rcwnd_ok_ptr->rcwnd_ok-1>=*min_w_ptr)){ //nos asegramos de quue la ventana final es mayor o igual que la minima
                                  decrease_ws++;
                              }

                              if(rcwnd_ok_ptr->rcwnd_ok-decrease_ws>=*min_w_ptr){  //nos aseguramos de que no bajamos por debajo de el minimo.
                                  (rcwnd_ok_ptr->rcwnd_ok)-=decrease_ws;
                				      (*rcwnd_scale_ptr)-=(decrease_ws*window_scales_ptr->window_scale);

                              bpf_printk("1571 Soy packet: %lld, rcwnd_ok: %lld, min: %lld, decrease_ws: %lld", *packet_number, rcwnd_ok_ptr->rcwnd_ok, *min_w_ptr, decrease_ws );
                              bpf_printk("1571: rcwnd_scale_ptr: %lld",*rcwnd_scale_ptr);
                              bpf_printk("rest %u", rest);

                              }
                              else {
                                  rcwnd_ok_ptr->rcwnd_ok=*min_w_ptr;
                              }

                              if((*rcwnd_scale_ptr<=0)||(rcwnd_ok_ptr->rcwnd_ok==*min_w_ptr)){
                                  *reduction_ptr=0;
                                  *rcwnd_scale_ptr=0;
                                  *recent_retransmission_ptr=0;
                              }
                			}
                    update_state("reducing");

              }else if(*rcwnd_scale_ptr==0){
                      // Some times the window to reduce is so small that is is 0. A reduction was
                      // requested, but the amount was 0.
          			*reduction_ptr=0;
                bpf_printk("aquiii");

          			update_state("reducing");
          		}

    //----------------------------------
/*
    Tenemos que ver si es una retransmision reciente para actuar en consecuencia solo 1 vez.
    Tras la primera retransmisión, el sistema actualiza el umbral de inicio lento (ssthresh),
    pero no reduce inmediatamente la ventana.
    Si ocurre otra condición que indica congestión (posiblemente una nueva retransmisión u otra señal de congestión),
    el sistema se prepara para reducir la ventana en las siguientes iteraciones
*/
    //----------------------------------

          if(*is_retransmission && !(*recent_retransmission_ptr)){
              *recent_retransmission_ptr=1;
              //if there is a loss and we are in a periodic reduction update ssthresh to rcwnd_ok/2
              if(!(*periodic_reduction_scheduled_ptr)&&!(*freeze_ended_ptr)){

                  __u64 ssthresh_aux=rcwnd_ok_ptr->rcwnd_ok/2;

                  if(ssthresh_aux>=*min_w_ptr)
                    *ssthresh_ptr=ssthresh_aux;
                  else
                    *ssthresh_ptr=*min_w_ptr;

                  update_state("perio_red+retr");
              }
              else {
              //we drop to minimum and grow in ss
              //no estamos en Periodic reduction, ha habido otra perdida, actuamos bajando la ventana al minimo.
              //pero como no podemos hacerlo de golpe, calculamos el rcwnd_scale y vamos haciendolo por cada paquete que llega.

              		__u64 ssthresh_aux=rcwnd_ok_ptr->rcwnd_ok/2;//marcamos el peligro en la mitad de la ventana.
              		*rcwnd_scale_ptr = (rcwnd_ok_ptr->rcwnd_ok - *min_w_ptr)*window_scales_ptr->window_scale; //cantidad de bytes que hay
                  //que reducir para llegar al minimo

          				if(ssthresh_aux>=*min_w_ptr)
          					   *ssthresh_ptr=ssthresh_aux;
                  else
                        *ssthresh_ptr=*min_w_ptr;

                      *reduction_ptr=1; //entramos en reduccion.
                      *is_ss_allowed_ptr=1; //entramos en ss
                      bpf_printk("AHORA1: Tsval: %llu, Tsecr: %llu", timestamp->tsval, timestamp->tsecr);
                      update_state("retrans");

                  // rtt values for packets already received do not have any meaning
                  clear_rtt_table();
                  *rtt_ptr = *rtt_min_ptr;

            	}
            }
  }//SEE IF HE HAVE TO MAINTAIN THE WINDOW
	  else if(reception_time<*keep_window_time_ptr){

            //Do nothing
            update_state("frozen");

            //Si hay una retransmisión durante este congelamiento, se actualiza el umbral ssthresh.

    		if(*is_retransmission){

                    __u64 ssthresh_aux=rcwnd_ok_ptr->rcwnd_ok/2;

                        if(ssthresh_aux>=*min_w_ptr)
                		    *ssthresh_ptr=ssthresh_aux;
                		else
                            *ssthresh_ptr=*min_w_ptr;

                    update_state("frozen+retrans");
            }

	}else{
            //CHANGE THE WINDOW  (si no estamos en reduccion, la ventana no esta congelada, y hemos superado keep_window_time)
            //See if we have just done a periodic slowdown to freeze the window
            //sabremos que acabamos de hacer un periodic slowdown, porque solo caundo acabamos de hacerlo, freez_ended=0.
            // to know if we have to freeze the window after a periodic reduction
            //aqui nos encargamos de actualizar el keepwindowtime y, inmediatamente despues, cogengelar.
            //en el if de arriba para el siguiente paquete que llega




            if(!*freeze_ended_ptr){

                /*
                la ventana acaba de salir de un estado de "reducción periódica" y
                ahora debe "congelarse" por cierto tiempo. La ventana se congela por un tiempo de 2 rtts:
                */

                *keep_window_time_ptr=reception_time +2*(*rtt_ptr);
                update_state("freezing");
                *freeze_ended_ptr=1;
                if(*is_retransmission){

                    __u64 ssthresh_aux=rcwnd_ok_ptr->rcwnd_ok/2;

                    if(ssthresh_aux>=*min_w_ptr)
                        *ssthresh_ptr=ssthresh_aux;
                    else
                        *ssthresh_ptr=*min_w_ptr;

                    update_state("freeze+retrans");
                }

            }//---------------------------------------------------------------cambiado sin entender

            //CASO: no estamos en redución y la ventana no esta congelada

            //See if we have to do a periodic slowdown
            //para ver si hay que hacer slowdown, la pregunta es, ¿se cumple que
            //no estamos en el primer ss y ha llegado el timepo de hacer slowdown y hay alguno programado?
            //el periodic slowdown es algo que se programa para hacer Cada periodic_reduction_time.

            else if((!*is_first_ss_ptr)&&(reception_time> periodic_reduction_ptr->periodic_reduction_time)&&*periodic_reduction_scheduled_ptr){

                *rcwnd_scale_ptr = (rcwnd_ok_ptr->rcwnd_ok - *min_w_ptr)*window_scales_ptr->window_scale;
                // TCP's receive window may force rcwn_ok to be 1 MSS. Do not reduce.
                if (*rcwnd_scale_ptr < 0) {
                    *rcwnd_scale_ptr = 0;
                }

                *reduction_ptr=1; //Activamos reduccion.
                periodic_reduction_ptr->begin_periodic_reduction_time=reception_time; //registramos cuando empieza.
                //set ssthresh to th current rcwnd
                *ssthresh_ptr=rcwnd_ok_ptr->rcwnd_ok;
                update_state("perio_red");
                *freeze_ended_ptr=0;
                *is_ss_allowed_ptr=1;
                *periodic_reduction_scheduled_ptr=0; //desactivamos porque la gastamos ahora.

                if(*is_retransmission){
                    __u64 ssthresh_aux=rcwnd_ok_ptr->rcwnd_ok/2;

                    if(ssthresh_aux>=*min_w_ptr)
                        *ssthresh_ptr=ssthresh_aux;
                    else
                        *ssthresh_ptr=*min_w_ptr;

                    update_state("perio_red+retr");
                }

            }
            //Se if there has been a packet loss
            else if(*is_retransmission){
                __u64 ssthresh_aux=rcwnd_ok_ptr->rcwnd_ok/2;

                      *recent_retransmission_ptr=1;

                if(ssthresh_aux>=*min_w_ptr)
                    *ssthresh_ptr=ssthresh_aux;
                else
                    *ssthresh_ptr=*min_w_ptr;


                // Option 1: reduce to minimum window value
                // rcwnd_scale = (rcwnd_ok - minimum_window)*window_scale;
                // option 2: reduce current window to half

                *rcwnd_scale_ptr = (rcwnd_ok_ptr->rcwnd_ok - *ssthresh_ptr) * window_scales_ptr->window_scale;     //aqui es el

                *reduction_ptr=1;
                *is_ss_allowed_ptr=1;
                bpf_printk("AHORA2:TSval: %llu, TSecr: %llu", timestamp->tsval, timestamp->tsecr);
                update_state("retrans");

                //we have to schedule first periodic reduction if the loss ocurred while first slow start
                if(*is_first_ss_ptr){

                  *is_first_ss_ptr=0;
                    //set first reduction
                    periodic_reduction_ptr->periodic_reduction_time=reception_time+2*(*rtt_ptr);
                    *periodic_reduction_scheduled_ptr=1;

                 }

                  // rtt values for packets already received do not have any meaning
                  clear_rtt_table();
            }

            //SI NO HAY PERDIDA DE PAQUETES, LA VENTANA NO ESTA CONGELADA, Y NO ES EL MOMENTO DE HACER EL PERIODIC SLOWDOWN, ENTONCES
                //FUNCOINAMEINTO NORAML.

            		//See if we have to decrease the window
                 #ifdef RLEDBAT2
            else if((*queue_delay_ptr>*target2)&&((!*is_first_ss_ptr)||(*periodic_reduction_scheduled_ptr))){
              //bpf_printk("Entro en el if del ifdef ");

                 #else
            // regular rledbat //aqui basicamente entramos cuando superamos el target, para activar la reduccion.
            else if((*queue_delay_ptr>TARGET)&&((!*is_first_ss_ptr)||(*periodic_reduction_scheduled_ptr))){
                //bpf_printk("Entro en el else del ifdef");
                #endif

                      if(reception_time>=*next_decrease_time_ptr){
                        //bpf_printk("Entro en el if_reception");
                              __s64 decrease_aux=0;
                              *is_ss_allowed_ptr=0;

                         //standard decrease
                            //rledbat and RLEDBAT2-specific
                            //W += max( (GAIN - Constant * W * (delay/target - 1)), -W/2) )
                             decrease_aux=bytes_to_decrease_rledbat(rcwnd_ok_ptr->rcwnd_ok,window_scales_ptr->window_scale,*queue_delay_ptr,*rtt_min_ptr);

                               bpf_printk("decrease returned: %lld\n, window_scale: %d, ventana: %lld, ueue_delay :%lld, rtt_min :%lld ",decrease_aux, window_scales_ptr->window_scale, rcwnd_ok_ptr->rcwnd_ok, *queue_delay_ptr, window_scales_ptr->window_scale);

                              //we can still increase,check if we decrease to set the reduction
                               if(decrease_aux<0){
                                    if(rcwnd_ok_ptr->rcwnd_ok>*min_w_ptr){
                                            *rcwnd_scale_ptr+=-1*decrease_aux;
                                            if(*rcwnd_scale_ptr>=window_scales_ptr->window_scale){
                                                      update_state("decrease");
                                                    //assure window is at least 2mss if it is not, set the window to 2mss
                                                    if( ( (rcwnd_ok_ptr->rcwnd_ok-(*rcwnd_scale_ptr)) / window_scales_ptr->window_scale) < (*min_w_ptr)){
                                                            *rcwnd_scale_ptr=(rcwnd_ok_ptr->rcwnd_ok-(*min_w_ptr)) * window_scales_ptr->window_scale;
                                                            update_state("decr2big");
                                                      }
                                                            *reduction_ptr=1;
                                                            *next_decrease_time_ptr=reception_time + (*rtt_ptr);
                                            }//not enough to reduce but we will ceil in the reduction, reducing 1 ws
                                            else{
                                            *reduction_ptr=1;
                                            bpf_printk("Soy el paquete: %lld", *packet_number);
                                            bpf_printk("Estoy en la linea 1803: rcwnd_ok: %lld, min: %lld, decrease: %lld",rcwnd_ok_ptr->rcwnd_ok, *min_w_ptr, decrease_aux );
                                            *next_decrease_time_ptr=reception_time +(*rtt_ptr);
                                            update_state("declessWS");
                                            }
                                    }
                                    else{
                                            *reduction_ptr=0;
                                            update_state("min_window");
                                        }
                                    // rtt values for packets already received do not have any meaning (as it will take an RTT to recover).
                                    // I may comment the following... and then some packets with larger RTT than the current one will be taken into account. But this is a problem at the beginning of the communication, so I clear it.
                                    // 20220701 comment again
                                    clear_rtt_table();
                                }
                                //we still grow: note that the formula for bytes to decrease may result in positive values
                                // if the queuing delay excedent is small
                                else {
                                        int increase_aux=0;
                                        *increase_bytes_ptr+=decrease_aux;
                                        if(*increase_bytes_ptr >= window_scales_ptr->window_scale){
                                                increase_aux=*increase_bytes_ptr / window_scales_ptr->window_scale;
                                                rcwnd_ok_ptr->rcwnd_ok+=increase_aux;
                                                *increase_bytes_ptr -= increase_aux*window_scales_ptr->window_scale;
                                        }
                                        update_state("growb4red");
                                    }
                                    //there's a case when we haven't scheduled a periodic_reduction & we are over TARGET so we have to check if there's one scheduled
                                    if(reception_time>periodic_reduction_ptr->periodic_reduction_time){
                                          __u64 reduction_time;
                                          *periodic_reduction_scheduled_ptr=1;
                                          periodic_reduction_ptr->end_periodic_reduction_time=reception_time;
                                          reduction_time=periodic_reduction_ptr->end_periodic_reduction_time-periodic_reduction_ptr->begin_periodic_reduction_time;
                                          periodic_reduction_ptr->periodic_reduction_time=reception_time+9*reduction_time;
                                    }
                                  }
                               //if(reception_time..)
                               else{
                                  update_state("waitrtt2dec");
                               }
                      //si no hemos superado el target, seguimos creciendo, y decidimos si en ss o en CA.
                      //See how we grow//---------------
                      }
                      else{

                                  // Init, use slow start to grow
                                      #ifdef RLEDBAT2
                              if(*is_first_ss_ptr &&(*queue_delay_ptr>(3*(*target2))/4)){
                                      #else
                              if(*is_first_ss_ptr &&(*queue_delay_ptr>(3*TARGET)/4)){
                                      #endif
                              int increase_aux=0;
                              //we have completed the first slow start
                              //set the ssthesh as the current window so the next time we grow in congestion avoidance
                              *ssthresh_ptr=rcwnd_ok_ptr->rcwnd_ok;

                              *is_first_ss_ptr=0;
                              *is_ss_allowed_ptr=0;
                              //set first reduction
                              periodic_reduction_ptr->periodic_reduction_time=reception_time+2*(*rtt_ptr);
                              *periodic_reduction_scheduled_ptr=1;
                              //congestion avoidance
                                      *increase_bytes_ptr+= *acked + ((*acked/(rcwnd_ok_ptr->rcwnd_ok*window_scales_ptr->window_scale)))/gain(*rtt_min_ptr);

                              if(*increase_bytes_ptr>=window_scales_ptr->window_scale){
                                increase_aux=*increase_bytes_ptr / window_scales_ptr->window_scale;
                                rcwnd_ok_ptr->rcwnd_ok+=increase_aux;
                                *increase_bytes_ptr -= increase_aux*window_scales_ptr->window_scale;

                              }
                              update_state("slow1_end");
                            }
                            else if(rcwnd_ok_ptr->rcwnd_ok<*ssthresh_ptr&&*is_ss_allowed_ptr){

                              int increase_aux=0;
                              //rledbat slow start
                              *increase_bytes_ptr+=*acked/gain(*rtt_min_ptr);
                              if(*increase_bytes_ptr>=window_scales_ptr->window_scale){
                                increase_aux=*increase_bytes_ptr / window_scales_ptr->window_scale;
                                rcwnd_ok_ptr->rcwnd_ok+=increase_aux;
                                *increase_bytes_ptr -= increase_aux*window_scales_ptr->window_scale;
                              }
                                update_state("slow");

                            }
                                  //there is a case when the congestion window reaches its maximum and the delay is less than 3/4 target and that breaks the algorithm
                                  else if(rcwnd_ok_ptr->rcwnd_ok>=*ssthresh_ptr && *is_first_ss_ptr){
                                      int increase_aux=0;
                              //we have completed the first slow start because we cant grow more
                              rcwnd_ok_ptr->rcwnd_ok=*ssthresh_ptr;
                              *is_first_ss_ptr=0;
                              *is_ss_allowed_ptr=0;
                              //set first reduction
                              periodic_reduction_ptr->periodic_reduction_time=reception_time+2*(*rtt_ptr);
                              *periodic_reduction_scheduled_ptr=1;
                              //congestion avoidance
                                      *increase_bytes_ptr+= *acked + ((*acked/(rcwnd_ok_ptr->rcwnd_ok*window_scales_ptr->window_scale)))/gain(*rtt_min_ptr);
                              if(*increase_bytes_ptr>=window_scales_ptr->window_scale){
                                increase_aux=*increase_bytes_ptr / window_scales_ptr->window_scale;
                                rcwnd_ok_ptr->rcwnd_ok+=increase_aux;
                                *increase_bytes_ptr -= increase_aux*window_scales_ptr->window_scale;
                              }
                              update_state("slow1_fix");

                                  }
                                  else{
                              int increase_aux=0;
                                      // int to_increase=0;
                                      *is_ss_allowed_ptr=0;
                              //we need to calculate the next periodic reduction if there is not one scheduled
                              if(reception_time>periodic_reduction_ptr->periodic_reduction_time){
                                unsigned long long reduction_time;
                                *periodic_reduction_scheduled_ptr=1;
                                periodic_reduction_ptr->end_periodic_reduction_time=reception_time;
                                reduction_time=periodic_reduction_ptr->end_periodic_reduction_time-periodic_reduction_ptr->begin_periodic_reduction_time;
                                periodic_reduction_ptr->periodic_reduction_time=reception_time+9*reduction_time;
                              }

                              //congestion avoidance
                                      // to_increase=((acked*acked/(rcwnd_ok*window_scale)))/gain(rtt_min);
                                  // acked * acked may not work as intended: with TSO/GSO and GRO, packets may be larger
                                      // than 1 mss, and window may grow more than 1 mss per RTT
                                      *to_increase_CA_ptr += *acked * MSS / gain(*rtt_min_ptr);
                                      // (acked/(rcwnd_ok*window_scale))/gain(rtt_min);

                                      denominator_CA = (rcwnd_ok_ptr->rcwnd_ok*window_scales_ptr->window_scale);

                                      if (*to_increase_CA_ptr  > denominator_CA)
                                      {
                                          long int increase_CA_aux;
                                          increase_CA_aux = *to_increase_CA_ptr/ denominator_CA;
                                          *increase_bytes_ptr += increase_CA_aux;
                                          *to_increase_CA_ptr -=  increase_CA_aux*denominator_CA;
                                      }

                                      if(*increase_bytes_ptr>=window_scales_ptr->window_scale){
                                              increase_aux=*increase_bytes_ptr / window_scales_ptr->window_scale;
                                              rcwnd_ok_ptr->rcwnd_ok+=increase_aux;
                                              if(rcwnd_ok_ptr->rcwnd_ok>MAX_WINDOW) rcwnd_ok_ptr->rcwnd_ok=MAX_WINDOW;
                                              *increase_bytes_ptr -= increase_aux*window_scales_ptr->window_scale;
                                      }
                                      update_state("CA");

                                  }
                }
              }

   char  *state=get_current_state();
   if(!state)
    return TC_ACT_OK;
   bpf_printk(" read;reception_time; %lld, rtt: %lld, rtt_min: %lld",reception_time, *rtt_ptr, *rtt_min_ptr);
   bpf_printk(" window :%lld, thresh :%lld,  State: %s, is_retransmission :%lld,  to reduice: :%lld, reduction :%lld, queue_delay :%lld",rcwnd_ok_ptr->rcwnd_ok,*ssthresh_ptr, state, *is_retransmission, *rcwnd_scale_ptr, *reduction_ptr,*queue_delay_ptr);
   bpf_printk(" TARGET :%lld, rcv_wscale :%lld, acked :%lld,  window_scale :%lld, increase_bytes :%lld, gain :%lld, periodic_reduction_time :%lld",TARGET, window_scales_ptr->rcv_wscale, *acked, window_scales_ptr->window_scale, *increase_bytes_ptr, gain(*rtt_min_ptr), periodic_reduction_ptr->periodic_reduction_time );

  // bpf_printk(" window :%lld, State: %s, queue_delay: %lld",rcwnd_ok_ptr->rcwnd_ok, state, *queue_delay_ptr);


  //------------------------FALTA HACER COMPROBACIONES Y ENTENDER CODIGO


    //----------------------ANALISIS OPCIONES DEL PAQUETE RECIBIDO-----------------//


    return TC_ACT_OK;
}

///----------------------------//

char _license[] SEC("license") = "GPL";
