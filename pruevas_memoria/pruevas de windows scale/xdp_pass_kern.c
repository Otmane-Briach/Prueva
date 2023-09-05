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
#define TARGET 60LL*6 //60ms
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

#define max_t(type, x, y) ({    \
    type __x = (x);             \
    type __y = (y);             \
    __x > __y ? __x : __y;      \
})

//----------------------------VVARIABLES GLOBALES-----------------------------//

//----------------------------INICIALIZADOS A CERO----------------------------//

// current pointer to last_qd_values
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} pointer_map SEC(".maps");

struct eth_hdr {
  	unsigned char   h_dest[ETH_ALEN];
  	unsigned char   h_source[ETH_ALEN];
  	unsigned short  h_proto;
  };

struct tcp_ts_option {
    __s64 tsval;
    __s64 tsecr;
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
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} tsval_rtt__map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
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
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} tsecr_already_checked_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, long);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} queue_delay SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} packet_number_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
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
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} seq_map SEC(".maps");

// number bytes acked
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
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


struct w_scale{
  //scaling factor (exponent)
  __u16 rcv_wscale;
  //scaling factor (bytes)
  __u32 window_scale;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct w_scale);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} window_scales_map SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __s32);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} increase_bytes_map SEC(".map");

// will be set to MIN_REDUCTION_BYTES / window_scale:
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} min_w_map SEC(".maps");

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
  // effective reception window
  __u64 rcwnd_ok;
  // Can be used for debug. The write module imports it but doesn't use it
  __u64 rcwnd_ok_before;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct rcwnd_ok_str);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rcwnd_ok_map SEC(".maps");








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
  __u64 *value;
  value = bpf_map_lookup_elem(&values_map, &key);
  if (value) {
      bpf_printk("last_qd_values_map[%u] = %lld\n", key, *value);
  }
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
//Cuando el host A envia un segmento, inlcuye la hora actual en el ts_val
//eso lo guarda en el array tsval_rtt.
//Cuando el host B  recibe el paquete, y envia un ack,
//en este segmento incluye el TSecr, y le da un valor igual al de TSval que recibió.
//De esta manera el host A teniendo el TSval=hora de envio y Tla hora registrada de
//cuando le llego el el segmento de TSecr=Tsvall,
//Ya tiene la hora de ida y la hora de recepción. Se hace la resta y eso es el rtt.
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

static void get_TSecr(struct tcphdr *tcph, void *data, void *data_end) {

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

    if (size < 2 || p + size > end || p + size > data_end) {
        return;
    }

    if (kind == 8 && size == 10) { // Opción de timestamp
      timestamp_encontrado=true;
        if (p + 8 > end || p + 8 > data_end) { // Comprobar que hay suficientes bytes para TSval y TSecr
            return;
        }

        timestamp->tsval = bpf_ntohl(*(__u32 *)(p)); //ya puedo avanzar
        timestamp->tsecr = bpf_ntohl(*(__u32 *)(p + 4));

        break; // Terminar el bucle después de encontrar la opción de timestamp
    }
    p += (size - 2);
}

if (timestamp_encontrado) {
  bpf_printk("TSval: %u, TSecr: %u", timestamp->tsval, timestamp->tsecr);
} else {
  bpf_printk("El paquete recibido no tiene opciones");
}
  return;
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

        //si size es menor que 2, entonces es una opcion MAL FORMADA.
        if (size < 2 || p + size > end || p + size > data_end) {
            return 0;
        }

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

static __u64 bytes_to_decrease_rledbat(__s64 window,__s64 scale, __s64 queue_delay,__s64 rtt_min){

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

    __s64 window_size=window*scale;
	__s64 diff=0;
	__s64 gain_val=0;
	__s64 aux=0;
	__s64 num=0;
	__s64 den=0;
	__s64 decrease=0;
	__s64 window_half=0;

    //diff es la diferencia entre el queue_delay actual y un valor
    //objetivo (TARGET o target2 dependiendo de si RLEDBAT2 está definido o no).
    //Esta diferencia indica cuánto excede el retraso actual el objetivo deseado.

    #ifdef RLEDBAT2
        diff = queue_delay - target2;
    #else
        diff=queue_delay-TARGET; //el target es 60 ms
    #endif

	gain_val=gain(rtt_min);   //gain = 1 / (min (16,(2*TARGET/base))
	aux=gain_val*CONSTANT_MULTIPLIER*window_size; //CONST_MULTI=1

    //Calculamos numerador y denominador de la fraccion:
    //(Constant_divider*Target - gain_divider*constant_num*window*(delay-target))/(gain_divider*constant_divider*target)

    #ifdef RLEDBAT2
      num=CONSTANT_DIVIDER* target2 -aux*diff; //si el delay es mayor que el target se hace negativa en propocion a la diferencia.
	    den=gain_val*CONSTANT_DIVIDER* target2;
    #else
	    num=CONSTANT_DIVIDER*TARGET-aux*diff;
	    den=gain_val*CONSTANT_DIVIDER*TARGET;
    #endif

	decrease=num/den;
	window_half=-1*(window_size/2); //limite inferior para la disminución de la ventana

    bpf_printk("decrease_rledbat aux:%lld num:%lld, den:%lld window_size:%llu gain:%llu window_half:%lld \n", aux, num, den, window_size, gain_val, window_half);

    if (decrease>=window_half){
    bpf_printk("Mayor que half");
      return decrease;
	  }else{
    bpf_printk("Menor que half, retornamos half %ld\n", window_half);
      return window_half;
    }
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
  if(!seq_values)
    return TC_ACT_OK;

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


  bpf_printk("packet_number: %lld\n", *packet_number);
  *packet_number = *packet_number + 1;
  bpf_map_update_elem(&packet_number_map, &key_0, packet_number, BPF_ANY);


  get_TSecr(tcph, data, data_end);

  //check if this packet is a retransmission
  //nos fijamos en el numero de secuencia y el valor de ts_val
  /*de entre los que recibimos con un numero de secuencia menor o igual que el ultimo
    parquete recibido, los que tienen un tsval mayor que el del ultimo es que son retranmisiones.
    */


  //obtenemos los punteros que apuntan a los mapas.
  //struct seq *seq_values = bpf_map_lookup_elem(&seq_map, &key_0);
  __u32 *is_retransmission = bpf_map_lookup_elem(&is_retransmission_map, &key_0);
  __u64 *tsval_rtt = bpf_map_lookup_elem(&tsval_rtt__map, &key_0);
  __u64 *tsval_rtt_old = bpf_map_lookup_elem(&tsval_rtt_old_map, &key_0);

  //Check para el acceso
  if(!is_retransmission || !tsval_rtt || !tsval_rtt_old){
    return TC_ACT_OK;
  }

  if((seq_values->last_seq <= seq_values->last_seq_old) && (*tsval_rtt >= *tsval_rtt_old)){
    //  bpf_printk("Es una retransmision, last_seq: %lu, last_seq_old: %lu", seq_values->last_seq, seq_values->last_seq_old );
  		*is_retransmission=1;
  }else{
      //bpf_printk("No una retransmision, last_seq: %lu, last_seq_old: %lu", seq_values->last_seq, seq_values->last_seq_old);
      *is_retransmission=0;
  	  seq_values->last_seq_old=seq_values->last_seq;
  }
 if (*tsval_rtt != *tsval_rtt_old){
      *tsval_rtt_old = *tsval_rtt;
  }



  //update global variables rtt and rtt_min
  struct tcp_ts_option *timestamp = bpf_map_lookup_elem(&timestamps_map, &key_0);
  if(!timestamp){
    return TC_ACT_OK;
  }
  min_rtt(timestamp->tsecr,reception_time);

  //acked= #bytes de datos que han venido en el paquete.
  //doff suele ser igual a 5, es la cantidad de palabras de 32 bits que tenemos.
  __u32 *acked=bpf_map_lookup_elem(&acked_map, &key_0);
  if(!acked){
    return TC_ACT_OK;
  }

  *acked = bpf_ntohs(iph->tot_len) - (tcph->doff * 4) - (iph->ihl * 4);

// bpf_printk("Acked: %d\n", *acked);
//  bpf_printk("iph->tot_len: %d\n",  bpf_ntohs(iph->tot_len) );
//  bpf_printk("tcph->doff * 4: %d\n",(tcph->doff * 4) );
//  bpf_printk("iph->ihl * 4:  %d\n",(iph->ihl * 4));


  __u64 *rtt=bpf_map_lookup_elem(&rtt_map, &key_0);
  __u64 *rtt_min=bpf_map_lookup_elem(&rtt_min_map, &key_0);
  __u64 *queue_delay=bpf_map_lookup_elem(&rtt_min_map, &key_0);

  if(!rtt_min || !rtt || !queue_delay)
   return TC_ACT_OK;

  *queue_delay = *rtt - *rtt_min;
  //bpf_printk("queue_delay: %lu", *queue_delay);
  //bpf_printk("rtt:  %lu\n",*rtt);
 //bpf_printk("rtt_min  %lu\n",*rtt_min);

  #ifdef RLEDBAT2
      // compute RLEDBAT2-specific target2 variable
      __u64 *target2=bpf_map_lookup_elem(&target2_map, &key_0);
      if(!target2)
        return TC_ACT_OK;

      if (*rtt_min < TARGET) {
          *target2 = rtt_min;
      }
      else {
          *target2 = TARGET;
      }
  #endif

  // Take the min of the last LAST_QDS values
  *queue_delay = qd_min_lastN(*queue_delay);


  // Next we consider all the cases relevant for rledbat behavior: first packet,
  // there is a retransmission, qd is too high, periodic slowdown to measure rttmin, etc.

  // Check in the first packet (that should be a SYN) that there is an WS option included.
  // The value used is discarded, compute a new value according to the available memory.
  // The value is exported to the module rewriting outgoing packets, so that it changes it for
  // all packets sent.

  // window_scale= scaling factor (bytes)
  // rcwnd_scale= number of bytes the window must be reduced
  // rcv_wscale= scaling factor (exponent)


if(1==*packet_number){
    if(getSyn(tcph) && isWSoption(tcph, data, data_end)){

      __u32 rest=0;
      __u32 tcp_rmem=0;
      __u32 sysctl_rmem_max;
      struct tcp_rmem *tcp_rmem_ptr=  bpf_map_lookup_elem(&tcp_rmem_map,&key_0);
      struct w_scale *window_scales_ptr=bpf_map_lookup_elem(&window_scales_map,&key_0);
      struct rcwnd_ok_str *rcwnd_ok_ptr=bpf_map_lookup_elem(&rcwnd_ok_map,&key_0);
      __u16 *min_w_ptr=bpf_map_lookup_elem(&min_w_map,&key_0);

      if(!tcp_rmem_ptr || !window_scales_ptr || !rcwnd_ok_ptr || !min_w_ptr)
        return TC_ACT_OK;

    tcp_rmem=tcp_rmem_ptr->def_buff;
    sysctl_rmem_max=tcp_rmem_ptr->max_buff;
    space = max_t(__u32, tcp_rmem, sysctl_rmem_max); //he creado una macro
    bpf_printk("Space %d\n", space);
    //    aqui fijamos el la escala S que vamos a usar en funcion de la memoria que tenemos.
    //    vemos cuanto espacio ademas del maximo que podemos representar
    //    con los bits de la ventana tenemos

    bpf_printk("rcv_wscale %d\n", window_scales_ptr->rcv_wscale);

    //A continuacion, calculamos la escala de la ventana para tcp


  //si el tamaño de la ventana deseada es mayor que 65535
  //(el maximo representable con 16 bits de la ventana )
  //trataremos de encontrar un factor de escala que pueda
  //representar ese valor.
     while (space > 65535 && (window_scales_ptr->rcv_wscale) < 14) {
         space >>= 1; //(dividir por 2) porque ocupamos el doble en cada incremento.
         (window_scales_ptr->rcv_wscale)++;
           bpf_printk("Space DENTRO %d\n", space);
          bpf_printk("rcv_wscale  DENTRO %d\n", window_scales_ptr->rcv_wscale);
      }

    bpf_printk("rcv_wscale %d\n", window_scales_ptr->rcv_wscale);

//-------------------------

    //Calcula el factor de escala de ventana.
    window_scales_ptr->window_scale=1<<(window_scales_ptr->rcv_wscale); // = 2^rcv_wscale
    bpf_printk("window_scale %d\n", window_scales_ptr->window_scale);

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
      bpf_printk("Ventana efectiva %d\n", rcwnd_ok_ptr->rcwnd_ok);
    // set minimum window depending on scaling
    rest=MIN_REDUCTION_BYTES%window_scales_ptr->window_scale;
    *min_w_ptr=MIN_REDUCTION_BYTES/window_scales_ptr->window_scale; //min reduction, 2 segmentos, 2896.
    //rounding (ceil)
    if(rest!=0){
      (*min_w_ptr)++;
    }

  }else {
          bpf_printk("WARNING: first packet received is not a SYN, and it should!");
          return TC_ACT_OK;
      }
  }


//----------------------ANALISIS OPCIONES DEL PAQUETE RECIBIDO-----------------//


return TC_ACT_OK;
}
///----------------------------//

char _license[] SEC("license") = "GPL";
