#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/resource.h>
#include <netinet/tcp.h>

//------------------------------DEFINES---------------------------------------//
#define MAP_SIZE 20
#define BPF_OBJ_FILE "xdp_pass_kern.o"
#define VALUES_MAP_PATH "/sys/fs/bpf/tc/globals/values_map"
#define RTT_MIN_MAP_PATH "/sys/fs/bpf/tc/globals/rtt_min_map"
#define RTT_MAP_PATH "/sys/fs/bpf/tc/globals/rtt_map"
#define RCWND_OK_MAP_PATH "/sys/fs/bpf/tc/globals/rcwnd_ok_map"
#define TCP_RMEM_MAP_PATH "/sys/fs/bpf/tc/globals/tcp_rmem_map"
#define IS_FIRST_SS_MAP_PATH "/sys/fs/bpf/tc/globals/is_first_ss_map"
#define IS_SS_ALLOWED_MAP_PATH "/sys/fs/bpf/tc/globals/is_ss_allowed_map"
#define FREEZE_ENDED_MAP_PATH "/sys/fs/bpf/tc/globals/freeze_ended_map"
#define WINDOW_SCALES_MAP_PATH "/sys/fs/bpf/tc/globals/window_scales_map"
#define SSTHRESH_MAP_PATH "/sys/fs/bpf/tc/globals/ssthresh_map"

#define MAX_COUNT_RTT 10000



#define KEY "/sys/fs/bpf/tc/globals/key_timestamps"
#define STATE "/sys/fs/bpf/tc/globals/state_map"
//#define TIME_RTT_ARRAY_MAP_PATH "/sys/fs/bpf/tc/globals/time_rtt_array_map"
//#define TSVAL_RTT_ARRY_MAP_PATH "/sys/fs/bpf/tc/globals/tsval_rtt_array_map"


#define TCP_RMEM_PATH "/proc/sys/net/ipv4/tcp_rmem"
#define MAX_LONG_LONG 9223372036854775803LL
#define TCP_HEADER_SIZE 20
#define MSS 1448 //unidad de ventana
#define INIT_WINDOW 1*MSS //Ventana inicial
#define MAX_WINDOW 65535

struct rcwnd_ok_str {
  // effective reception window
  __u64 rcwnd_ok; //----------------Solo este valor.
  // Can be used for debug. The write module imports it but doesn't use it
  __u64 rcwnd_ok_before;
};


#define MAX_SIZE 15 // Asegúrate de que esta definición coincida con la que usaste en la definición del mapa

void update_state_user_space(int fd_state, const char *new_state) {
    __u32 key = 0;
    char state_value[MAX_SIZE] = {0}; // Inicializa todo a cero

    // Copia la cadena new_state a state_value, pero asegúrate de no desbordar el buffer.
    snprintf(state_value, MAX_SIZE, "%s", new_state);

    if (bpf_map_update_elem(fd_state, &key, state_value, BPF_ANY)) {
        fprintf(stderr, "Failed to update state map\n");
        return;
    }
}

int main(int argc, char **argv) {
	__u32 key;
	long long value;


//-------------------------OBTENCION DE LOS FILES DESCRIPTORS-----------------//
	// Get the map file descriptors
	int fd_values = bpf_obj_get(VALUES_MAP_PATH);
	if (fd_values < 0) {
		fprintf(stderr, "Failed to open map: %s\n", VALUES_MAP_PATH);
		return EXIT_FAILURE;
	}

  int fd_rtt_min = bpf_obj_get(RTT_MIN_MAP_PATH);
  if (fd_rtt_min < 0) {
    fprintf(stderr, "Failed to open map: %s\n", RTT_MIN_MAP_PATH);
    return EXIT_FAILURE;
  }

	int fd_rtt = bpf_obj_get(RTT_MAP_PATH);
  if (fd_rtt < 0) {
    fprintf(stderr, "Failed to open map: %s\n", RTT_MAP_PATH);
    return EXIT_FAILURE;
  }

	int fd_tcp_rmem = bpf_obj_get(TCP_RMEM_MAP_PATH);
	if (fd_tcp_rmem < 0) {
		fprintf(stderr, "Failed to open map: %s\n", TCP_RMEM_MAP_PATH);
		return EXIT_FAILURE;
	}

	int fd_is_first_ss = bpf_obj_get(IS_FIRST_SS_MAP_PATH);
	if (fd_is_first_ss < 0) {
		fprintf(stderr, "Failed to open map: %s\n", IS_FIRST_SS_MAP_PATH);
		return EXIT_FAILURE;
	}

	int fd_is_ss_allowed = bpf_obj_get(IS_SS_ALLOWED_MAP_PATH);
	if (fd_is_ss_allowed < 0) {
		fprintf(stderr, "Failed to open map: %s\n", IS_SS_ALLOWED_MAP_PATH);
		return EXIT_FAILURE;
	}

	int fd_freeze_ended = bpf_obj_get(FREEZE_ENDED_MAP_PATH);
	if (fd_freeze_ended < 0) {
		fprintf(stderr, "Failed to open map: %s\n", FREEZE_ENDED_MAP_PATH);
		return EXIT_FAILURE;
	}
	int fd_rcwnd_ok_map = bpf_obj_get(RCWND_OK_MAP_PATH);
	if (fd_rcwnd_ok_map < 0) {
		fprintf(stderr, "Failed to open map: %s\n", RCWND_OK_MAP_PATH);
		return EXIT_FAILURE;
	}
	int fd_window_scales_map = bpf_obj_get(WINDOW_SCALES_MAP_PATH);
	if (fd_window_scales_map < 0) {
		fprintf(stderr, "Failed to open map: %s\n", WINDOW_SCALES_MAP_PATH);
		return EXIT_FAILURE;
	}






  int fd_key = bpf_obj_get(KEY);
  if (fd_values < 0) {
    fprintf(stderr, "Failed to open map: %s\n", KEY);
    return EXIT_FAILURE;
  }

  int fd_state = bpf_obj_get(STATE);
  if (fd_values < 0) {
    fprintf(stderr, "Failed to open map: %s\n", STATE);
    return EXIT_FAILURE;
  }



 	int fd_ssthresh = bpf_obj_get(SSTHRESH_MAP_PATH);
  if (fd_ssthresh < 0) {
    fprintf(stderr, "Failed to open map: %s\n", SSTHRESH_MAP_PATH);
    return EXIT_FAILURE;
  }
   


//-----------------------------------INITIALICIAR----------------------------//

//INITIALIZE LAS_QD_VALUES
  value = MAX_LONG_LONG;
  for (key = 0; key < MAP_SIZE; key++) {
      if (bpf_map_update_elem(fd_values, &key, &value, BPF_ANY)) {
          fprintf(stderr, "Failed to update map: %s\n", VALUES_MAP_PATH);
          return EXIT_FAILURE;
      }
  }

  key = 0;
  value = MAX_LONG_LONG;
  if (bpf_map_update_elem(fd_rtt_min, &key, &value, BPF_ANY)) {
			fprintf(stderr, "Failed to update map: %s\n", RTT_MIN_MAP_PATH);
      return EXIT_FAILURE;
  }

	key = 0;
	value = MAX_LONG_LONG;
	if (bpf_map_update_elem(fd_rtt, &key, &value, BPF_ANY)) {
			fprintf(stderr, "Failed to update map: %s\n", RTT_MIN_MAP_PATH);
			return EXIT_FAILURE;
	}

  key = 0;
	value = 0;
	if (bpf_map_update_elem(fd_key, &key, &value, BPF_ANY)) {
			fprintf(stderr, "Failed to update map: %s\n", RTT_MIN_MAP_PATH);
			return EXIT_FAILURE;
	}

update_state_user_space(fd_state, "undef");

key = 0;
	value = MAX_WINDOW;		
	if (bpf_map_update_elem(fd_ssthresh, &key, &value, BPF_ANY)) {
			fprintf(stderr, "Failed to update map: %s\n", RTT_MIN_MAP_PATH);
			return EXIT_FAILURE;
	}


//------------------------------


//-----------------------------
struct rcwnd_ok_str rcwnd_ok_value={0,0}; // Allocating on stack instead of pointer.
key = 0; // Assuming you are using the key 0 since max_entries is 1 and no key was provided.

rcwnd_ok_value.rcwnd_ok = INIT_WINDOW;

if (bpf_map_update_elem(fd_rcwnd_ok_map, &key, &rcwnd_ok_value, BPF_ANY)) {
	fprintf(stderr, "Failed to update map: %s\n", RTT_MIN_MAP_PATH); 
	return EXIT_FAILURE;
}
 printf("rcwnd_ok_value: %lli\n",rcwnd_ok_value.rcwnd_ok);


//------------------------------------

	value=1;
	if (bpf_map_update_elem(fd_is_first_ss, &key, &value, BPF_ANY)) {
			fprintf(stderr, "Failed to update map: %s\n", RTT_MIN_MAP_PATH);
			return EXIT_FAILURE;
	}

	if (bpf_map_update_elem(fd_is_ss_allowed, &key, &value, BPF_ANY)) {
			fprintf(stderr, "Failed to update map: %s\n", RTT_MIN_MAP_PATH);
			return EXIT_FAILURE;
	}


	if (bpf_map_update_elem(fd_freeze_ended, &key, &value, BPF_ANY)) {
			fprintf(stderr, "Failed to update map: %s\n", RTT_MIN_MAP_PATH);
			return EXIT_FAILURE;
	}


	if (bpf_map_update_elem(fd_window_scales_map, &key, &value, BPF_ANY)) {
			fprintf(stderr, "Failed to update map: %s\n", RTT_MIN_MAP_PATH);
			return EXIT_FAILURE;
	}


	//------------------------------

	printf("Mapas inicializados\n\n");
//--------------------------------PRINT---------------------------------------//




//obtener valores sysctl_rmem
FILE *fp;
 int tcp_rmem_values[3];

 // Abrir el archivo para lectura
 fp = fopen(TCP_RMEM_PATH, "r");
 if (!fp) {
		 perror("Error al abrir el archivo");
		 return 1;
 }

 // Leer los valores
 if (fscanf(fp, "%d %d %d", &tcp_rmem_values[0], &tcp_rmem_values[1], &tcp_rmem_values[2]) != 3) {
		 perror("Error al leer los valores");
		 fclose(fp);
		 return 1;
 }

 // Cerrar el archivo
 fclose(fp);

 // Imprimir los valores para verificar
 printf("tcp_rmem values:\n");
 printf("Min: %d\n", tcp_rmem_values[0]);
 printf("Default: %d\n", tcp_rmem_values[1]);
 printf("Max: %d\n", tcp_rmem_values[2]);

 key = 0;
 struct tcp_rmem {
   __u32 min_buff;
   __u32 def_buff;
   __u32 max_buff;
 };

 struct tcp_rmem values;
 values.min_buff=tcp_rmem_values[0];
 values.def_buff=tcp_rmem_values[1];
 values.max_buff=tcp_rmem_values[2];

 if (bpf_map_update_elem(fd_tcp_rmem, &key, &values, BPF_ANY)) {
		 fprintf(stderr, "Failed to update fd_tcp_rmem\n");
		 return EXIT_FAILURE;
 }

	return EXIT_SUCCESS;
}
