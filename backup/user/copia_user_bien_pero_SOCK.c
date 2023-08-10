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
#define MAP_SIZE 20
#define BPF_OBJ_FILE "xdp_pass_kern.o"
#include <stdlib.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
// Función open_raw_sock
static inline int open_raw_sock(const char *name) {
	struct sockaddr_ll sll;
	int sock;

	sock = socket(PF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(ETH_P_ALL));
	if (sock < 0) {
		printf("cannot create raw socket\n");
		return -1;
	}

	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = if_nametoindex(name);
	sll.sll_protocol = htons(ETH_P_ALL);
	if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
		printf("bind to %s: %s\n", name, strerror(errno));
		close(sock);
		return -1;
	}

	return sock;
}

int main(int argc, char **argv) {
/*	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};

	if (setrlimit(RLIMIT_MEMLOCK, &r)) {
		perror("setrlimit");
		return EXIT_FAILURE;
	}
*/
//----
// Creación y vinculación del socket raw
  const char *if_name = "enp0s8";  // <- nombre de la interfaz
  int sock = open_raw_sock(if_name);
  if (sock < 0) {
    fprintf(stderr, "Error al abrir el socket raw\n");
    return EXIT_FAILURE;
  }

//---
	// llave para acceder al programa y sus mapas.
	struct bpf_object *obj;
	obj = bpf_object__open(BPF_OBJ_FILE);
	if (libbpf_get_error(obj)) {
			fprintf(stderr, "Failed to open eBPF object file\n");
			return EXIT_FAILURE;
			}
//------chek

	//obtener el programa
	struct bpf_program *prog;
	prog = bpf_object__find_program_by_name(obj, "tc_drop1");
	if (libbpf_get_error(prog)) {
    	fprintf(stderr, "No se ha encontrado el programa\n");
			return EXIT_FAILURE;
	}else{
			fprintf(stderr, "SE Ha encontrado el programa\n");
	}
	//bpf_program__set_type(prog, BPF_PROG_TYPE_FLOW_DISSECTOR);


  int err=bpf_object__load(obj);
	if (err<0) {
	  	fprintf(stderr, "NO SE HA PODIDO CARGAR EL PROGRAMA\n");
	}else{
 			fprintf(stderr, "SE Ha cargado el programa\n");
	}



	int prog_fd = bpf_program__fd(prog);
  if (prog_fd < 0) {
    fprintf(stderr, "Failed to get program fd\n");
    return EXIT_FAILURE;
  }
	bpf_program__set_type(prog, BPF_PROG_TYPE_SOCKET_FILTER);
	if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd)) < 0) {
	    fprintf(stderr, "Failed to setsockopt: %s\n", strerror(errno));
	    return EXIT_FAILURE;
	  }

	/*

	const char *if_name="test";
	unsigned int if_index=if_nametoindex(if_name);
	if(if_index==0){
		printf("Error interfaz\n");
	}
	bpf_program__set_ifindex(prog, if_index);

*/
	//Cargamos el programa en la linea de comandos
  char cmd[256];
    sprintf(cmd, "tc filter add dev test ingress bpf da obj xdp_pass_kern.o sec tc ");
    system(cmd);
//		si uso esto estoy haciendo dos instancias difernetes del mismo programa.

//-------------------------LECTURA MAPAS-------------------------------------//
__u32 key;
long long value;
	// Get the map file descriptors
	struct bpf_map *values_map, *pointer_map;
values_map = bpf_object__find_map_by_name(obj, "values_map");
if (libbpf_get_error(values_map)) {
	fprintf(stderr, "Failed to get map 'values_map'\n");
	return EXIT_FAILURE;
}

pointer_map = bpf_object__find_map_by_name(obj, "pointer_map");
if (libbpf_get_error(pointer_map)) {
	fprintf(stderr, "Failed to get map 'pointer_map'\n");
	return EXIT_FAILURE;
}

	// ... (resto del código) ...

	// Bucle infinito para leer los valores del mapa
	while(1) {
	    // Read and print values from values_map
	 /*   for (key = 0; key < MAP_SIZE; key++) {
	        if (bpf_map__lookup_elem(values_map, &key, sizeof(key), &value, sizeof(value), 0)) {
	            fprintf(stderr, "Failed to read from values_map\n");
	            return EXIT_FAILURE;
	        } else {
	            printf("values_map[%u] = %lld\n", key, value);
	        }
	    }
*/
	    // Read and print value from pointer_map
	    key = 0;
	    if (bpf_map__lookup_elem(pointer_map, &key, sizeof(key), &value, sizeof(value), 0)) {
	        fprintf(stderr, "Failed to read from pointer_map\n");
	        return EXIT_FAILURE;
	    } else {
	        printf("pointer_map[0] = %lld\n", value);
	    }

	    // Wait 1 second before the next read
	    sleep(1);
	}

	return EXIT_SUCCESS;
}
