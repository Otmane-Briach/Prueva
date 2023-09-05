
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <arpa/inet.h>
#include <sys/resource.h>
#define MAP_SIZE 20
#define BPF_OBJ_FILE "xdp_pass_kern.o"  // Cambiar a tu archivo de objeto BPF

int main() {

		struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};

	 if (setrlimit(RLIMIT_MEMLOCK, &r)) {
			 perror("setrlimit");
			 return EXIT_FAILURE;
	 }

__u32 key;
long long value;
struct bpf_object *obj;
int qd_values_pointer_map_fd; //Descriptor de archivo
// Obtener el archivo objeto bpf_object
obj = bpf_object__open(BPF_OBJ_FILE);
if (libbpf_get_error(obj)) {
    printf("Error al abrir el objeto eBPF\n");
    return EXIT_FAILURE;
}
// Cargar el objeto bpf en el kernel
if (bpf_object__load(obj)) {
    printf("Error al cargar el objeto eBPF en el kernel\n");
    return EXIT_FAILURE;
}
qd_values_pointer_map_fd = bpf_object__find_map_fd_by_name(obj, "pointer_map");
if (qd_values_pointer_map_fd < 0) {
    printf("Error al obtener el descriptor del archivo");
    return EXIT_FAILURE;
}else{
	printf("¡Mapa encontrado! \n");
}
	// Lee e imprime el valor
	key = 0;
	if (bpf_map_lookup_elem(qd_values_pointer_map_fd, &key, &value)) {
	    printf("Error al leer el valor del mapa\n");
	    return EXIT_FAILURE;
	} else {
	    printf("qd_values_pointer_map[0] = %lld\n", value);
	}
return EXIT_SUCCESS;
}
