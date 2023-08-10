
//NO LLEGA A LEER LOS MAPAS PERO CREO QUE CASI.
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <arpa/inet.h>
#include <sys/resource.h>
#define MAP_SIZE 20
#define BPF_OBJ_FILE "xdp_pass_kern.o"
int main(int argc, char **argv) {

	if (argc < 2) {
		fprintf(stderr, "Por favor especifica el archivo de objeto BPF como argumento.\n");
		return EXIT_FAILURE;
	}


	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};

	if (setrlimit(RLIMIT_MEMLOCK, &r)) {
		perror("setrlimit");
		return EXIT_FAILURE;
	}


	__u32 key;
	long long value;

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
	prog = bpf_object__next_program(obj, NULL);
	bpf_program__set_type(prog, BPF_PROG_TYPE_FLOW_DISSECTOR);


	// Get the map file descriptors
	int values_map_fd, pointer_map_fd;
	values_map_fd =bpf_object__find_map_fd_by_name(obj, "values_map");
	if (values_map_fd < 0) {
		fprintf(stderr, "Failed to get descriptor for map 'values_map': %s\n", strerror(errno));
		return EXIT_FAILURE;
	}

	pointer_map_fd = bpf_object__find_map_fd_by_name(obj, "pointer_map");
	if (pointer_map_fd < 0) {
		fprintf(stderr, "Failed to get descriptor for map 'pointer_map': %s\n", strerror(errno));
		return EXIT_FAILURE;
	}

	// Read and print values from values_map
	for (key = 0; key < MAP_SIZE; key++) {
		if (bpf_map_lookup_elem(values_map_fd, &key, &value)) {
			fprintf(stderr, "Failed to read from values_map\n");
			return EXIT_FAILURE;
		} else {
			printf("values_map[%u] = %lld\n", key, value);
		}
	}

	// Read and print value from pointer_map
	key = 0;
	if (bpf_map_lookup_elem(pointer_map_fd, &key, &value)) {
		fprintf(stderr, "Failed to read from pointer_map\n");
		return EXIT_FAILURE;
	} else {
		printf("pointer_map[0] = %lld\n", value);
	}

	return EXIT_SUCCESS;
}
