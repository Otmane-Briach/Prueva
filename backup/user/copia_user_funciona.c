
//lee los mapas pero estan vacios, porque no esta atachhado a la interfaz ni a nada, solo esta subido en el kernel.

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


		struct bpf_object *obj;
    int last_qd_values_map_fd, qd_values_pointer_map_fd;
    __u32 key;
    long long value;

    // Load the eBPF object file
    obj = bpf_object__open(BPF_OBJ_FILE);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open eBPF object file\n");
        return EXIT_FAILURE;
    }

    // Load the BPF object into the kernel
    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load eBPF object into kernel\n");
        return EXIT_FAILURE;
    }

    // Get the map file descriptors
    last_qd_values_map_fd = bpf_object__find_map_fd_by_name(obj, "last_qd_values_map");
    if (last_qd_values_map_fd < 0) {
        fprintf(stderr, "Failed to get descriptor for map 'last_qd_values_map': %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    qd_values_pointer_map_fd = bpf_object__find_map_fd_by_name(obj, "qd_values_pointer_map");
    if (qd_values_pointer_map_fd < 0) {
        fprintf(stderr, "Failed to get descriptor for map 'qd_values_pointer_map': %s\n", strerror(errno));
        return EXIT_FAILURE;
    }


		// Read and print values from last_qd_values_map
		for (key = 0; key < MAP_SIZE; key++) {
		    if (bpf_map_lookup_elem(last_qd_values_map_fd, &key, &value)) {
		        fprintf(stderr, "Failed to read from last_qd_values_map\n");
		        return EXIT_FAILURE;
		    } else {
		        printf("last_qd_values_map[%u] = %lld\n", key, value);
		    }
		}

		// Read and print value from qd_values_pointer_map
		key = 0;
		if (bpf_map_lookup_elem(qd_values_pointer_map_fd, &key, &value)) {
		    fprintf(stderr, "Failed to read from qd_values_pointer_map\n");
		    return EXIT_FAILURE;
		} else {
		    printf("qd_values_pointer_map[0] = %lld\n", value);
		}

return EXIT_SUCCESS;

}
