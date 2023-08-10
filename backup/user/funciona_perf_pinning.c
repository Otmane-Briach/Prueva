//-----------------------------------------------------------------------
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
#include <net/if.h>
#include <sys/resource.h>

#define MAP_SIZE 20
#define BPF_OBJ_FILE "xdp_pass_kern.o"
#define POINTER_MAP_PATH "/sys/fs/bpf/tc/globals/pointer_map"
#define VALUES_MAP_PATH "/sys/fs/bpf/tc/globals/values_map"

int main(int argc, char **argv) {
	__u32 key;
	long long value;

	// Get the map file descriptors
	int fd_values = bpf_obj_get(VALUES_MAP_PATH);
	if (fd_values < 0) {
		fprintf(stderr, "Failed to open map: %s\n", VALUES_MAP_PATH);
		return EXIT_FAILURE;
	}

	int fd_pointer = bpf_obj_get(POINTER_MAP_PATH);
	if (fd_pointer < 0) {
		fprintf(stderr, "Failed to open map: %s\n", POINTER_MAP_PATH);
		return EXIT_FAILURE;
	}

	// Initialize values_map
	value = 500;
	for (key = 0; key < MAP_SIZE; key++) {
	    if (bpf_map_update_elem(fd_values, &key, &value, BPF_ANY)) {
	        fprintf(stderr, "Failed to update values_map\n");
	        return EXIT_FAILURE;
	    }
	}

	// Initialize pointer_map
	key = 0;
	value = 100;
	if (bpf_map_update_elem(fd_pointer, &key, &value, BPF_ANY)) {
	    fprintf(stderr, "Failed to update pointer_map\n");
	    return EXIT_FAILURE;
	}

	// Print the updated values
	while(1) {
	    key = 0;
	    if (bpf_map_lookup_elem(fd_pointer, &key, &value)) {
	        fprintf(stderr, "Failed to read from pointer_map\n");
	        return EXIT_FAILURE;
	    } else {
	        printf("pointer_map[0] = %lld\n", value);
	    }

	    sleep(1);
	}

	return EXIT_SUCCESS;
}
