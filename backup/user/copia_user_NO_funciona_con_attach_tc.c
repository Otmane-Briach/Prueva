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
#include <net/if.h>
#include <linux/pkt_cls.h>
#define MAP_SIZE 20
#define BPF_OBJ_FILE "xdp_pass_kern.o"
#define IF_NAME "enp0s3"
int main(int argc, char **argv) {


	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	if (setrlimit(RLIMIT_MEMLOCK, &r)) {
		perror("setrlimit");
		return EXIT_FAILURE;
	}

	// llave para acceder al programa y sus mapas.
	struct bpf_object *obj;
	obj = bpf_object__open(BPF_OBJ_FILE);
	if (libbpf_get_error(obj)) {
			fprintf(stderr, "Failed to open eBPF object file\n");
			return EXIT_FAILURE;
			}


	//obtener el programa
	struct bpf_program *prog;
	prog = bpf_object__next_program(obj, NULL);
	bpf_program__set_type(prog, BPF_PROG_TYPE_FLOW_DISSECTOR);


	//AQUI HABRIA QUE CARGARLO
	if (bpf_object__load(obj)) {
		fprintf(stderr, "Failed to load eBPF object into kernel\n");
		return EXIT_FAILURE;
	}


//------chek

	//AQUI HABRIA QUE OBTENER EL FD DEL PROG PARA "ADJUNTARLO A"
	int prog_fd;
		prog_fd = bpf_program__fd(prog);
		if (prog_fd < 0) {
			fprintf(stderr, "Failed to get BPF program fd: %s\n", strerror(errno));
			return 1;
		}


		struct bpf_tc_hook hook;
		struct bpf_tc_opts opts;

		// Attach the BPF program to the interface using TC
    int if_index = if_nametoindex(IF_NAME);
    if (if_index == 0) {
        fprintf(stderr, "Failed to get interface index for %s\n", IF_NAME);
        return EXIT_FAILURE;
    }

    memset(&hook, 0, sizeof(hook));
    hook.ifindex = if_index;
    hook.attach_point = BPF_TC_INGRESS;

    memset(&opts, 0, sizeof(opts));
    opts.prog_fd = bpf_program__fd(prog);

    if (bpf_tc_attach(&hook, &opts)) {
        fprintf(stderr, "Failed to attach BPF program to interface %s\n", IF_NAME);
        return EXIT_FAILURE;
    }




	// Get the map file descriptors
	int last_qd_values_map_fd, qd_values_pointer_map_fd;
	last_qd_values_map_fd =bpf_object__find_map_fd_by_name(obj, "values_map");
	if (last_qd_values_map_fd < 0) {
		fprintf(stderr, "Failed to get descriptor for map 'values_map': %s\n", strerror(errno));
		return EXIT_FAILURE;
	}

	qd_values_pointer_map_fd = bpf_object__find_map_fd_by_name(obj, "pointer_map");
	if (qd_values_pointer_map_fd < 0) {
		fprintf(stderr, "Failed to get descriptor for map 'pointer_map': %s\n", strerror(errno));
		return EXIT_FAILURE;
	}

	// Read and print values from last_qd_values_map
	__u32 key;
	long long value;
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
