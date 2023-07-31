/*include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>


#include <net/if.h>
#include <linux/if_link.h> // depend on kernel-headers installed

int find_map_fd(struct bpf_object *bpf_obj, const char *mapname)
{
	struct bpf_map *map;
	int map_fd = -1;

	// Lesson#3: bpf_object to bpf_map
	map = bpf_object__find_map_by_name(bpf_obj, mapname);
        if (!map) {
		fprintf(stderr, "ERR: cannot find map by name: %s\n", mapname);
		goto out;
	}

	map_fd = bpf_map__fd(map);
 out:
	return map_fd;
}
int main(int argc, char **argv)
{
  printf("Hla");
}
*/
//-----------------------------------------------------------------------
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

int main() {

	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};

	if (setrlimit(RLIMIT_MEMLOCK, &r)) {
		perror("setrlimit");
		return EXIT_FAILURE;
	}

	int last_qd_values_map_fd, qd_values_pointer_map_fd;
	__u32 key;
	long long value;

	// Get the map file descriptors
	last_qd_values_map_fd = bpf_map_get_fd_by_name("last_qd_values_map");
	if (last_qd_values_map_fd < 0) {
		fprintf(stderr, "Failed to get descriptor for map 'last_qd_values_map': %s\n", strerror(errno));
		return EXIT_FAILURE;
	}

	qd_values_pointer_map_fd = bpf_map_get_fd_by_name("qd_values_pointer_map");
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
