// SPDX-License-Identifier: GPL-2.0
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
#define BPF_OBJ_FILE "sockex1_kern.o"
#include <stdlib.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <assert.h>


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


int main(int ac, char **argv)
{
	struct bpf_object *obj;
	struct bpf_program *prog;
	int map_fd, prog_fd;
	char filename[256];
	int i, sock, err;
	FILE *f;




	obj = bpf_object__open(BPF_OBJ_FILE);
	if (libbpf_get_error(obj)) {
			fprintf(stderr, "Failed to open eBPF object file\n");
			return EXIT_FAILURE;
			}

	prog = bpf_object__next_program(obj, NULL);
	bpf_program__set_type(prog, BPF_PROG_TYPE_SOCKET_FILTER);

	err = bpf_object__load(obj);
	if (err)
		return 1;

	prog_fd = bpf_program__fd(prog);
	map_fd = bpf_object__find_map_fd_by_name(obj, "my_map");

	sock = open_raw_sock("lo");

	assert(setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd,
			  sizeof(prog_fd)) == 0);

//	f = popen("ping -4 -c5 localhost", "r");
	//(void) f;

	while(1){
		long long tcp_cnt, udp_cnt, icmp_cnt;
		int key;

		key = IPPROTO_TCP;
		assert(bpf_map_lookup_elem(map_fd, &key, &tcp_cnt) == 0);

		key = IPPROTO_UDP;
		assert(bpf_map_lookup_elem(map_fd, &key, &udp_cnt) == 0);

		key = IPPROTO_ICMP;
		assert(bpf_map_lookup_elem(map_fd, &key, &icmp_cnt) == 0);

		printf("TCP %lld UDP %lld ICMP %lld bytes\n",
		       tcp_cnt, udp_cnt, icmp_cnt);
		sleep(1);
}

	return 0;
}
