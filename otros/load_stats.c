#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <locale.h>
#include <unistd.h>
#include <time.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define MAX_ENTRIES 20
#define MAP_NAME_LAST_VALUES "last_qd_values_map"
#define MAP_NAME_POINTER "qd_values_pointer_map"

void map_get_value_array(int fd, int key, long long *value)
{
    if ((bpf_map_lookup_elem(fd, &key, value)) != 0) {
        fprintf(stderr,
                "ERR: bpf_map_lookup_elem failed key:%d\n", key);
    }
}

int main(void)
{
    long long last_values[MAX_ENTRIES];
    long long pointer;

    int map_fd_values = bpf_map_get_fd_by_name(MAP_NAME_LAST_VALUES);
    if (map_fd_values < 0) {
        fprintf(stderr, "ERR: cannot find map by name: %s\n", MAP_NAME_LAST_VALUES);
        return EXIT_FAILURE;
    }

    int map_fd_pointer = bpf_map_get_fd_by_name(MAP_NAME_POINTER);
    if (map_fd_pointer < 0) {
        fprintf(stderr, "ERR: cannot find map by name: %s\n", MAP_NAME_POINTER);
        return EXIT_FAILURE;
    }

    for (int i = 0; i < MAX_ENTRIES; i++) {
        map_get_value_array(map_fd_values, i, &last_values[i]);
    }

    map_get_value_array(map_fd_pointer, 0, &pointer);

    printf("Last values:\n");
    for (int i = 0; i < MAX_ENTRIES; i++) {
        printf("%lld\n", last_values[i]);
    }

    printf("Pointer: %lld\n", pointer);

    return 0;
}
