/* SPDX-License-Identifier: GPL-2.0 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TRACEFS_PIPE "/sys/kernel/debug/tracing/trace_pipe"

#ifndef PATH_MAX
#define PATH_MAX   4096
#endif

int main(int argc, char **argv)
{
    FILE *stream;
    char *line = NULL;
    size_t len = 0;
    ssize_t nread;

    stream = fopen(TRACEFS_PIPE, "r");
    if (stream == NULL) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    while ((nread = getline(&line, &len, stream)) != -1) {
        char *trace_start = strstr(line, ": bpf_trace_printk: ");
        if (trace_start) {
            trace_start += strlen(": bpf_trace_printk: ");
            printf("%s", trace_start);
        }
    }

    free(line);
    fclose(stream);
    return EXIT_SUCCESS;
}
