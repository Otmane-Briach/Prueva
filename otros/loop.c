struct loop_context {
    __u32 i;
    long long qd_min;
};

SEC("callback")
int loop_callback(u32 index, struct loop_context *ctx) {
    __u32 key = ctx->i;
    long long *value = bpf_map_lookup_elem(&values_map, &key);
    if (!value)
        return 1;  // Termina el ciclo si no se encuentra el valor.

    if (*value < ctx->qd_min) {
        ctx->qd_min = *value;
    }

    ctx->i++;

    return 0;  // Continúa el ciclo.
}

static long long qd_min_lastN(long long last_qd)
{
    __u32 key_0 = 0;
    __u32 key;
    __u64 *pointer = bpf_map_lookup_elem(&pointer_map, &key_0);
    if (!pointer)
        return -1;

    key = ((*pointer)%LAST_QDS);

    // Actualiza values_map directamente
    if (bpf_map_update_elem(&values_map, &key, &last_qd, BPF_ANY)) {
        bpf_printk("Update values_map failed\n");
    }
    (*pointer)++;
    // Actualiza pointer_map directamente
    if (bpf_map_update_elem(&pointer_map, &key_0, pointer, BPF_ANY)) {
        bpf_printk("Update pointer_map failed\n");
    }

    struct loop_context ctx = { .i = 1, .qd_min = *(__u64 *)bpf_map_lookup_elem(&values_map, &key_0) };

    // Ejecuta el bucle.
    bpf_loop(LAST_QDS - 1, loop_callback, &ctx, 0);

    return ctx.qd_min;
}

SEC("tc")
int tc_drop1(struct __sk_buff *skb) {
    __u32 key=0;
    int top=3;
    long long ret = qd_min_lastN(400);

    long long *value;
    for (key = 0; key < top; key++) {
        value = bpf_map_lookup_elem(&values_map, &key);
        if (value) {
            bpf_printk("last_qd_values_map[%u] = %lld\n", key, *value);
        }
    }
    bpf_printk("El menor es: %lld\n", ret);

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
