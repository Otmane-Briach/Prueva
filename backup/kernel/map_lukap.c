//---------------------------------TESTEO-------------------------------------//
SEC("tc")
int tc_drop1(struct __sk_buff *skb) {
    __u32 key = 0;
    long long *value;
    // Print and update last_qd_values_map
    value = bpf_map_lookup_elem(&values_map, &key);
    if (value) {
        bpf_printk("last_qd_values_map[0]: %lld\n", *value);
        *value = *value + 1;
        bpf_map_update_elem(&values_map, &key, value, BPF_ANY);
    }
    // Print and update qd_values_pointer_map
    value = bpf_map_lookup_elem(&pointer_map, &key);
    if (value) {
        bpf_printk("qd_values_pointer_map[0]: %lld\n", *value);
        *value = *value + 1;
        bpf_map_update_elem(&pointer_map, &key, value, BPF_ANY);
    }

    return TC_ACT_OK;
}
//---------------------Conc-----------------//
char _license[] SEC("license") = "GPL";
