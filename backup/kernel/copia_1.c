
//todo bien pero no acepta los bucles debido a la llamad a los map_lukap.

/*
  le llega el ultimo retraso de cola medido, lo guarda
  en la matriz de los ultimos 20 y calcula cual es el minimo.
  y eso es lo que devuelve.
  */

  static long long qd_min_lastN(long long last_qd)
  {
      __u32 i;
      long long qd_min;
      __u32 key_0 = 0;
      __u32 key = 0;
      __u64 *pointer;
      pointer = bpf_map_lookup_elem(&pointer_map, &key_0);

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

      qd_min = *(__u64 *)bpf_map_lookup_elem(&values_map, &key_0);
      long long *value;
      for (i = 1; i < LAST_QDS; i++)
      {
          value = bpf_map_lookup_elem(&values_map, &i);
          if (!value)
              return -1;

          if (*value < qd_min) {
              qd_min = *value;
          }
      }
      return qd_min;
  }

//---------------------------------TESTEO-------------------------------------//
SEC("tc")
int tc_drop1(struct __sk_buff *skb) {
    __u32 key=0;
    int top=3;
  long long ret = 4;//qd_min_lastN(400);

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
//---------------------Conc-----------------//
char _license[] SEC("license") = "GPL";
