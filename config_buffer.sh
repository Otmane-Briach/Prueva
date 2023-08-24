#!/bin/bash

# Función para ajustar el tamaño del buffer del receptor
set_buffer_values() {
    MIN_BUFFER=$1
    DEFAULT_BUFFER=$2
    MAX_BUFFER=$3

    echo "Setting tcp_rmem values to: Min: $MIN_BUFFER, Default: $DEFAULT_BUFFER, Max: $MAX_BUFFER"
    sudo sysctl -w net.ipv4.tcp_rmem="$MIN_BUFFER $DEFAULT_BUFFER $MAX_BUFFER"
}

# Valores a establecer para tcp_rmem
MIN_VAL=4096
DEFAULT_VAL=121212
MAX_VAL=1313121

# Llama a la función para ajustar los valores de tcp_rmem
set_buffer_values $MIN_VAL $DEFAULT_VAL $MAX_VAL


