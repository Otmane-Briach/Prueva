import matplotlib.pyplot as plt
import re

# Extraer los valores de 'queue_delay', 'window', y 'state' del archivo
queue_delays_new = []
window_values_new = []
states_new = []

with open("/home/otman/TC/trazas/R1_sbuffer300ms_latency30ms_10mbps3.txt", "r") as file:
    for line in file:
        match_queue_delay = re.search(r'queue_delay\s*:\s*(\d+)', line)
        match_window = re.search(r'window\s*:\s*(\d+)', line)
        match_state = re.search(r'State:\s*(\w+)', line)
        
        if match_queue_delay:
            queue_delays_new.append(int(match_queue_delay.group(1)))
        if match_window and match_state:
            window_values_new.append(int(match_window.group(1)))
            states_new.append(match_state.group(1))

# Graficar los valores de 'queue_delay'
plt.figure(figsize=(18, 7))
plt.plot(queue_delays_new, label='Queue Delay (ns)', color='blue', linewidth=1.5, alpha=0.8)
plt.axhline(y=60000000, color='r', linestyle='--', label='60ms Target')

# Títulos, etiquetas y leyenda
plt.title('Queue Delay VS time', fontsize=18, pad=20)
plt.xlabel('Time (Arbitrario)', fontsize=14, labelpad=15)
plt.ylabel('Queue Delay (ns)', fontsize=14, labelpad=15)
plt.legend(fontsize=12, loc='upper left')
plt.grid(True)
plt.tight_layout()
plt.yscale('log')  # Using a logarithmic scale for the y-axis to clearly visualize the changes

# Anotar la línea de 60ms
plt.annotate('60ms', xy=(len(queue_delays_new) * 0.1, 60000000), xytext=(len(queue_delays_new) * 0.1, 60000000 * 5),
             arrowprops=dict(facecolor='black', arrowstyle='->'),
             fontsize=10)

# Mostrar el gráfico
plt.show(block=True)
#plt.close()  # Cerrar la ventana del gráfico después de mostrarlo

# Graficar los valores de 'window'
plt.figure(figsize=(18, 7))
plt.plot(window_values_new, label='Window', color='blue', linewidth=1.5, alpha=0.8)

# Resaltar las regiones de 'slow start' y 'congestion avoidance' con etiquetas únicas
slow_start_label_added = False
ca_label_added = False

for i, state in enumerate(states_new):
    if state == 'slow' and not slow_start_label_added:
        plt.axvspan(i-1, i, color='yellow', alpha=0.4, label='Slow Start')
        slow_start_label_added = True
    elif state == 'slow':
        plt.axvspan(i-1, i, color='yellow', alpha=0.4)
    
    if state == 'CA' and not ca_label_added:
        plt.axvspan(i-1, i, color='green', alpha=0.3, label='Congestion Avoidance')
        ca_label_added = True
    elif state == 'CA':
        plt.axvspan(i-1, i, color='green', alpha=0.3)

# Títulos, etiquetas y leyenda
plt.title('Window Size(Bytes) Over Time', fontsize=18, pad=20)
plt.xlabel('Time (Arbitrary)', fontsize=14, labelpad=15)
plt.ylabel('Window Size', fontsize=14, labelpad=15)
plt.legend(fontsize=12, loc='upper left')
plt.grid(True)
plt.tight_layout()

# Mostrar el gráfico
plt.show(block=True)
plt.close()  # Cerrar la ventana del gráfico después de mostrarlo
