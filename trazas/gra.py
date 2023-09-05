import matplotlib.pyplot as plt
import re

# Extraer los valores de 'queue_delay', 'window', y 'state' del archivo
queue_delays_new = []
window_values_new = []
states_new = []

with open("/home/otman/TC/trazas/traza_mucho.txt", "r") as file:
    for line in file:
        match_queue_delay = re.search(r'queue_delay\s*:\s*(\d+)', line)
        match_window = re.search(r'window\s*:\s*(\d+)', line)
        match_state = re.search(r'State:\s*(\w+)', line)
        
        if match_queue_delay:
            queue_delays_new.append(int(match_queue_delay.group(1)))
        if match_window and match_state:
            window_values_new.append(int(match_window.group(1)))
            states_new.append(match_state.group(1))

# Encontrar las fases de 'slow start' y determinar la más larga
lengths = []
start_indices = []

in_slow_start = False
current_length = 0
current_start_index = None

for i, state in enumerate(states_new):
    if state == 'slow' and not in_slow_start:
        in_slow_start = True
        current_length = 1
        current_start_index = i
    elif state == 'slow' and in_slow_start:
        current_length += 1
    elif state != 'slow' and in_slow_start:
        in_slow_start = False
        lengths.append(current_length)
        start_indices.append(current_start_index)
        current_length = 0
        current_start_index = None

# Encontrar el índice de inicio de la fase 'slow start' más larga
longest_slow_start_index = start_indices[lengths.index(max(lengths))]
start_index_focus = max(0, longest_slow_start_index - 50)
end_index_focus = min(longest_slow_start_index + max(lengths) + 50, len(window_values_new))

# Graficar los valores de 'window' con un enfoque en la fase 'slow start' más larga
plt.figure(figsize=(18, 7))
plt.plot(window_values_new[start_index_focus:end_index_focus], label='Window', color='blue', linewidth=1.5, alpha=0.8)

# Resaltar las regiones de 'slow start' y 'congestion avoidance' con etiquetas únicas
slow_start_label_added = False
ca_label_added = False

for i, state in enumerate(states_new[start_index_focus:end_index_focus]):
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
plt.title('Circunstancia: Perio_red', fontsize=18, pad=20)
plt.xlabel('Time(Arbitrario)', fontsize=14, labelpad=15)
plt.ylabel('Ventana(Bytes)', fontsize=14, labelpad=15)
plt.legend(fontsize=12, loc='upper left')
plt.grid(True)
plt.tight_layout()
plt.show()
