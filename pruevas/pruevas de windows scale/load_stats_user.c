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
#include <netinet/tcp.h>

//------------------------------DEFINES---------------------------------------//
#define MAP_SIZE 20
#define BPF_OBJ_FILE "xdp_pass_kern.o"
#define POINTER_MAP_PATH "/sys/fs/bpf/tc/globals/pointer_map"
#define VALUES_MAP_PATH "/sys/fs/bpf/tc/globals/values_map"
#define TSVAL_RTT_ARRAY_MAP_PATH "/sys/fs/bpf/tc/globals/tsval_rtt_array_map"
#define RTT_MIN_MAP_PATH "/sys/fs/bpf/tc/globals/rtt_min_map"
#define TIME_RTT_MAP_PATH "/sys/fs/bpf/tc/globals/time_rtt_array_map"
#define TSECR_CHEKED_PATH "/sys/fs/bpf/tc/globals/tsecr_already_checked_map"
#define SEQ_MAP_PATH "/sys/fs/bpf/tc/globals/seq_map"
#define TCP_RMEM_MAP_PATH "/sys/fs/bpf/tc/globals/tcp_rmem_map"
#define RCWND_OK_MAP_PATH "/sys/fs/bpf/tc/globals/rcwnd_ok_map"

#define TCP_RMEM_PATH "/proc/sys/net/ipv4/tcp_rmem"
#define MAX_LONG_LONG 9223372036854775803LL
#define TCP_HEADER_SIZE 20
#define MSS 1448 //unidad de ventana
#define INIT_WINDOW 1*MSS //Ventana inicial

int main(int argc, char **argv) {
	__u32 key;
	long long value;


//-------------------------OBTENCION DE LOS FILES DESCRIPTORS-----------------//
	// Get the map file descriptors
	int fd_values = bpf_obj_get(VALUES_MAP_PATH);
	if (fd_values < 0) {
		fprintf(stderr, "Failed to open map: %s\n", VALUES_MAP_PATH);
		return EXIT_FAILURE;
	}
	int fd_pointer = bpf_obj_get(POINTER_MAP_PATH);
	if (fd_pointer < 0) {
		fprintf(stderr, "Failed to open map: %s\n", POINTER_MAP_PATH);
		return EXIT_FAILURE;
	}
  int fd_tsval_array = bpf_obj_get(TSVAL_RTT_ARRAY_MAP_PATH);
  if (fd_pointer < 0) {
    fprintf(stderr, "Failed to open map: %s\n", TSVAL_RTT_ARRAY_MAP_PATH);
    return EXIT_FAILURE;
  }

  int fd_rtt_min = bpf_obj_get(RTT_MIN_MAP_PATH);
  if (fd_rtt_min < 0) {
    fprintf(stderr, "Failed to open map: %s\n", RTT_MIN_MAP_PATH);
    return EXIT_FAILURE;
  }
  int fd_time_rtt = bpf_obj_get(TIME_RTT_MAP_PATH);
  if (fd_time_rtt < 0) {
    fprintf(stderr, "Failed to open map: %s\n", TIME_RTT_MAP_PATH);
    return EXIT_FAILURE;
  }
  int fd_tsecr_cheked = bpf_obj_get(TSECR_CHEKED_PATH);
  if (fd_tsecr_cheked < 0) {
    fprintf(stderr, "Failed to open map: %s\n", TSECR_CHEKED_PATH);
    return EXIT_FAILURE;
  }

	int fd_seq_map= bpf_obj_get(SEQ_MAP_PATH);
  if (fd_tsecr_cheked < 0) {
    fprintf(stderr, "Failed to open map: %s\n", SEQ_MAP_PATH);
    return EXIT_FAILURE;
  }

	int fd_tcp_rmem = bpf_obj_get(TCP_RMEM_MAP_PATH);
	if (fd_tcp_rmem < 0) {
		fprintf(stderr, "Failed to open map: %s\n", VALUES_MAP_PATH);
		return EXIT_FAILURE;
	}


	int fd_rcwnd_ok = bpf_obj_get(RCWND_OK_MAP_PATH);
	if (fd_tcp_rmem < 0) {
		fprintf(stderr, "Failed to open map: %s\n", RCWND_OK_MAP_PATH);
		return EXIT_FAILURE;
	}
//-----------------------------------INITIALICIAR----------------------------//
	// Initialize values_map
//	value = rand()%100 +1;

//     SE RELLENA EN EL KERNEL? SE USA EXPORT_SIMBOL PARA ESTO

// Initialize fd_tsval_array EN FORMA DE PRUEVAS
	/*for (key = 0; key < MAP_SIZE; key++) {
    	value = rand()%100 +1;
	    if (bpf_map_update_elem(fd_tsval_array, &key, &value, BPF_ANY)) {
	        fprintf(stderr, "Failed to update map: %s\n", TSVAL_RTT_ARRAY_MAP_PATH);
	        return EXIT_FAILURE;
	    }
	}
*/



//INITIALIZE LAS_QD_VALUES
  value = MAX_LONG_LONG;
  for (key = 0; key < MAP_SIZE; key++) {
      if (bpf_map_update_elem(fd_values, &key, &value, BPF_ANY)) {
          fprintf(stderr, "Failed to update map: %s\n", VALUES_MAP_PATH);
          return EXIT_FAILURE;
      }
  }

  key = 0;
  value = MAX_LONG_LONG;
  if (bpf_map_update_elem(fd_rtt_min, &key, &value, BPF_ANY)) {
			fprintf(stderr, "Failed to update map: %s\n", RTT_MIN_MAP_PATH);
      return EXIT_FAILURE;
  }

	/*key = 0;
  value = 0;
  if (bpf_map_update_elem(fd_tsecr_cheked, &key, &value, BPF_ANY)) {
      fprintf(stderr, "Failed to update tsecr_cheked_map\n");
      return EXIT_FAILURE;
  }*/



// TSVAL RTT Y TIME_RTT SE RELLENAN A LA VEZ Y DE FORMA SINCRONIZADA, ES MEJOR HACERLO EN UNA ESTRUCTURA.

  key = 8;
  value = 50;
  if (bpf_map_update_elem(fd_time_rtt, &key, &value, BPF_ANY)) {
      fprintf(stderr, "Failed to update map: %s\n", TIME_RTT_MAP_PATH);
      return EXIT_FAILURE;
  }

  key = 0;
  value = 0;
  if (bpf_map_update_elem(fd_pointer, &key, &value, BPF_ANY)) {
      fprintf(stderr, "Failed to update pointer_map\n");
      return EXIT_FAILURE;
  }


	key = 0;
  value = INIT_WINDOW ;
  if (bpf_map_update_elem(fd_rcwnd_ok, &key, &value, BPF_ANY)) {
      fprintf(stderr, "Failed to update pointer_map\n");
      return EXIT_FAILURE;
  }
//--------------------------------PRINT---------------------------------------//
 //int ya=1;
	// Print the updated values
	/*while(1) {

			// Read and print values from last_qd_values_map
			for (key = 0; key < MAP_SIZE; key++) {
				    if (bpf_map_lookup_elem(fd_tsval_array, &key, &value)) {
				        fprintf(stderr, "Failed to read from last_qd_values_map\n");
				        return EXIT_FAILURE;
				    } else {
				        printf("fd_tsval_array[%u] = %lld\n", key, value);
				    }
				}
        printf("-------------------------------\n");

        key = 0;
     	    if (bpf_map_lookup_elem(fd_rtt_min, &key, &value)) {
     	        fprintf(stderr, "Failed to read from pointer_map\n");
     	        return EXIT_FAILURE;
     	    } else {
     	        printf("RTT_MIN = %lld\n", value);
     	    }
          if (bpf_map_lookup_elem(fd_tsecr_cheked, &key, &value)) {
     	        fprintf(stderr, "Failed to read from pointer_map\n");
     	        return EXIT_FAILURE;
     	    } else {
     	        printf("Alreade_cheked = %lld\n", value);
     	    }

          key=8;
          if (bpf_map_lookup_elem(fd_time_rtt, &key, &value)) {
               fprintf(stderr, "Failed to read from pointer_map\n");
               return EXIT_FAILURE;
           } else {
               printf("TIME_RTT[8] = %lld\n", value);
           }

           key=0;
           if (bpf_map_lookup_elem(fd_pointer, &key, &value)) {
                fprintf(stderr, "Failed to read from pointer_map\n");
                return EXIT_FAILURE;
            } else {
                printf("pointer_map = %lld\n", value);
            }

          printf("\n\n");
          if(ya==4){
            key = 0;
            value = 5;
            if (bpf_map_update_elem(fd_pointer, &key, &value, BPF_ANY)) {
                fprintf(stderr, "Failed to update pointer_map\n");
                return EXIT_FAILURE;
            }
          }
          ya++;
        sleep(2);
}  */
 //--------------------RTT MIN
	/*while(1) {
		    key = 0;

				// Read and print the TCP header from tcp_header_map
			printf("TCP Header: ");
			__u8 tcp_byte;
			for (key = 0; key < TCP_HEADER_SIZE; key++) {
					if (bpf_map_lookup_elem(fd_tcphdr, &key, &tcp_byte)) {
							fprintf(stderr, "Failed to read from tcp_header_map\n");
							return EXIT_FAILURE;
					} else {
							printf("%02x ", tcp_byte);
					}
			}
			printf("\n");
	    sleep(1);
		}*/ //------------------CABECERA TCP FIJA
	//-------------------BUCLE PARA ACCEDER A LA CABECERA TC
  /*while (1) {
		    // ...
		    // Leer y preparar la cabecera TCP
		    struct tcphdr tcph;
		    for (key = 0; key < 32; key++) {
		        if (bpf_map_lookup_elem(fd_tcphdr, &key, &((uint8_t *)&tcph)[key])) {
		            fprintf(stderr, "Failed to read from tcp_header_map\n");
		            return EXIT_FAILURE;
		        }
		    }

		    // Llamar a la función para obtener el valor TSecr
		    get_TSecr(&tcph);


		    // Otras acciones...

		    sleep(1);
		}*/
//--------------------------------------------------------
/*		struct seq {
		  __u32 last_seq;
		  __u32 last_seq_old;
		};
while (1) {
	int key=0;
	struct seq value;
	if (bpf_map_lookup_elem(fd_seq_map, &key, &value)) {
 		 fprintf(stderr, "Failed to read from last_qd_values_map\n");
 		 return EXIT_FAILURE;
  } else {
 		 printf("last_seq = %d\n", value.last_seq);
  }

	sleep(2);
}
*/


	int ret = system("sudo rm /sys/fs/bpf/tc/globals/packet_number_map");
	 if (ret == -1) {
			 perror("Error al ejecutar el comando");
			 return 1;
	 }
	 printf("Mapa pcket_number RESETEADO\n" );


FILE *fp;
 int tcp_rmem_values[3];

 // Abrir el archivo para lectura
 fp = fopen(TCP_RMEM_PATH, "r");
 if (!fp) {
		 perror("Error al abrir el archivo");
		 return 1;
 }

 // Leer los valores
 if (fscanf(fp, "%d %d %d", &tcp_rmem_values[0], &tcp_rmem_values[1], &tcp_rmem_values[2]) != 3) {
		 perror("Error al leer los valores");
		 fclose(fp);
		 return 1;
 }

 // Cerrar el archivo
 fclose(fp);

 // Imprimir los valores para verificar
 printf("tcp_rmem values:\n");
 printf("Min: %d\n", tcp_rmem_values[0]);
 printf("Default: %d\n", tcp_rmem_values[1]);
 printf("Max: %d\n", tcp_rmem_values[2]);

 key = 0;
 struct tcp_rmem {
   __u32 min_buff;
   __u32 def_buff;
   __u32 max_buff;
 };

 struct tcp_rmem values;
 values.min_buff=tcp_rmem_values[0];
 values.def_buff=tcp_rmem_values[1];
 values.max_buff=tcp_rmem_values[2];

 if (bpf_map_update_elem(fd_tcp_rmem, &key, &values, BPF_ANY)) {
		 fprintf(stderr, "Failed to update fd_tcp_rmem\n");
		 return EXIT_FAILURE;
 }




	return EXIT_SUCCESS;
}
