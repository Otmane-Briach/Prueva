



#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    int key;
    int value;
    key = 1;
    value = 1;

    printf("ANTES DE TODO\n");

    if (key == 2) {

        // ... (bloque vacío)

    } else {
        if (value == 1) {
            if (key == 1) {
                printf("ANTES DE TODO\n");

                #ifdef RLEDBAT2
            } else if (value == 1) {
                printf("aqui 1");
                #else
            } else if (value == 1) {
                printf("aqui 2\n");
                #endif

                if (value == 1) {
                    printf("IF de dentro del todo\n");
                }

                printf("Acabado \n");
            }
        }
    }

    return EXIT_SUCCESS;
}