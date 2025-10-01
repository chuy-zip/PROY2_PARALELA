#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <mpi.h>
#include <unistd.h>
#include <openssl/des.h>

void decrypt(long key, char *ciph, int len) {
    DES_cblock key_block;
    DES_key_schedule schedule;
    
    memcpy(key_block, &key, 8);
    DES_set_odd_parity(&key_block);
    DES_set_key_checked(&key_block, &schedule);
    
    // DES opera en bloques de 8 bytes
    for(int i = 0; i < len; i += 8) {
        DES_ecb_encrypt((DES_cblock *)(ciph + i), (DES_cblock *)(ciph + i), &schedule, DES_DECRYPT);
    }
}

void encrypt(long key, char *ciph, int len) {
    DES_cblock key_block;
    DES_key_schedule schedule;
    
    memcpy(key_block, &key, 8);
    DES_set_odd_parity(&key_block);
    DES_set_key_checked(&key_block, &schedule);
    
    for(int i = 0; i < len; i += 8) {
        DES_ecb_encrypt((DES_cblock *)(ciph + i), (DES_cblock *)(ciph + i), &schedule, DES_ENCRYPT);
    }
}

char search[] = " the ";
int tryKey(long key, char *ciph, int len) {
    char *temp = malloc(len + 1);
    memcpy(temp, ciph, len);
    temp[len] = 0;
    
    decrypt(key, temp, len);
    int found = (strstr(temp, search) != NULL);
    
    free(temp);
    return found;
}

// la cadena cifrada en bytes binarios para representar chars
// es el valor ascii practicamente del texto cifrado

unsigned char cipher[] = {108, 245, 65, 63, 125, 200, 150, 66, 17, 170, 207, 170, 34, 31, 70, 215, 0};

int main(int argc, char *argv[]) {
    int N, id;
    long upper = (1L << 56); // esto se puede cambiar para probar las posibles combinaciones, pede ser 2^24 en lugar de 2^56
    long mylower, myupper;
    MPI_Status st;
    MPI_Request req;
    int ciphlen = 16; // Longitud fija del cipher
    
    MPI_Init(&argc, &argv);
    MPI_Comm_size(MPI_COMM_WORLD, &N);
    MPI_Comm_rank(MPI_COMM_WORLD, &id);
    
    int range_per_node = upper / N;
    mylower = range_per_node * id;
    myupper = range_per_node * (id + 1) - 1;
    
    if(id == N - 1) {
        myupper = upper;
    }
    
    long found = 0;
    int flag = 0;
    
    // Recibir de forma asíncrona
    MPI_Irecv(&found, 1, MPI_LONG, MPI_ANY_SOURCE, MPI_ANY_TAG, MPI_COMM_WORLD, &req);
    
    printf("Process %d searching range %ld to %ld\n", id, mylower, myupper);
    
    for(long i = mylower; i <= myupper && !flag; ++i) {
        MPI_Test(&req, &flag, &st);
        if(flag) break; // Alguien ya encontró la clave
        
        if(tryKey(i, (char *)cipher, ciphlen)) {
            found = i;
            printf("Process %d found the key: %ld\n", id, found);
            
            // Notificar a todos los procesos
            for(int node = 0; node < N; node++) {
                if(node != id) {
                    MPI_Send(&found, 1, MPI_LONG, node, 0, MPI_COMM_WORLD);
                }
            }
            break;
        }
    }
    
    if(id == 0) {
        if(!found) {
            MPI_Wait(&req, &st);
        }
        if(found) {
            char result[ciphlen + 1];
            memcpy(result, cipher, ciphlen);
            result[ciphlen] = 0;
            decrypt(found, result, ciphlen);
            printf("Key found: %ld\nDecrypted text: %s\n", found, result);
        } else {
            printf("Key not found in the searched range\n");
        }
    }
    
    MPI_Finalize();
    return 0;
}