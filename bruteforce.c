#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <mpi.h>
#include <unistd.h>
#include <openssl/des.h>

#define MAX_SEARCH_PHRASE 1024

void decrypt(long key, unsigned char *ciph, int len) {
    DES_cblock key_block;
    DES_key_schedule schedule;

    memset(&key_block, 0, sizeof(key_block));
    memcpy(key_block, &key, sizeof(long) < 8 ? sizeof(long) : 8);
    DES_set_odd_parity(&key_block);
    DES_set_key_checked(&key_block, &schedule);

    // DES opera en bloques de 8 bytes
    for(int i = 0; i < len; i += 8) {
        DES_ecb_encrypt((DES_cblock *)(ciph + i), (DES_cblock *)(ciph + i), &schedule, DES_DECRYPT);
    }
}

void encrypt(long key, unsigned char *ciph, int len) {
    DES_cblock key_block;
    DES_key_schedule schedule;

    memset(&key_block, 0, sizeof(key_block));
    memcpy(key_block, &key, sizeof(long) < 8 ? sizeof(long) : 8);
    DES_set_odd_parity(&key_block);
    DES_set_key_checked(&key_block, &schedule);

    for(int i = 0; i < len; i += 8) {
        DES_ecb_encrypt((DES_cblock *)(ciph + i), (DES_cblock *)(ciph + i), &schedule, DES_ENCRYPT);
    }
}

int tryKey(long key, unsigned char *ciph, int len, const char *search) {
    unsigned char *temp = malloc(len + 1);
    if (!temp) return 0;
    memcpy(temp, ciph, len);
    temp[len] = '\0';

    decrypt(key, temp, len);
    int found = (strstr((char *)temp, search) != NULL);

    free(temp);
    return found;
}

unsigned char *read_text_file(const char *filename, int *out_len) {
    FILE *f = fopen(filename, "rb");
    if(!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *buf = malloc(sz + 1);
    if(!buf) { fclose(f); return NULL; }
    fread(buf, 1, sz, f);
    buf[sz] = '\0';
    fclose(f);
    *out_len = (int)sz;
    return buf;
}

int write_cipher_bin(const char *filename, unsigned char *buf, int len) {
    FILE *f = fopen(filename, "wb");
    if(!f) return -1;
    if(fwrite(&len, sizeof(int), 1, f) != 1) { fclose(f); return -1; }
    if(fwrite(buf, 1, len, f) != (size_t)len) { fclose(f); return -1; }
    fclose(f);
    return 0;
}

int read_cipher_bin(const char *filename, unsigned char **out_buf, int *out_len) {
    FILE *f = fopen(filename, "rb");
    if(!f) return -1;
    int len;
    if(fread(&len, sizeof(int), 1, f) != 1) { fclose(f); return -1; }
    unsigned char *buf = malloc(len);
    if(!buf) { fclose(f); return -1; }
    if(fread(buf, 1, len, f) != (size_t)len) { free(buf); fclose(f); return -1; }
    fclose(f);
    *out_buf = buf;
    *out_len = len;
    return 0;
}

unsigned char *pad8(unsigned char *in, int in_len, int *out_len) {
    int pad = 8 - (in_len % 8);
    if (pad == 0) pad = 8;
    int newlen = in_len + pad;
    unsigned char *out = malloc(newlen);
    if(!out) return NULL;
    memcpy(out, in, in_len);
    memset(out + in_len, pad, pad);
    *out_len = newlen;
    return out;
}

int main(int argc, char *argv[]) {
    int N, id;
    long upper = (1L << 24);
    long mylower, myupper;
    MPI_Status st;
    MPI_Request req;
    int ciphlen = 0;
    unsigned char *cipher = NULL;

    char search_phrase[MAX_SEARCH_PHRASE];
    memset(search_phrase, 0, sizeof(search_phrase));

    int do_encrypt = 0;
    long encrypt_key = 0;
    if(argc >= 2 && strcmp(argv[1], "encrypt") == 0) {
        do_encrypt = 1;
        if(argc < 3) {
            fprintf(stderr, "Usage: %s encrypt <numeric_key>\n", argv[0]);
            return 1;
        }
        encrypt_key = atol(argv[2]);
    }

    MPI_Init(&argc, &argv);
    MPI_Comm_size(MPI_COMM_WORLD, &N);
    MPI_Comm_rank(MPI_COMM_WORLD, &id);

    if(id == 0) {
        FILE *kf = fopen("key.txt", "r");
        if(!kf) {
            fprintf(stderr, "Error: no se encuentra key.txt (debe contener la palabra a buscar).\n");
            MPI_Abort(MPI_COMM_WORLD, 1);
        }
        if(fgets(search_phrase, sizeof(search_phrase), kf) == NULL) {
            fclose(kf);
            fprintf(stderr, "Error: key.txt vacío\n");
            MPI_Abort(MPI_COMM_WORLD, 1);
        }
        size_t l = strlen(search_phrase);
        if(l > 0 && (search_phrase[l-1] == '\n' || search_phrase[l-1] == '\r')) search_phrase[l-1] = '\0';
        l = strlen(search_phrase);
        if(l > 0 && (search_phrase[l-1] == '\n' || search_phrase[l-1] == '\r')) search_phrase[l-1] = '\0';
        fclose(kf);
    }

    int splen = 0;
    if(id == 0) splen = strlen(search_phrase) + 1;
    MPI_Bcast(&splen, 1, MPI_INT, 0, MPI_COMM_WORLD);
    if(splen <= 0 || splen > MAX_SEARCH_PHRASE) {
        if(id == 0) fprintf(stderr, "search phrase inválida o muy larga\n");
        MPI_Abort(MPI_COMM_WORLD, 1);
    }
    MPI_Bcast(search_phrase, splen, MPI_CHAR, 0, MPI_COMM_WORLD);

    /* MODO ENCRYPT */
    if(do_encrypt) {
        if(id == 0) {
            int plain_len;
            unsigned char *plain = read_text_file("plain_text.txt", &plain_len);
            if(!plain) {
                fprintf(stderr, "Error leyendo plain_text.txt\n");
                MPI_Abort(MPI_COMM_WORLD, 1);
            }

            int padded_len;
            unsigned char *padded = pad8(plain, plain_len, &padded_len);
            free(plain);
            if(!padded) {
                fprintf(stderr, "Error en padding\n");
                MPI_Abort(MPI_COMM_WORLD, 1);
            }

            encrypt(encrypt_key, padded, padded_len);

            if(write_cipher_bin("cipher.bin", padded, padded_len) != 0) {
                fprintf(stderr, "Error escribiendo cipher.bin\n");
                free(padded);
                MPI_Abort(MPI_COMM_WORLD, 1);
            }
            free(padded);
            printf("Encrypted %d bytes written to cipher.bin\n", padded_len);
        }
        MPI_Finalize();
        return 0;
    }

    /* MODO DECRYPT */
    if(id == 0) {
        if(read_cipher_bin("cipher.bin", &cipher, &ciphlen) != 0) {
            fprintf(stderr, "Error leyendo cipher.bin. Asegúrate que existe (puedes generar con 'encrypt').\n");
            MPI_Abort(MPI_COMM_WORLD, 1);
        }
    }

    // broadcast length and cipher bytes
    MPI_Bcast(&ciphlen, 1, MPI_INT, 0, MPI_COMM_WORLD);
    if(ciphlen <= 0) {
        if(id == 0) fprintf(stderr, "cipher.bin corrupto o vacío\n");
        MPI_Abort(MPI_COMM_WORLD, 1);
    }
    if(id != 0) cipher = malloc(ciphlen);
    MPI_Bcast(cipher, ciphlen, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);

    // rangos de búsqueda
    int world_size = N;
    long range_per_node = upper / world_size;
    mylower = range_per_node * id;
    myupper = range_per_node * (id + 1) - 1;
    if(id == world_size - 1) myupper = upper - 1;

    long found = -1;
    int flag = 0;

    // Recibir de forma asíncrona notificación de found
    MPI_Irecv(&found, 1, MPI_LONG, MPI_ANY_SOURCE, MPI_ANY_TAG, MPI_COMM_WORLD, &req);

    if(id == 0) {
        printf("Searching for phrase \"%s\" in decrypted text.\n", search_phrase);
    }
    printf("Process %d searching range %ld to %ld\n", id, mylower, myupper);

    double t_start = MPI_Wtime();

    for(long i = mylower; i <= myupper && !flag; ++i) {
        MPI_Test(&req, &flag, &st);
        if(flag) break;
        if(tryKey(i, cipher, ciphlen, search_phrase)) {
            found = i;
            printf("Process %d found a candidate key: %ld\n", id, found);
            for(int node = 0; node < world_size; node++) {
                if(node != id) {
                    MPI_Send(&found, 1, MPI_LONG, node, 0, MPI_COMM_WORLD);
                }
            }
            break;
        }
    }

    // todos saben que la búsqueda terminó
    MPI_Barrier(MPI_COMM_WORLD);
    double t_end = MPI_Wtime();

    if(id == 0) {
        if(found != -1) {
            unsigned char *result = malloc(ciphlen + 1);
            if(result) {
                memcpy(result, cipher, ciphlen);
                result[ciphlen] = '\0';
                decrypt(found, result, ciphlen);
                int pad = result[ciphlen-1];
                int plain_len = ciphlen;
                if(pad > 0 && pad <= 8) plain_len = ciphlen - pad;
                result[plain_len] = '\0';
                printf("Key found: %ld\nDecrypted text: %s\n", found, (char*)result);
                free(result);
            } else {
                printf("Key found: %ld\n", found);
            }
            double elapsed = t_end - t_start;
            printf("Time to find key: %.4f seconds\n", elapsed);
        } else {
            printf("Key not found in message\n");
            double elapsed = t_end - t_start;
            printf("Elapsed search time: %.4f seconds\n", elapsed);
        }
    }

    if(cipher) free(cipher);
    MPI_Finalize();
    return 0;
}
