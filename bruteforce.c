#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <mpi.h>
#include <unistd.h>
#include <openssl/des.h>
#include <sys/stat.h>

void decrypt(long key, unsigned char *ciph, int len) {
    DES_cblock key_block;
    DES_key_schedule schedule;

    memcpy(key_block, &key, 8);
    DES_set_odd_parity(&key_block);
    DES_set_key_checked(&key_block, &schedule);

    for(int i = 0; i < len; i += 8) {
        DES_ecb_encrypt((DES_cblock *)(ciph + i), (DES_cblock *)(ciph + i), &schedule, DES_DECRYPT);
    }
}

void encrypt(long key, unsigned char *ciph, int len) {
    DES_cblock key_block;
    DES_key_schedule schedule;

    memcpy(key_block, &key, 8);
    DES_set_odd_parity(&key_block);
    DES_set_key_checked(&key_block, &schedule);

    for(int i = 0; i < len; i += 8) {
        DES_ecb_encrypt((DES_cblock *)(ciph + i), (DES_cblock *)(ciph + i), &schedule, DES_ENCRYPT);
    }
}

char search_phrase[] = " the ";

int tryKey(long key, unsigned char *ciph, int len) {
    unsigned char *temp = malloc(len + 1);
    memcpy(temp, ciph, len);
    temp[len] = 0;

    decrypt(key, temp, len);
    int found = (strstr((char *)temp, search_phrase) != NULL);

    free(temp);
    return found;
}

unsigned char default_cipher[] = {108, 245, 65, 63, 125, 200, 150, 66, 17, 170, 207, 170, 34, 31, 70, 215};

unsigned char *read_file_bytes(const char *path, int *out_len, int binary) {
    FILE *f = fopen(path, binary ? "rb" : "r");
    if (!f) return NULL;
    struct stat st;
    if (stat(path, &st) != 0) {
        fseek(f, 0, SEEK_END);
        long l = ftell(f);
        fseek(f, 0, SEEK_SET);
        unsigned char *buf = malloc(l + 1);
        int r = fread(buf, 1, l, f);
        buf[r] = 0;
        fclose(f);
        *out_len = r;
        return buf;
    }
    int len = (int)st.st_size;
    unsigned char *buf = malloc(len + 1);
    int r = fread(buf, 1, len, f);
    fclose(f);
    buf[r] = 0;
    *out_len = r;
    return buf;
}

unsigned char *pad_pkcs5(unsigned char *in, int inlen, int *outlen) {
    int pad = 8 - (inlen % 8);
    if (pad == 0) pad = 8;
    *outlen = inlen + pad;
    unsigned char *out = malloc(*outlen);
    memcpy(out, in, inlen);
    for(int i = 0; i < pad; ++i) out[inlen + i] = (unsigned char)pad;
    return out;
}

int write_binary_file(const char *path, unsigned char *buf, int len) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    fwrite(buf, 1, len, f);
    fclose(f);
    return 0;
}

int write_text_file(const char *path, const char *s) {
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    fprintf(f, "%s", s);
    fclose(f);
    return 0;
}

int main(int argc, char *argv[]) {
    /* MODO ENCRYPT */
    if (argc > 1 && strcmp(argv[1], "encrypt") == 0) {
        int plain_len = 0;
        unsigned char *plain = read_file_bytes("plain_text.txt", &plain_len, 0);
        if (!plain) {
            fprintf(stderr, "Error: no se pudo leer plain_text.txt\n");
            return 1;
        }
        int key_txt_len = 0;
        unsigned char *keytxt = read_file_bytes("key.txt", &key_txt_len, 0);
        if (!keytxt) {
            fprintf(stderr, "Error: no se pudo leer key.txt\n");
            free(plain);
            return 1;
        }
        char *endptr = NULL;
        long key = strtoll((char *)keytxt, &endptr, 10);
        if (endptr == (char *)keytxt) {
            fprintf(stderr, "Error: key.txt no contiene un número válido\n");
            free(plain);
            free(keytxt);
            return 1;
        }
        int padded_len = 0;
        unsigned char *padded = pad_pkcs5(plain, plain_len, &padded_len);
        unsigned char *cipher = malloc(padded_len);
        memcpy(cipher, padded, padded_len);
        encrypt(key, cipher, padded_len);
        if (write_binary_file("cipher.bin", cipher, padded_len) != 0) {
            fprintf(stderr, "Error: no se pudo escribir cipher.bin\n");
            free(plain); free(keytxt); free(padded); free(cipher);
            return 1;
        }
        char lenstr[64];
        snprintf(lenstr, sizeof(lenstr), "%d", padded_len);
        write_text_file("cipher_len.txt", lenstr);
        printf("Encrypted %d bytes written to cipher.bin\n", padded_len);
        printf("unsigned char cipher[] = {");
        for(int i = 0; i < padded_len; ++i) {
            printf("%u", (unsigned int)cipher[i]);
            if (i + 1 < padded_len) printf(", ");
        }
        printf("};\n");
        free(plain);
        free(keytxt);
        free(padded);
        free(cipher);
        return 0;
    }

    /* MODO DECRYPT */
    int N, id;
    int ciphlen = 16;
    unsigned char *cipher = NULL;
    int cipher_len = 0;
    unsigned char *tmp = read_file_bytes("cipher_len.txt", &cipher_len, 0);
    if (tmp) {
        int len_from_file = atoi((char *)tmp);
        free(tmp);
        if (len_from_file > 0) {
            int rlen = 0;
            unsigned char *bin = read_file_bytes("cipher.bin", &rlen, 1);
            if (bin && rlen > 0) {
                cipher = bin;
                cipher_len = rlen;
            }
        }
    }
    if (!cipher) {
        cipher_len = sizeof(default_cipher);
        cipher = malloc(cipher_len);
        memcpy(cipher, default_cipher, cipher_len);
    }
    ciphlen = cipher_len;

    MPI_Init(&argc, &argv);
    MPI_Comm_size(MPI_COMM_WORLD, &N);
    MPI_Comm_rank(MPI_COMM_WORLD, &id);

    long upper = (1L << 24); // para pruebas rápidas
    long mylower, myupper;
    long range_per_node = upper / N;
    mylower = range_per_node * id;
    myupper = range_per_node * (id + 1) - 1;
    if (id == N - 1) myupper = upper - 1;

    if (id == 0) {
        printf("Running brute force with %d processes. Searching global range [0 .. %ld)\n", N, upper);
    }
    printf("Process %d searching range %ld to %ld (cipher length %d)\n", id, mylower, myupper, ciphlen);

    MPI_Barrier(MPI_COMM_WORLD);
    double start = MPI_Wtime();

    long local_found_key = 0;
    long global_found_key = 0;
    const long CHECK_INTERVAL = 10000;

    for (long i = mylower; i <= myupper; ++i) {
        if (tryKey(i, cipher, ciphlen)) {
            local_found_key = i;
        }

        if (local_found_key || (i % CHECK_INTERVAL == 0)) {
            MPI_Allreduce(&local_found_key, &global_found_key, 1, MPI_LONG, MPI_MAX, MPI_COMM_WORLD);
            if (global_found_key != 0) break;
        }
    }

    MPI_Allreduce(&local_found_key, &global_found_key, 1, MPI_LONG, MPI_MAX, MPI_COMM_WORLD);

    if (id == 0) {
        double end = MPI_Wtime();
        double elapsed = end - start;
        if (global_found_key) {
            unsigned char *result = malloc(ciphlen + 1);
            memcpy(result, cipher, ciphlen);
            result[ciphlen] = 0;
            decrypt(global_found_key, result, ciphlen);
            printf("Key found: %ld\nDecrypted text: %s\n", global_found_key, result);
            printf("Search Time: %f seconds\n", elapsed);
            free(result);
        } else {
            printf("Key not found in the searched range\n");
            printf("Time: %f seconds\n", elapsed);
        }
    }

    free(cipher);
    MPI_Finalize();
    return 0;
}