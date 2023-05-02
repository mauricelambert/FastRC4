// Compilation: gcc test.c ARC4.o

#include <stdio.h>
#include <stdlib.h>

char *get_iv();
void *encrypt(char *key, char *data, unsigned long long length);
void *decrypt(char *key, char iv[256], char *data, unsigned long long length);
void *generate_iv();
void *xor_key_iv();
void *generate_key(char *key);
void *arc4_null_byte(char *data);
void *arc4(char *data, unsigned long long length);
void *reset_key();
void *set_iv(char *iv);

int main() {
        puts("start");
        char* key = "key";
        puts(key);
        char* data = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        // data[0] = 1;
        char* data2 = malloc(63);
        for (int i = 0; i < 63; i++) data2[i] = data[i];
        unsigned long long length = 62;
        puts(data);
        generate_iv();
        puts("IV generated");
        generate_key(key);
        puts("Key generated");
        xor_key_iv();
        puts("Key ciphered by IV");
        arc4(data2, length);
        puts("Cipher");
        for (int i = 0; i < 63; i++) printf("%02x", data[i]);
        puts("");
        char *iv = get_iv();
        reset_key();
        generate_key(key);
        set_iv(iv);
        xor_key_iv();
        arc4(data2, 62);
        puts(data2);
        return 0;
}
