// crypto_helpers.c
#include "crypto_helpers.h"
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <string.h>
#include <errno.h>
#include <openssl/err.h>

#define CONTACT_KEYS_DIR "keys/contacts"

EVP_PKEY *load_private_key_from_file(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) return NULL;
    EVP_PKEY *key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    return key;
}

EVP_PKEY *load_public_key_from_file(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) return NULL;
    EVP_PKEY *key = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    return key;
}

char *base64_encode(const unsigned char *input, size_t len) {
    BIO *bmem = NULL, *b64 = NULL;
    BUF_MEM *bptr;

    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);  // No newlines
    BIO_write(b64, input, len);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);

    char *buff = malloc(bptr->length + 1);
    if (buff) {
        memcpy(buff, bptr->data, bptr->length);
        buff[bptr->length] = '\0';
    }

    BIO_free_all(b64);
    return buff;
}

unsigned char *base64_decode(const char *input, size_t *out_len) {
    size_t len = strlen(input);
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bmem = BIO_new_mem_buf((void *)input, len);
    b64 = BIO_push(b64, bmem);

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);  // No newlines

    size_t max_len = len * 3 / 4;  // Approximate max
    unsigned char *buffer = malloc(max_len);
    if (!buffer) return NULL;

    int decoded_len = BIO_read(b64, buffer, max_len);
    if (decoded_len <= 0) {
        BIO_free_all(b64);
        free(buffer);
        return NULL;
    }

    *out_len = decoded_len;
    BIO_free_all(b64);
    return buffer;
}

EVP_PKEY *load_public_key_from_base64(const char *b64) {
    size_t bin_len = 0;
    unsigned char *der = base64_decode(b64, &bin_len);
    if (!der) return NULL;

    const unsigned char *p = der;
    EVP_PKEY *key = d2i_PUBKEY(NULL, &p, bin_len);
    free(der);
    return key;
}

char *export_public_key_to_base64(EVP_PKEY *key) {
    unsigned char *der = NULL;
    int len = i2d_PUBKEY(key, &der);
    if (len <= 0) return NULL;

    char *b64 = base64_encode(der, len);
    OPENSSL_free(der);
    return b64;
}

// Load a private key (EVP_PKEY *) from a PEM file
EVP_PKEY *load_private_key_from_pem(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        perror("Failed to open private key file");
        return NULL;
    }

    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    if (!pkey) {
        fprintf(stderr, "Failed to load private key from %s\n", path);
        ERR_print_errors_fp(stderr);
    }

    return pkey;
}

// Load a public key (EVP_PKEY *) from a PEM file
EVP_PKEY *load_public_key_from_pem(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        perror("Failed to open public key file");
        return NULL;
    }

    EVP_PKEY *pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);

    if (!pkey) {
        fprintf(stderr, "Failed to load public key from %s\n", path);
        ERR_print_errors_fp(stderr);
    }

    return pkey;
}

// Builds full path from a contact key filename (e.g., "alice.pem")
static char *build_contact_key_path(const char *filename) {
    size_t path_len = strlen(CONTACT_KEYS_DIR) + strlen(filename) + 2; // '/' + '\0'
    char *full_path = malloc(path_len);
    if (!full_path) return NULL;

    snprintf(full_path, path_len, "%s/%s", CONTACT_KEYS_DIR, filename);
    return full_path;
}

// Loads a contact's public key from keys/contacts/<filename>
EVP_PKEY *load_contact_public_key(const char *filename) {
    char *full_path = build_contact_key_path(filename);
    if (!full_path) {
        fprintf(stderr, "Failed to allocate memory for key path\n");
        return NULL;
    }

    EVP_PKEY *key = load_public_key_from_pem(full_path);
    free(full_path);
    return key;
}