// crypto_helpers.h
#ifndef CRYPTO_HELPERS_H
#define CRYPTO_HELPERS_H

#include <openssl/evp.h>
#include <stddef.h>

// Key management
EVP_PKEY *load_private_key_from_file(const char *filename);
EVP_PKEY *load_public_key_from_file(const char *filename);
EVP_PKEY *load_public_key_from_base64(const char *b64);
char *export_public_key_to_base64(EVP_PKEY *key);

// Base64 encoding
char *base64_encode(const unsigned char *input, size_t len);
unsigned char *base64_decode(const char *input, size_t *out_len);

// Load an EVP_PKEY (private key) from a PEM file
EVP_PKEY *load_private_key_from_pem(const char *path);

// Load an EVP_PKEY (public key) from a PEM file
EVP_PKEY *load_public_key_from_pem(const char *path);
EVP_PKEY *load_contact_public_key(const char *filename);

#endif
