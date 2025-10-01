#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <stddef.h>
#include <stdbool.h>
#include <openssl/evp.h>

// AES constants
#define AES_KEY_SIZE   32  // 256 bits
#define AES_IV_LEN     16  // 128 bits
#define AES_BLOCK_SIZE 16  // AES block size

// Represents a secure message with its data and length.
// Note: Caller is responsible for freeing `data` when done.
typedef struct {
    unsigned char *data;
    size_t length;
} SecureMessage;


int generate_and_save_ec_keypair(const char *private_key_file, const char *public_key_file);
int prompt_and_save_username();
int load_username(char *username_buffer, size_t buffer_size);

// Key loading functions
EVP_PKEY *load_private_key(const char *filename);
EVP_PKEY *load_public_key(const char *filename);

// AES functions
int aes_encrypt(const unsigned char *plaintext, int plaintext_len,
                const unsigned char *key, const unsigned char *iv,
                unsigned char **ciphertext, int *ciphertext_len);

int aes_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                const unsigned char *key, const unsigned char *iv,
                unsigned char **plaintext, int *plaintext_len);

// ECIES Encrypt
int ecies_encrypt_aes_key(
    const unsigned char *aes_key, size_t key_len,
    EVP_PKEY *recipient_pubkey,
    unsigned char **wrapped_key, size_t *wrapped_len);

int ecies_decrypt_aes_key(
    EVP_PKEY *recipient_privkey,
    const unsigned char *wrapped_key, size_t wrapped_len,
    unsigned char *aes_key_out, size_t *aes_key_len);

// AES Key generation
int generate_aes_key_and_iv(unsigned char *key, unsigned char *iv);

// Signing
int sign_message(EVP_PKEY *pkey,
                 const unsigned char *msg, size_t msg_len,
                 unsigned char **signature, size_t *sig_len);

int verify_signature(EVP_PKEY *pkey,
                     const unsigned char *msg, size_t msg_len,
                     const unsigned char *signature, size_t sig_len);


// Secure message
bool build_secure_message_package(
    const unsigned char *plaintext,
    size_t plaintext_len,
    EVP_PKEY *sender_privkey,
    EVP_PKEY *recipient_pubkey,
    SecureMessage *out_msg
);

bool parse_and_decrypt_secure_message(
    const SecureMessage *msg,
    EVP_PKEY *recipient_privkey,
    EVP_PKEY *sender_pubkey,
    unsigned char **plaintext_out,
    size_t *plaintext_len_out
);


#endif  // CRYPTO_UTILS_H
