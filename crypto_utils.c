#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/kdf.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include "crypto_utils.h"
#include <sys/stat.h>
#include "crypto_helpers.h"

#define USERNAME_FILENAME ".contacts_username"
#define CURVE_NAME NID_X9_62_prime256v1
#define NONCE_SIZE 12
#define MAX_MESSAGE_SIZE 8192
#define MAX_SIGNATURE_SIZE 512
#define MAX_WRAPPED_KEY_SIZE 512

// Ensure the directory exists
void ensure_key_directories() {
    mkdir("keys", 0700);
    mkdir("keys/self", 0700);
    mkdir("keys/contacts", 0700);
}

// Helper: get path to ~/.contacts_username
static void get_username_path(char *path, size_t maxlen) {
    const char *home = getenv("HOME");
    if (!home) {
        home = ".";
    }
    snprintf(path, maxlen, "%s/%s", home, USERNAME_FILENAME);
}

// Load username if file exists
/*
int load_username(char *username_buffer, size_t buffer_size) {
    char path[PATH_MAX];
    get_username_path(path, sizeof(path));

    FILE *fp = fopen(path, "r");
    if (!fp) {
        return -1; // Not found
    }

    if (!fgets(username_buffer, buffer_size, fp)) {
        fclose(fp);
        return -1;
    }

    // Remove trailing newline if present
    username_buffer[strcspn(username_buffer, "\n")] = '\0';

    fclose(fp);
    return 0;
}

// Ask user and save username (run only once)
int prompt_and_save_username() {
    char username[128];
    printf("Enter your username: ");
    if (!fgets(username, sizeof(username), stdin)) {
        fprintf(stderr, "Failed to read username\n");
        return -1;
    }

    // Remove newline
    username[strcspn(username, "\n")] = '\0';

    if (strlen(username) == 0) {
        fprintf(stderr, "Username cannot be empty\n");
        return -1;
    }

    char path[PATH_MAX];
    get_username_path(path, sizeof(path));

    FILE *fp = fopen(path, "w");
    if (!fp) {
        perror("Failed to save username");
        return -1;
    }

    fprintf(fp, "%s\n", username);
    fclose(fp);

    return 0;
}
*/

int generate_and_save_ec_keypair() {
    int ret = 0;
    EC_KEY *ec_key = NULL;

    // Create new EC key with curve secp256r1
    ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (ec_key == NULL) {
        fprintf(stderr, "Failed to create EC key\n");
        ret = -1;
        goto cleanup;
    }

    if (EC_KEY_generate_key(ec_key) != 1) {
        fprintf(stderr, "Failed to generate EC key\n");
        ret = -1;
        goto cleanup;
    }

    // File paths
    const char *private_key_file = "keys/self/self_priv.pem";
    const char *public_key_file  = "keys/self/self_pub.pem";

    // Save private key
    BIO *bp_private = BIO_new_file(private_key_file, "w+");
    if (!bp_private || !PEM_write_bio_ECPrivateKey(bp_private, ec_key, NULL, NULL, 0, NULL, NULL)) {
        fprintf(stderr, "Failed to write EC private key to %s\n", private_key_file);
        ret = -1;
        goto cleanup;
    }

    // Save public key
    BIO *bp_public = BIO_new_file(public_key_file, "w+");
    if (!bp_public || !PEM_write_bio_EC_PUBKEY(bp_public, ec_key)) {
        fprintf(stderr, "Failed to write EC public key to %s\n", public_key_file);
        ret = -1;
        goto cleanup;
    }

    printf("✅ EC key pair generated and saved successfully.\n");

cleanup:
    if (bp_private) BIO_free_all(bp_private);
    if (bp_public) BIO_free_all(bp_public);
    if (ec_key) EC_KEY_free(ec_key);

    return ret;
}

EVP_PKEY *load_private_key(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("Failed to open private key file");
        return NULL;
    }

    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    if (!pkey) {
        fprintf(stderr, "Error loading private key from %s\n", filename);
        return NULL;
    }
    return pkey;
}

EVP_PKEY *load_public_key(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("Failed to open public key file from:");
        return NULL;
    }

    EVP_PKEY *pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);

    if (!pkey) {
        fprintf(stderr, "Error loading public key from %s\n", filename);
        return NULL;
    }
    return pkey;
}

///////////////////////////////////////////////////////////////////
/*
3. 📤 Message Sending (Sender's Side)

Generate a random AES key + IV

Encrypt the plaintext using AES-256-CBC

Encrypt the AES key using recipient's EC public key (ECIES-style)

Build a message payload:

Include your username

Include the encrypted AES key

Include the IV

Include the ciphertext

Sign the whole payload (except the signature) with your EC private key

Append the signature to the message

4. 📥 Message Receiving (Recipient's Side)

Extract sender's username, encrypted AES key, IV, ciphertext, and signature

Retrieve sender's public key (assume it's available via the username)

Verify the signature on the payload using sender's public key

Decrypt the AES key using recipient's EC private key

Decrypt the ciphertext using AES key and IV

Output the decrypted plaintext
*/
///////////////////////////////////////////////////////////////////////

// Generate a random AES key + IV and decrypt it

int aes_encrypt(const unsigned char *plaintext, int plaintext_len,
                const unsigned char *key, const unsigned char *iv,
                unsigned char **ciphertext, int *ciphertext_len) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ct_len;

    *ciphertext = malloc(plaintext_len + AES_BLOCK_SIZE);
    if (!*ciphertext) return 0;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        free(*ciphertext);
        return 0;
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) goto err;

    if (1 != EVP_EncryptUpdate(ctx, *ciphertext, &len, plaintext, plaintext_len)) goto err;
    ct_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, *ciphertext + len, &len)) goto err;
    ct_len += len;

    *ciphertext_len = ct_len;

    EVP_CIPHER_CTX_free(ctx);
    return 1;

err:
    EVP_CIPHER_CTX_free(ctx);
    free(*ciphertext);
    *ciphertext = NULL;
    return 0;
}

int aes_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                const unsigned char *key, const unsigned char *iv,
                unsigned char **plaintext, int *plaintext_len) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int pt_len;

    *plaintext = malloc(ciphertext_len);  // Ciphertext length is upper bound
    if (!*plaintext) return 0;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        free(*plaintext);
        return 0;
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) goto err;

    if (1 != EVP_DecryptUpdate(ctx, *plaintext, &len, ciphertext, ciphertext_len)) goto err;
    pt_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, *plaintext + len, &len)) goto err;
    pt_len += len;

    *plaintext_len = pt_len;

    EVP_CIPHER_CTX_free(ctx);
    return 1;

err:
    EVP_CIPHER_CTX_free(ctx);
    free(*plaintext);
    *plaintext = NULL;
    return 0;
}

int ecies_encrypt_aes_key(
    const unsigned char *aes_key, size_t key_len,
    EVP_PKEY *recipient_pubkey,
    unsigned char **wrapped_key, size_t *wrapped_len)
{
    int ret = 0;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *ephemeral_key = NULL;
    unsigned char shared_secret[32];
    size_t secret_len = sizeof(shared_secret);

    unsigned char *derived_key = NULL;
    size_t derived_key_len = 32;

    *wrapped_key = NULL;
    *wrapped_len = 0;

    // Generate ephemeral EC key pair
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0) goto cleanup;

    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1);
    if (EVP_PKEY_keygen(ctx, &ephemeral_key) <= 0) goto cleanup;

    // Derive shared secret using ECDH
    EVP_PKEY_CTX *derive_ctx = EVP_PKEY_CTX_new(ephemeral_key, NULL);
    if (!derive_ctx || EVP_PKEY_derive_init(derive_ctx) <= 0) goto cleanup;

    if (EVP_PKEY_derive_set_peer(derive_ctx, recipient_pubkey) <= 0) goto cleanup;
    if (EVP_PKEY_derive(derive_ctx, shared_secret, &secret_len) <= 0) goto cleanup;

    EVP_PKEY_CTX_free(derive_ctx);

    // Derive encryption key from shared secret
    derived_key = OPENSSL_malloc(derived_key_len);
    if (!derived_key) goto cleanup;

    if (!EVP_Digest(shared_secret, secret_len, derived_key, NULL, EVP_sha256(), NULL)) goto cleanup;

    // Encrypt AES key using derived key
    unsigned char iv[16];
    if (RAND_bytes(iv, sizeof(iv)) != 1) goto cleanup;

    unsigned char *ciphertext = NULL;
    int ciphertext_len = 0;

    if (!aes_encrypt(aes_key, key_len, derived_key, iv, &ciphertext, &ciphertext_len)) goto cleanup;

    // Package: [ephemeral pubkey (in DER)] + [IV] + [ciphertext]
    int ephkey_len = i2d_PUBKEY(ephemeral_key, NULL);
    if (ephkey_len <= 0) goto cleanup;

    *wrapped_len = ephkey_len + sizeof(iv) + ciphertext_len;
    *wrapped_key = malloc(*wrapped_len);
    if (!*wrapped_key) goto cleanup;

    unsigned char *p = *wrapped_key;
    i2d_PUBKEY(ephemeral_key, &p);  // writes DER key and moves the pointer
    memcpy(p, iv, sizeof(iv)); p += sizeof(iv);
    memcpy(p, ciphertext, ciphertext_len);

    ret = 1;

cleanup:
    if (ctx) EVP_PKEY_CTX_free(ctx);
    if (ephemeral_key) EVP_PKEY_free(ephemeral_key);
    if (derived_key) OPENSSL_free(derived_key);
    if (ciphertext) free(ciphertext);
    return ret;
}

int ecies_decrypt_aes_key(
    EVP_PKEY *recipient_privkey,
    const unsigned char *wrapped_key, size_t wrapped_len,
    unsigned char *aes_key_out, size_t *aes_key_len)
{
    int ret = 0;
    EVP_PKEY *ephemeral_key = NULL;
    EVP_PKEY_CTX *derive_ctx = NULL;
    unsigned char shared_secret[32];
    size_t secret_len = sizeof(shared_secret);
    unsigned char derived_key[32];

    const unsigned char *p = wrapped_key;
    size_t consumed = 0;

    // Parse ephemeral public key from DER
    ephemeral_key = d2i_PUBKEY(NULL, &p, wrapped_len);
    if (!ephemeral_key) goto cleanup;

    consumed = p - wrapped_key;
    if (wrapped_len < consumed + 16) goto cleanup;

    const unsigned char *iv = wrapped_key + consumed;
    const unsigned char *ciphertext = iv + 16;
    int ciphertext_len = wrapped_len - consumed - 16;

    // Derive shared secret
    derive_ctx = EVP_PKEY_CTX_new(recipient_privkey, NULL);
    if (!derive_ctx || EVP_PKEY_derive_init(derive_ctx) <= 0) goto cleanup;
    if (EVP_PKEY_derive_set_peer(derive_ctx, ephemeral_key) <= 0) goto cleanup;
    if (EVP_PKEY_derive(derive_ctx, shared_secret, &secret_len) <= 0) goto cleanup;

    EVP_PKEY_CTX_free(derive_ctx);
    derive_ctx = NULL;

    // Derive key from shared secret
    if (!EVP_Digest(shared_secret, secret_len, derived_key, NULL, EVP_sha256(), NULL)) goto cleanup;

    // Decrypt AES key
    unsigned char *plaintext = NULL;
    int plaintext_len = 0;

    if (!aes_decrypt(ciphertext, ciphertext_len, derived_key, iv, &plaintext, &plaintext_len)) goto cleanup;

    if ((size_t)plaintext_len > *aes_key_len) goto cleanup;

    memcpy(aes_key_out, plaintext, plaintext_len);
    *aes_key_len = plaintext_len;

    free(plaintext);
    ret = 1;

cleanup:
    if (ephemeral_key) EVP_PKEY_free(ephemeral_key);
    if (derive_ctx) EVP_PKEY_CTX_free(derive_ctx);
    return ret;
}


int generate_aes_key_and_iv(unsigned char *key, unsigned char *iv) {
    if (RAND_bytes(key, AES_KEY_SIZE) != 1) return 0;
    if (RAND_bytes(iv, AES_IV_LEN) != 1) return 0;
    return 1;
}

int sign_message(EVP_PKEY *pkey,
                 const unsigned char *msg, size_t msg_len,
                 unsigned char **signature, size_t *sig_len) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return 0;

    int ret = 0;
    *signature = NULL;

    if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey) != 1) goto cleanup;
    if (EVP_DigestSignUpdate(ctx, msg, msg_len) != 1) goto cleanup;

    // Get signature length
    if (EVP_DigestSignFinal(ctx, NULL, sig_len) != 1) goto cleanup;

    *signature = malloc(*sig_len);
    if (!*signature) goto cleanup;

    if (EVP_DigestSignFinal(ctx, *signature, sig_len) != 1) goto cleanup;

    ret = 1;  // success

cleanup:
    EVP_MD_CTX_free(ctx);
    if (!ret && *signature) {
        free(*signature);
        *signature = NULL;
    }
    return ret;
}

int verify_signature(EVP_PKEY *pkey,
                     const unsigned char *msg, size_t msg_len,
                     const unsigned char *signature, size_t sig_len) {
    int ret = 0;
    EVP_MD_CTX *mdctx = NULL;

    mdctx = EVP_MD_CTX_new();
    if (!mdctx) goto cleanup;

    if (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pkey) != 1)
        goto cleanup;

    if (EVP_DigestVerifyUpdate(mdctx, msg, msg_len) != 1)
        goto cleanup;

    ret = EVP_DigestVerifyFinal(mdctx, signature, sig_len);

cleanup:
    if (mdctx) EVP_MD_CTX_free(mdctx);

    return ret == 1;  // 1 = success, 0 = fail, -1 = error
}


bool build_secure_message_package(
    const unsigned char *plaintext,
    size_t plaintext_len,
    EVP_PKEY *sender_privkey,
    EVP_PKEY *recipient_pubkey,
    SecureMessage *out_msg
) {
    unsigned char aes_key[AES_KEY_SIZE];
    unsigned char iv[AES_IV_LEN];

    // 1. Generate AES key + IV
    if (!generate_aes_key_and_iv(aes_key, iv)) {
        fprintf(stderr, "Failed to generate AES key and IV\n");
        return false;
    }

    // 2. Encrypt plaintext using AES
    unsigned char *ciphertext = NULL;
    int ciphertext_len = 0;
    if (!aes_encrypt(plaintext, plaintext_len, aes_key, iv, &ciphertext, &ciphertext_len)) {
        fprintf(stderr, "AES encryption failed\n");
        return false;
    }

    // 3. Wrap AES key using ECIES
    unsigned char *wrapped_key = NULL;
    size_t wrapped_key_len = 0;
    if (!ecies_encrypt_aes_key(aes_key, AES_KEY_SIZE, recipient_pubkey, &wrapped_key, &wrapped_key_len)) {
        fprintf(stderr, "Failed to wrap AES key\n");
        free(ciphertext);
        return false;
    }

    // 4. Create signed message to sign: [wrapped_key || iv || ciphertext]
    size_t signed_len = wrapped_key_len + AES_IV_LEN + ciphertext_len;
    unsigned char *signed_data = malloc(signed_len);
    if (!signed_data) return false;

    memcpy(signed_data, wrapped_key, wrapped_key_len);
    memcpy(signed_data + wrapped_key_len, iv, AES_IV_LEN);
    memcpy(signed_data + wrapped_key_len + AES_IV_LEN, ciphertext, ciphertext_len);

    // 5. Sign the signed_data
    unsigned char *signature = NULL;
    size_t signature_len = 0;
    if (!sign_message(sender_privkey, signed_data, signed_len, &signature, &signature_len)) {
        fprintf(stderr, "Failed to sign message\n");
        free(ciphertext); free(wrapped_key); free(signed_data);
        return false;
    }

    // 6. Package everything
    size_t total_size = 2 + wrapped_key_len + AES_IV_LEN + 4 + ciphertext_len + 2 + signature_len;
    unsigned char *buffer = malloc(total_size);
    if (!buffer) {
        fprintf(stderr, "Allocation failed for SecureMessage\n");
        free(ciphertext); free(wrapped_key); free(signed_data); free(signature);
        return false;
    }

    unsigned char *ptr = buffer;

    // 6.1 Add wrapped_key_len (2B)
    uint16_t wrapped_len_n = htons((uint16_t)wrapped_key_len);
    memcpy(ptr, &wrapped_len_n, 2); ptr += 2;

    // 6.2 Add wrapped_key
    memcpy(ptr, wrapped_key, wrapped_key_len); ptr += wrapped_key_len;

    // 6.3 Add IV
    memcpy(ptr, iv, AES_IV_LEN); ptr += AES_IV_LEN;

    // 6.4 Add ciphertext_len (4B)
    uint32_t cipher_len_n = htonl((uint32_t)ciphertext_len);
    memcpy(ptr, &cipher_len_n, 4); ptr += 4;

    // 6.5 Add ciphertext
    memcpy(ptr, ciphertext, ciphertext_len); ptr += ciphertext_len;

    // 6.6 Add signature_len (2B)
    uint16_t sig_len_n = htons((uint16_t)signature_len);
    memcpy(ptr, &sig_len_n, 2); ptr += 2;

    // 6.7 Add signature
    memcpy(ptr, signature, signature_len);

    // Output the final package
    out_msg->data = buffer;
    out_msg->length = total_size;

    // Cleanup
    free(ciphertext);
    free(wrapped_key);
    free(signed_data);
    free(signature);
    return true;
}

bool parse_and_decrypt_secure_message(
    const SecureMessage *msg,
    EVP_PKEY *recipient_privkey,
    EVP_PKEY *sender_pubkey,
    unsigned char **plaintext_out,
    size_t *plaintext_len_out
) {
    const unsigned char *ptr = msg->data;
    const unsigned char *end = msg->data + msg->length;

    uint16_t wrapped_key_len = 0;
    uint32_t ciphertext_len = 0;
    uint16_t signature_len = 0;

    unsigned char *wrapped_key = NULL;
    unsigned char iv[AES_IV_LEN];
    unsigned char *ciphertext = NULL;
    unsigned char *signature = NULL;
    unsigned char aes_key[AES_KEY_SIZE];
    size_t unwrapped_key_len = AES_KEY_SIZE;

    // Helper macros
    #define READ_UINT16(var) do { \
        if (ptr + 2 > end) return false; \
        var = (ptr[0] << 8) | ptr[1]; \
        ptr += 2; \
    } while(0)

    #define READ_UINT32(var) do { \
        if (ptr + 4 > end) return false; \
        var = (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | ptr[3]; \
        ptr += 4; \
    } while(0)

    // Step 1: Extract wrapped_key_len (2 bytes)
    READ_UINT16(wrapped_key_len);
    if (ptr + wrapped_key_len > end) return false;
    wrapped_key = malloc(wrapped_key_len);
    if (!wrapped_key) return false;
    memcpy(wrapped_key, ptr, wrapped_key_len);
    ptr += wrapped_key_len;

    // Step 2: Extract IV (fixed AES_IV_LEN bytes)
    if (ptr + AES_IV_LEN > end) {
        free(wrapped_key);
        return false;
    }
    memcpy(iv, ptr, AES_IV_LEN);
    ptr += AES_IV_LEN;

    // Step 3: Extract ciphertext_len (4 bytes)
    READ_UINT32(ciphertext_len);
    if (ptr + ciphertext_len > end) {
        free(wrapped_key);
        return false;
    }
    ciphertext = malloc(ciphertext_len);
    if (!ciphertext) {
        free(wrapped_key);
        return false;
    }
    memcpy(ciphertext, ptr, ciphertext_len);
    ptr += ciphertext_len;

    // Step 4: Extract signature_len (2 bytes)
    READ_UINT16(signature_len);
    if (ptr + signature_len > end) {
        free(wrapped_key);
        free(ciphertext);
        return false;
    }
    signature = malloc(signature_len);
    if (!signature) {
        free(wrapped_key);
        free(ciphertext);
        return false;
    }
    memcpy(signature, ptr, signature_len);
    ptr += signature_len;

    // Step 5: Rebuild signed_data = [wrapped_key || iv || ciphertext]
    size_t signed_data_len = wrapped_key_len + AES_IV_LEN + ciphertext_len;
    unsigned char *signed_data = malloc(signed_data_len);
    if (!signed_data) {
        free(wrapped_key);
        free(ciphertext);
        free(signature);
        return false;
    }
    unsigned char *p = signed_data;
    memcpy(p, wrapped_key, wrapped_key_len); p += wrapped_key_len;
    memcpy(p, iv, AES_IV_LEN); p += AES_IV_LEN;
    memcpy(p, ciphertext, ciphertext_len);

    // Step 6: Verify signature
    if (!verify_signature(sender_pubkey, signed_data, signed_data_len, signature, signature_len)) {
        fprintf(stderr, "Signature verification failed\n");
        free(wrapped_key);
        free(ciphertext);
        free(signature);
        free(signed_data);
        return false;
    }

    // Step 7: Decrypt AES key using ECIES with recipient's private key
    if (!ecies_decrypt_aes_key(recipient_privkey, wrapped_key, wrapped_key_len, aes_key, &unwrapped_key_len)) {
        fprintf(stderr, "AES key unwrap failed\n");
        free(wrapped_key);
        free(ciphertext);
        free(signature);
        free(signed_data);
        return false;
    }

    // Step 8: Decrypt ciphertext using AES key and IV
    int decrypted_len = 0;
    if (!aes_decrypt(ciphertext, ciphertext_len, aes_key, iv, plaintext_out, &decrypted_len)) {
        fprintf(stderr, "AES decryption failed\n");
        free(wrapped_key);
        free(ciphertext);
        free(signature);
        free(signed_data);
        return false;
    }

    *plaintext_len_out = (size_t)decrypted_len;

    // Cleanup
    free(wrapped_key);
    free(ciphertext);
    free(signature);
    free(signed_data);

    return true;
}