/*
 * Fernet implementation
 * Last update: 02/22/2020
 * Issue date:  02/22/2020
 *
 * Copyright (C) 2020 Zhanhua Kuang <zhanhua.kuang@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <endian.h>
#include <ctype.h>
#include <time.h>

#include "base64.h"
#include "aes.h"
#include "hmac_sha2.h"
#include "fernet.h"

#define FERNET_B64_KEY_LEN 44
#define FERNET_KEY_LEN 32
#define FERNET_VERSION 128
#define FERNET_VERSION_LEN 1
#define FERNET_TIMESTAMP_LEN 8
#define FERNET_IV_LEN 16
#define FERNET_HMAC_LEN 32
#define FERNET_PARTIAL_KEY_LEN 16
#define FERNET_OVERHEAD (FERNET_VERSION_LEN + FERNET_TIMESTAMP_LEN + FERNET_IV_LEN + FERNET_HMAC_LEN)

static int32_t decompose_keys(const uint8_t* key, uint8_t key_bin[], uint8_t** signing_key, uint8_t** encrypt_key) {

    size_t key_len = b64_decode(key, FERNET_B64_KEY_LEN, key_bin);
    if (key_len != FERNET_KEY_LEN) {
        return FERNET_INV_KEY;
    }
    *signing_key = key_bin;
    *encrypt_key = &key_bin[FERNET_PARTIAL_KEY_LEN];

#ifdef FERNET_DEBUG
    printf("key:\t");
    for(int i = 0; i < FERNET_KEY_LEN; i++) {
        printf("%02hhx", key_bin[i]);
    }
    printf("\n");
#endif

    return FERNET_OK;
}

static int32_t decompose_token(const uint8_t* token, size_t token_len, uint8_t** version, uint8_t** timestamp, uint8_t** iv,
                            uint8_t** hmac, uint8_t** data, size_t *data_len, uint8_t token_bin[], size_t *token_bin_len) {
    if (*token_bin_len < (token_len * 133 / 100 + 1)) return FERNET_INS_BUF;

    *token_bin_len = b64_decode(token, token_len, token_bin);
    *data_len = *token_bin_len - FERNET_OVERHEAD;

#ifdef FERNET_DEBUG
    printf("token:\t");
    for(size_t i = 0; i < *token_bin_len; i++) {
        printf("%02hhx", token_bin[i]);
    }
    printf("\n");
#endif

    if (*data_len <= 0 || *data_len % 16 != 0) {
#ifdef FERNET_DEBUG
        printf("invalid token len %lu.", *token_bin_len);
#endif
        return FERNET_INV_TOKEN;
    }    

    *version = token_bin;
    *timestamp = &token_bin[FERNET_VERSION_LEN];
    *iv = &token_bin[FERNET_VERSION_LEN + FERNET_TIMESTAMP_LEN];
    *hmac = &token_bin[*token_bin_len - FERNET_HMAC_LEN];
    *data = &token_bin[FERNET_VERSION_LEN + FERNET_TIMESTAMP_LEN + FERNET_IV_LEN];

    return FERNET_OK;
}

static int32_t check_vesrion(uint8_t* version) {
#ifdef FERNET_DEBUG
    printf("version: %d\n", *version);
#endif
    return *version != FERNET_VERSION;
}

static void generate_hmac(uint8_t* message, size_t message_len, uint8_t* signing_key, uint8_t hmac[]) {
    #ifdef FERNET_DEBUG
        printf("signing key:\t");
        for (int i = 0; i < FERNET_PARTIAL_KEY_LEN; i++) {
            printf("%02hhx", signing_key[i]);
        }
        printf("\n");

        printf("message:\t");
        for (int i = 0; i < message_len; i++) {
            printf("%02hhx", message[i]);
        }
        printf("\n");
    #endif

    hmac_sha256(signing_key, FERNET_PARTIAL_KEY_LEN, message, message_len, hmac, FERNET_HMAC_LEN);
}

static int32_t validate_hmac(const uint8_t hmac[FERNET_HMAC_LEN], uint8_t* token_bin, size_t token_bin_len, uint8_t* signing_key) {
    uint8_t hash[FERNET_HMAC_LEN];
    generate_hmac(token_bin, token_bin_len - FERNET_HMAC_LEN, signing_key, hash);

#ifdef FERNET_DEBUG
    printf("hmac: \n\t");
    for (int i = 0; i < FERNET_HMAC_LEN; i++) {
        printf("%02hhx", hmac[i]);
    }
    printf("\n\t");
    for (int i = 0; i < FERNET_HMAC_LEN; i++) {
        printf("%02hhx", hash[i]);
    }
    printf("\n");
#endif
    if (memcmp(hmac, hash, FERNET_HMAC_LEN)) {
        return FERNET_INV_TOKEN;
    }
    return FERNET_OK;
}

static int32_t decrypt_data(uint8_t *encrypt_key, uint8_t *iv, uint8_t* data, uint32_t data_len) {
    struct AES_ctx ctx;

#ifdef FERNET_DEBUG
    printf("encrypt key:\t");
    for(int i = 0; i < FERNET_PARTIAL_KEY_LEN; i++) {
        printf("%02hhx", encrypt_key[i]);
    }
    printf("\n");
    printf("iv:\t");
    for(int i = 0; i < FERNET_IV_LEN; i++) {
        printf("%02hhx", iv[i]);
    }
    printf("\n");
#endif

    AES_init_ctx_iv(&ctx, encrypt_key, iv);

#ifdef FERNET_DEBUG
    printf("encrypted:\t");
    for(int i = 0; i < data_len; i++) {
        printf("%02hhx", data[i]);
    }
    printf("\t%d\n", data_len);
#endif

    AES_CBC_decrypt_buffer(&ctx, data, data_len);
#ifdef FERNET_DEBUG
    printf("decrypted:\t");
    for(int i = 0; i < data_len; i++) {
        printf("%02hhx", data[i]);
    }
    printf("\t%d\n", data_len);
#endif

    uint8_t padv = data[data_len - 1];

#ifdef FERNET_DEBUG
    printf("padv: %d.\n", padv);
#endif
    for (uint32_t i = data_len - 2; i >= data_len - padv; i--) {
        if (data[i] != padv) {
            if (i == data_len - 2) {
                break;
            } else {
                return FERNET_INV_TOKEN;
            }
        }
    }
    data_len -= padv;
    data[data_len] = '\0';

#ifdef FERNET_DEBUG
    printf("decrypted pure data:\t");
    for(int i = 0; i < data_len; i++) {
        printf("%02hhx", data[i]);
    }
    printf("\t%d\n", data_len);
#endif
    return FERNET_OK;
}

int32_t fernet_decrypt(const uint8_t* token, size_t token_len, const uint8_t* key, uint8_t* buf, size_t *buf_len) {
    uint8_t* version;
    uint8_t* timestamp;
    uint8_t* iv;
    uint8_t* hmac;
    uint8_t* data;
    uint8_t token_bin[FERNET_INTERNAL_BUF_LEN];
    uint8_t key_bin[FERNET_KEY_LEN];
    uint8_t* signing_key;
    uint8_t* encrypt_key;
    size_t data_len;
    size_t token_bin_len = FERNET_INTERNAL_BUF_LEN;

    int32_t res = decompose_keys(key, key_bin, &signing_key, &encrypt_key);
    if (res) return res;

    res = decompose_token(token, token_len, &version, &timestamp, &iv, &hmac, &data, &data_len, token_bin, &token_bin_len);
    if (res) return res;

    res = check_vesrion(version);
    if (res) return res;

    res = validate_hmac(hmac, token_bin, token_bin_len, signing_key);
    if (res) return res;

    if (*buf_len < data_len) return FERNET_INS_BUF;
    
    for (uint32_t i = 0; i < data_len; i++) {
        buf[i] = data[i];
    }
    res = decrypt_data(encrypt_key, iv, buf, data_len);
    if (res) return res;

    *buf_len = data_len;
    return FERNET_OK;
}

int32_t fernet_generate_key(uint8_t* buf) {
    uint8_t bytes[FERNET_KEY_LEN];
    for (int i = 0; i < FERNET_KEY_LEN; i++) {
        bytes[i] = rand() % 256;
    }
    b64_encode(bytes, FERNET_KEY_LEN, buf);
    return FERNET_OK;
}

static void generate_iv(uint8_t* iv) {
    for (int i = 0; i < FERNET_IV_LEN; i++) {
        iv[i] = rand() % 256;
    }

#ifdef FERNET_DEGUB
    printf("iv:\t");
    for (int i = 0; i < FERNET_IV_LEN; i++) {
        printf("%hhx", iv[i]);
    }
    printf("\n");
#endif
}

static void generate_version(uint8_t* version) {
    *version = FERNET_VERSION;
}

static void generate_timestamp(uint8_t* timestamp) {
    time_t t = time(NULL);
    uint64_t res = t;
    res = htobe64(res);
#ifdef FERNET_DEBUG
    uint8_t *tp = &res;
    printf("timestamp:\t%lu\n", t);
    for(int i=0; i<8; i++) {
        printf("%02hhx", tp[i]);
    }
    printf("\n");
#endif
    memcpy((void *)timestamp, (void *)&res, 8);
}

static int32_t encrypt_data(uint8_t *encrypt_key, uint8_t *iv, uint8_t* data, size_t data_len, size_t *buf_len) {
    struct AES_ctx ctx;

#ifdef FERNET_DEBUG
    printf("encrypt key:\t");
    for(int i = 0; i < FERNET_PARTIAL_KEY_LEN; i++) {
        printf("%02hhx", encrypt_key[i]);
    }
    printf("\n");
    printf("iv:\t");
    for(int i = 0; i < FERNET_IV_LEN; i++) {
        printf("%02hhx", iv[i]);
    }
    printf("\n");
#endif

    AES_init_ctx_iv(&ctx, encrypt_key, iv);

#ifdef FERNET_DEBUG
    printf("raw:\t");
    for(int i = 0; i < data_len; i++) {
        printf("%02hhx", data[i]);
    }
    printf("\t%lu\n", data_len);
#endif

    uint8_t padv = 16 - (data_len % 16);
    if (padv == 0) {
        padv = 16;
    }
    if (*buf_len < data_len + padv) {
        return FERNET_INS_BUF;
    }
    for(int i = 0; i < padv; i++) {
        data[data_len + i] = padv;
    }

    *buf_len = data_len + padv;
#ifdef FERNET_DEBUG
    printf("with padding:\t");
    for(int i = 0; i < data_len + padv; i++) {
        printf("%02hhx", data[i]);
    }
    printf("\t%lu\n", *buf_len);
#endif


    AES_CBC_encrypt_buffer(&ctx, data, data_len + padv);
#ifdef FERNET_DEBUG
    printf("encrypted:\t");
    for(int i = 0; i < data_len + padv; i++) {
        printf("%02hhx", data[i]);
    }
    printf("\t%lu\n", *buf_len);
#endif
    return FERNET_OK;
}

int32_t fernet_encrypt(const char* data, size_t data_len, const uint8_t* key, uint8_t* buf, size_t *buf_len) {
    uint8_t key_bin[FERNET_KEY_LEN];
    uint8_t* signing_key;
    uint8_t* encrypt_key;
    uint8_t token_bin[FERNET_INTERNAL_BUF_LEN];
    size_t token_bin_data_len = FERNET_INTERNAL_BUF_LEN - FERNET_OVERHEAD;

    uint8_t* version = token_bin;
    uint8_t* timestamp = &token_bin[FERNET_VERSION_LEN];
    uint8_t* iv = &token_bin[FERNET_VERSION_LEN + FERNET_TIMESTAMP_LEN];
    uint8_t* _data = &token_bin[FERNET_VERSION_LEN + FERNET_TIMESTAMP_LEN + FERNET_IV_LEN];
    uint8_t* hmac;

    int32_t res = decompose_keys(key, key_bin, &signing_key, &encrypt_key);
    if (res) return res;
    generate_version(version);
    generate_timestamp(timestamp);
    generate_iv(iv);

    memcpy((void*)_data, (void *)data, data_len);
    res = encrypt_data(encrypt_key, iv, _data, data_len, &token_bin_data_len);
    if (res) return res;
    hmac = &token_bin[FERNET_VERSION_LEN + FERNET_TIMESTAMP_LEN + FERNET_IV_LEN + token_bin_data_len];

    generate_hmac(token_bin, FERNET_VERSION_LEN + FERNET_TIMESTAMP_LEN + FERNET_IV_LEN + token_bin_data_len, signing_key, hmac);
    
    // *buf_len = FERNET_OVERHEAD + token_bin_data_len;
    *buf_len = b64_encode(token_bin, FERNET_OVERHEAD + token_bin_data_len, buf);
    return FERNET_OK;
}
