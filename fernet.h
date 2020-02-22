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

#ifndef _FERNET_H_
#define _FERNET_H_
#include <stdint.h>
#include <stddef.h>

// token : the fernet token to be decrypted, token must be base64 url safe encoded.
// token_len : number of bytes of the token.
// key: the key to decrypt the token, key len must be base64 url safe endcode encoded of 44.
// buf : pointer to buffer with enough memory for decrypted data, user is responsible for memory allocation
// buf_len: number of bytes of the buf, and receives the actual len of the decrypted data
// return FERNET_OK if decrypt success
//        FERNET_INV_TOKEN if the token is not valid
//        FERNET_INV_KEY if the key is not valid
//        FERNET_INS_BUF if the buffer is too small
int32_t fernet_decrypt(const uint8_t* token, size_t token_len, const uint8_t* key, uint8_t* buf, size_t *buf_len);

// buf: pointer to buffer with enough memory for storing the base64 url safe encoded key, user is responsible for memory allocation
//      the size of the buffer must be larger than 45bytes, and the key is exactly 44bytes plus a null-terminator.
int32_t fernet_generate_key(uint8_t* buf);

// data : the data to be encrypted.
// data_len : number of bytes of the data.
// key: the key to encrypt the token, key len must be base64 url safe endcode encoded of 44.
// buf : pointer to buffer with enough memory for storing the encrypted token, user is responsible for memory allocation
// buf_len: number of bytes of the buf, and receives the actual len of the decrypted data
// return FERNET_OK if decrypt success
//        FERNET_INV_TOKEN if the token is not valid
//        FERNET_INV_KEY if the key is not valid
//        FERNET_INS_BUF if the buffer is too small
int32_t fernet_encrypt(const char* data, size_t data_len, const uint8_t* key, uint8_t* buf, size_t *buf_len);

#define FERNET_INV_TOKEN -1
#define FERNET_INV_KEY -2
#define FERNET_INS_BUF -3
#define FERNET_OK 0
#define FERNET_INTERNAL_BUF_LEN 2048

// #define FERNET_DEBUG

#endif // __FERNET_H_