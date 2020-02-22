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

#include <string.h>
#include <stdio.h>
#include "./fernet.h"

const char* KEY = "iV6R18Ne7wiVZ4GxwSyVmGMdaSAwH_2phk-1IxXc4n0=";
const char* TOKEN = "gAAAAABeT-3TPA-ZkeRYai_-yUMI7mcOtSn7cLCrt-1YvFp-a1IG5ZjuMzR-h4NVtdIk3PomaPY7LXydv0xNeDDZ1hC-UwFqZ9TBnpPzFr78IMbboAEM60A_noLQ4XVPLnR4o6YvM7ox";

int main() {
    size_t buf_len = 1024;
    uint8_t buf[1024];
    uint8_t key[45];
    memset(buf, '\0', 1024);

    fernet_generate_key(key);

    const char *msg = "hello world!!!12";
    if(fernet_encrypt(msg, strlen(msg), key, buf, &buf_len) != 0) {
        return -1;
    }
    size_t token_len = buf_len;
    buf_len = 1024;

    if(fernet_decrypt(buf, token_len, key, buf, &buf_len) != 0) {
        return -1;
    }
    printf("%s\n", buf);

    return 0;
}