/**
 * Copyright 2026 sarami@ChatGPT
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "session_keys.h"
#include "session_keys_internal.h"
#include <stdlib.h>
#include <string.h>

struct session_keys {
	unsigned char key_a[16];
	unsigned char key_b[16];
	int have_keys;
};

session_keys* session_keys_create(void)
{
	session_keys* sk = (session_keys*)calloc(1, sizeof(*sk));
	return sk;
}

void session_keys_destroy(
	session_keys* sk
) {
	free(sk);
}

int session_keys_establish(
	odd_ctx* ctx,
	const crypto_backend* crypto,
	const drive_transport* tr,
	session_keys* sk,
	int selection
) {
	unsigned char header[4] = {
		0, 16, 0, 0
	};
	unsigned char response[20];   // 4 + 16
	memcpy(response, header, 4);

	size_t klen = 0, ivlen = 0;
	const uint8_t* key_select1 = NULL;
	if (selection == 0) {
		key_select1 = odd_ctx_default_key_ref(ctx, ODD_DEFAULT_KEY_1, &klen);
	}
	else if (selection == 1) {
		key_select1 = odd_ctx_user_key_ref(ctx, ODD_USER_KEY_1_4, &klen);
	}
	if (!key_select1 || klen != 16) {
		return -1;
	}

	const uint8_t* iv = odd_ctx_iv_ref(ctx, ODD_IV_1, &ivlen);
	if (!iv || ivlen != 16) {
		return -1;
	}

	unsigned char challenge[16] = {
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
	};
	size_t wrote = 0;
	int res = crypto->v->aes128_cbc_nopad_enc(crypto->user, key_select1, iv, challenge, 16, response + 4, 16, &wrote);
	if (res != 0 || wrote != 16) {
		return -1;
	}

	res = tr->v->send_blob(tr->dev, selection, response, sizeof(response));
	if (res == -1) {
		return -1;
	}

	unsigned char receive[36];   // 4 + 16 + 16
	res = tr->v->recv_blob(tr->dev, selection, receive, sizeof(receive), &wrote);
	if (res == -1) {
		return -1;
	}
	
	const uint8_t* key_select2 = NULL;
	if (selection == 0) {
		key_select2 = odd_ctx_default_key_ref(ctx, ODD_DEFAULT_KEY_2, &klen);
	}
	else if (selection == 1) {
		key_select2 = odd_ctx_user_key_ref(ctx, ODD_USER_KEY_2_4, &klen);
	}
	if (!key_select2 || klen != 16) {
		return -1;
	}

	unsigned char establish_out1[16];
	res = crypto->v->aes128_cbc_nopad_dec(crypto->user, key_select2, iv, receive + 4, 16, establish_out1, 16, &wrote);
	if (res != 0 || wrote != 16) {
		return -1;
	}

	unsigned char establish_out2[16];
	res = crypto->v->aes128_cbc_nopad_dec(crypto->user, key_select2, iv, receive + 20, 16, establish_out2, 16, &wrote);
	if (res != 0 || wrote != 16) {
		return -1;
	}

	for (int i = 0; i < 16; ++i) {
		if (challenge[i] != establish_out1[i]) {
			return -1;
		}
	}

	unsigned char tmp[16];
	memcpy(tmp, establish_out1, 8);
	memcpy(tmp + 8, establish_out2 + 8, 8);
	const uint8_t* key = odd_ctx_input_key_ref(ctx, ODD_INPUT_KEY_1, &klen);
	if (!key || klen != 16) {
		return -1;
	}
	res = crypto->v->aes128_cbc_nopad_enc(crypto->user, key, iv, tmp, 16, sk->key_a, 16, &wrote);
	if (res != 0 || wrote != 16) {
		return -1;
	}

	memcpy(tmp, establish_out1 + 8, 8);
	memcpy(tmp + 8, establish_out2, 8);
	key = odd_ctx_input_key_ref(ctx, ODD_INPUT_KEY_2, &klen);
	if (!key || klen != 16) {
		return -1;
	}
	res = crypto->v->aes128_cbc_nopad_enc(crypto->user, key, iv, tmp, 16, sk->key_b, 16, &wrote);
	if (res != 0 || wrote != 16) {
		return -1;
	}
	sk->have_keys = 1;

	if (selection == 0) {
		memcpy(response, header, 4);

		res = crypto->v->aes128_cbc_nopad_enc(crypto->user, key_select1, iv, establish_out2, 16, response + 4, 16, &wrote);
		if (res != 0 || wrote != 16) {
			return -1;
		}

		res = tr->v->send_blob(tr->dev, 2, response, sizeof(response));
		if (res == -1) {
			return -1;
		}
	}
	else {
		res = tr->v->recv_blob(tr->dev,  selection, receive, sizeof(receive), &wrote);
		if (res == -1) {
			return -1;
		}
	}
	return 0;
}

const uint8_t* session_keys_key_a_ref(
	const session_keys* sk,
	size_t* len
) {
	if (len) {
		*len = 0;
	}
	if (!sk || !sk->have_keys) {
		return NULL;
	}
	if (len) {
		*len = 16;
	}
	return sk->key_a;
}

const uint8_t* session_keys_key_b_ref(
	const session_keys* sk,
	size_t* len
) {
	if (len) {
		*len = 0;
	}
	if (!sk || !sk->have_keys) {
		return NULL;
	}
	if (len) {
		*len = 16;
	}
	return sk->key_b;
}
