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
#include "data_unwrap.h"

int data_unwrap_finalize(
	odd_ctx* ctx,
	const crypto_backend* crypto,
	proto_out* inout
) {
	size_t klen, ivlen = 0;
	size_t wrote = 0;
	const uint8_t* key = odd_ctx_unwrap_key_ref(ctx, ODD_UNWRAP_KEY_1, &klen);
	if (!key || klen != 16) {
		return -1;
	}
	const uint8_t* iv = odd_ctx_iv_ref(ctx, ODD_IV_4, &ivlen);
	if (!iv || ivlen != 16) {
		return -1;
	}
	int ret = crypto->v->aes128_cbc_nopad_enc(crypto->user, key, iv, inout->a, 16, inout->a, 16, &wrote);
	if (ret != 0 || wrote != 16) {
		return -1;
	}

	key = odd_ctx_unwrap_key_ref(ctx, ODD_UNWRAP_KEY_2, &klen);
	if (!key || klen != 16) {
		return -1;
	}
	iv = odd_ctx_iv_ref(ctx, ODD_IV_1, &ivlen);
	if (!iv || ivlen != 16) {
		return -1;
	}
	ret = crypto->v->aes128_cbc_nopad_dec(crypto->user, key, iv, inout->b, 16, inout->b, 16, &wrote);
	if (ret != 0 || wrote != 16) {
		return -1;
	}
	return 0;
}
