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
#include "drive_proto.h"
#include "session_keys_internal.h"

int drive_proto_authenticate(
	odd_ctx* ctx,
	const crypto_backend* crypto,
	const drive_transport* tr,
	session_keys* sk
) {
	unsigned char tx_frame84[84];
	tx_frame84[0] = 0;
	tx_frame84[1] = 80;
	tx_frame84[2] = 0;
	tx_frame84[3] = 0;

	size_t klen, ivlen, paramlen = 0;
	const uint8_t* key = session_keys_key_a_ref(sk, &klen);
	if (!key || klen != 16) {
		return -1;
	}
	const uint8_t* iv = odd_ctx_iv_ref(ctx, ODD_IV_3, &ivlen);
	if (!iv || ivlen != 16) {
		return -1;
	}
	const uint8_t* param = odd_ctx_paramset_ref(ctx, ODD_PARAMSET_4, &paramlen);
	if (!param || paramlen != 80) {
		return -1;
	}
	size_t wrote = 0;
	int ret = crypto->v->aes128_cbc_nopad_enc(crypto->user, key, iv, param, paramlen, tx_frame84 + 4, 80, &wrote);
	if (ret != 0 || wrote != 80) {
		return -1;
	}

	unsigned char auth_out[8];

	iv = odd_ctx_iv_ref(ctx, ODD_IV_2, &ivlen);
	if (!iv || ivlen != 8) {
		return -1;
	}
	const uint8_t* in = odd_ctx_const_ref(ctx, ODD_CONST_1, &paramlen);
	if (!in || paramlen != 8) {
		return -1;
	}
	ret = crypto->v->tdes_ede_cbc_nopad_enc(crypto->user, key, iv, in, 8, auth_out, 8, &wrote);
	if (ret != 0 || wrote != 8) {
		return -1;
	}
	ret = tr->v->vendor_cmd_b(tr->dev, auth_out, 0, tx_frame84, 84, &wrote);
	if (ret != 0 || wrote != 84) {
		return -1;
	}
	return 0;
}

int drive_proto_get_two_blobs(
	odd_ctx* ctx,
	const crypto_backend* crypto,
	const drive_transport* tr,
	const session_keys* sk,
	proto_out* out_enc
) {
	unsigned char tx_frame84[84];
	tx_frame84[0] = 0;
	tx_frame84[1] = 80;
	tx_frame84[2] = 0;
	tx_frame84[3] = 0;

	size_t klen, ivlen, paramlen = 0;
	const uint8_t* key = session_keys_key_a_ref(sk, &klen);
	if (!key || klen != 16) {
		return -1;
	}
	const uint8_t* iv3 = odd_ctx_iv_ref(ctx, ODD_IV_3, &ivlen);
	if (!iv3 || ivlen != 16) {
		return -1;
	}
	size_t wrote = 0;
	const uint8_t* param = odd_ctx_paramset_ref(ctx, ODD_PARAMSET_3, &paramlen);
	if (!param || paramlen != 80) {
		return -1;
	}
	int ret = crypto->v->aes128_cbc_nopad_enc(crypto->user, key, iv3, param, paramlen, tx_frame84 + 4, paramlen, &wrote);
	if (ret != 0 || wrote != 80) {
		return -1;
	}

	unsigned char get_out[8];

	const uint8_t* iv2 = odd_ctx_iv_ref(ctx, ODD_IV_2, &ivlen);
	if (!iv2 || ivlen != 8) {
		return -1;
	}
	const uint8_t* in = odd_ctx_const_ref(ctx, ODD_CONST_2, &paramlen);
	if (!in || paramlen != 8) {
		return -1;
	}
	ret = crypto->v->tdes_ede_cbc_nopad_enc(crypto->user, key, iv2, in, 8, get_out, 8, &wrote);
	if (ret != 0 || wrote != 8) {
		return -1;
	}

	ret = tr->v->vendor_cmd_b(tr->dev, get_out, 0, tx_frame84, 84, &wrote);
	if (ret != 0 || wrote != 84) {
		return -1;
	}

	in = odd_ctx_const_ref(ctx, ODD_CONST_3, &paramlen);
	if (!in || paramlen != 8) {
		return -1;
	}
	ret = crypto->v->tdes_ede_cbc_nopad_enc(crypto->user, key, iv2, in, 8, get_out, 8, &wrote);
	if (ret != 0 || wrote != 8) {
		return -1;
	}

	ret = tr->v->vendor_cmd_a(tr->dev, get_out, 0, tx_frame84, 52, &wrote);
	if (ret != 0 || wrote != 52) {
		return -1;
	}

	unsigned char get_out2[48];

	ret = crypto->v->aes128_cbc_nopad_dec(crypto->user, key, iv3, tx_frame84 + 4, 48, get_out2, 48, &wrote);
	if (ret != 0 || wrote != 48) {
		return -1;
	}

	key = session_keys_key_b_ref(sk, &klen);
	if (!key || klen != 16) {
		return -1;
	}
	ret = crypto->v->aes128_cbc_nopad_dec(crypto->user, key, iv3, get_out2 + 3, 16, out_enc->a, 16, &wrote);
	if (ret != 0 || wrote != 16) {
		return -1;
	}
	ret = crypto->v->aes128_cbc_nopad_dec(crypto->user, key, iv3, get_out2 + 19, 16, out_enc->b, 16, &wrote);
	if (ret != 0 || wrote != 16) {
		return -1;
	}
	return 0;
}
