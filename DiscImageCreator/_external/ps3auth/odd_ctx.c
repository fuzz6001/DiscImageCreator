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
#include "odd_tables.h"
#include <stdlib.h>
#include <string.h>

struct odd_ctx {
	unsigned char iv1[16];
	unsigned char ivs_3des[8];
	unsigned char ivs_aes[16];
	unsigned char ivs_unwrap[16];
	unsigned char default_key1[16];
	unsigned char default_key2[16];
	unsigned char user_key1_u0[16];
	unsigned char user_key2_u0[16];
	unsigned char user_key1_u1[16];
	unsigned char user_key2_u1[16];
	unsigned char user_key1_u2[16];
	unsigned char user_key2_u2[16];
	unsigned char user_key1_u3[16];
	unsigned char user_key2_u3[16];
	unsigned char user_key1_u4[16];
	unsigned char user_key2_u4[16];
	unsigned char input_key1[16];
	unsigned char input_key2[16];
	unsigned char const1[8];
	unsigned char const2[8];
	unsigned char const3[8];
	unsigned char paramset_0[80];
	unsigned char paramset_1[80];
	unsigned char paramset_2[80];
	unsigned char paramset_3[80];
	unsigned char paramset_4[80];
	unsigned char unwrap_key1[16];
	unsigned char unwrap_key2[16];
};

odd_ctx* odd_ctx_create(void)
{
	odd_ctx* ctx = (odd_ctx*)calloc(1, sizeof(*ctx));
	return ctx;
}

void odd_ctx_destroy(odd_ctx* ctx)
{
	free(ctx);
}

void odd_ctx_load_ivs(
	odd_ctx* ctx
) {
	size_t len = 0;
	const uint8_t* p = NULL;

	p = odd_tables_iv_ref(ODD_IV_1, &len);
	memcpy(ctx->iv1, p, 16);
	p = odd_tables_iv_ref(ODD_IV_2, &len);
	memcpy(ctx->ivs_3des, p, 8);
	p = odd_tables_iv_ref(ODD_IV_3, &len);
	memcpy(ctx->ivs_aes, p, 16);
	p = odd_tables_iv_ref(ODD_IV_4, &len);
	memcpy(ctx->ivs_unwrap, p, 16);
}

void odd_ctx_load_default_keys(
	odd_ctx* ctx
) {
	size_t len = 0;
	const uint8_t* p = NULL;

	p = odd_tables_default_key_ref(ODD_DEFAULT_KEY_1, &len);
	memcpy(ctx->default_key1, p, 16);
	p = odd_tables_default_key_ref(ODD_DEFAULT_KEY_2, &len);
	memcpy(ctx->default_key2, p, 16);
}

void odd_ctx_load_user_keys(
	odd_ctx* ctx
) {
	size_t len = 0;
	const uint8_t* p = NULL;

	p = odd_tables_user_key_ref(ODD_USER_KEY_1_0, &len);
	memcpy(ctx->user_key1_u0, p, 16);
	p = odd_tables_user_key_ref(ODD_USER_KEY_2_0, &len);
	memcpy(ctx->user_key2_u0, p, 16);
	p = odd_tables_user_key_ref(ODD_USER_KEY_1_1, &len);
	memcpy(ctx->user_key1_u1, p, 16);
	p = odd_tables_user_key_ref(ODD_USER_KEY_2_1, &len);
	memcpy(ctx->user_key2_u1, p, 16);
	p = odd_tables_user_key_ref(ODD_USER_KEY_1_2, &len);
	memcpy(ctx->user_key1_u2, p, 16);
	p = odd_tables_user_key_ref(ODD_USER_KEY_2_2, &len);
	memcpy(ctx->user_key2_u2, p, 16);
	p = odd_tables_user_key_ref(ODD_USER_KEY_1_3, &len);
	memcpy(ctx->user_key1_u3, p, 16);
	p = odd_tables_user_key_ref(ODD_USER_KEY_2_3, &len);
	memcpy(ctx->user_key2_u3, p, 16);
	p = odd_tables_user_key_ref(ODD_USER_KEY_1_4, &len);
	memcpy(ctx->user_key1_u4, p, 16);
	p = odd_tables_user_key_ref(ODD_USER_KEY_2_4, &len);
	memcpy(ctx->user_key2_u4, p, 16);
}

void odd_ctx_load_input_keys(
	odd_ctx* ctx
) {
	size_t len = 0;
	const uint8_t* p = NULL;

	p = odd_tables_input_key_ref(ODD_INPUT_KEY_1, &len);
	memcpy(ctx->input_key1, p, 16);
	p = odd_tables_input_key_ref(ODD_INPUT_KEY_2, &len);
	memcpy(ctx->input_key2, p, 16);
}

void odd_ctx_load_const(
	odd_ctx* ctx
) {
	size_t len = 0;
	const uint8_t* p = NULL;

	p = odd_tables_const_ref(ODD_CONST_1, &len);
	memcpy(ctx->const1, p, 8);
	p = odd_tables_const_ref(ODD_CONST_2, &len);
	memcpy(ctx->const2, p, 8);
	p = odd_tables_const_ref(ODD_CONST_3, &len);
	memcpy(ctx->const3, p, 8);
}

void odd_ctx_load_params(
	odd_ctx* ctx
) {
	size_t len = 0;
	const uint8_t* p = NULL;

	p = odd_tables_paramset_ref(ODD_PARAMSET_0, &len);
	memcpy(ctx->paramset_0, p, 80);
	p = odd_tables_paramset_ref(ODD_PARAMSET_1, &len);
	memcpy(ctx->paramset_1, p, 80);
	p = odd_tables_paramset_ref(ODD_PARAMSET_2, &len);
	memcpy(ctx->paramset_2, p, 80);
	p = odd_tables_paramset_ref(ODD_PARAMSET_3, &len);
	memcpy(ctx->paramset_3, p, 80);
	p = odd_tables_paramset_ref(ODD_PARAMSET_4, &len);
	memcpy(ctx->paramset_4, p, 80);
}

void odd_ctx_load_unwrap_keys(
	odd_ctx* ctx
) {
	size_t len = 0;
	const uint8_t* p = NULL;

	p = odd_tables_unwrap_key_ref(ODD_UNWRAP_KEY_1, &len);
	memcpy(ctx->unwrap_key1, p, 16);
	p = odd_tables_unwrap_key_ref(ODD_UNWRAP_KEY_2, &len);
	memcpy(ctx->unwrap_key2, p, 16);
}

const uint8_t* odd_ctx_iv_ref(
	const odd_ctx* ctx,
	odd_iv_id id,
	size_t* len
) {
	if (len) {
		*len = 0;
	}
	else {
		return NULL;
	}
	if (!ctx) {
		return NULL;
	}
	switch (id) {
	case ODD_IV_1: 
		*len = 16;
		return ctx->iv1;
	case ODD_IV_2:
		*len = 8;
		return ctx->ivs_3des;
	case ODD_IV_3:
		*len = 16;
		return ctx->ivs_aes;
	case ODD_IV_4:
		*len = 16;
		return ctx->ivs_unwrap;
	default:
		return NULL;
	}
}

const uint8_t* odd_ctx_default_key_ref(
	const odd_ctx* ctx,
	odd_default_key_id id,
	size_t* len
) {
	if (len) {
		*len = 0;
	}
	else {
		return NULL;
	}
	if (!ctx) {
		return NULL;
	}
	switch (id) {
	case ODD_DEFAULT_KEY_1:
		*len = 16;
		return ctx->default_key1;
	case ODD_DEFAULT_KEY_2:
		*len = 16;
		return ctx->default_key2;
	default:
		return NULL;
	}
}

const uint8_t* odd_ctx_user_key_ref(
	const odd_ctx* ctx,
	odd_user_key_id id,
	size_t* len
) {
	if (len) {
		*len = 0;
	}
	else {
		return NULL;
	}
	if (!ctx) {
		return NULL;
	}
	switch (id) {
	case ODD_USER_KEY_1_0:
		*len = 16;
		return ctx->user_key1_u0;
	case ODD_USER_KEY_2_0:
		*len = 16;
		return ctx->user_key2_u0;
	case ODD_USER_KEY_1_1:
		*len = 16;
		return ctx->user_key1_u1;
	case ODD_USER_KEY_2_1:
		*len = 16;
		return ctx->user_key2_u1;
	case ODD_USER_KEY_1_2:
		*len = 16;
		return ctx->user_key1_u2;
	case ODD_USER_KEY_2_2:
		*len = 16;
		return ctx->user_key2_u2;
	case ODD_USER_KEY_1_3:
		*len = 16;
		return ctx->user_key1_u3;
	case ODD_USER_KEY_2_3:
		*len = 16;
		return ctx->user_key2_u3;
	case ODD_USER_KEY_1_4:
		*len = 16;
		return ctx->user_key1_u4;
	case ODD_USER_KEY_2_4:
		*len = 16;
		return ctx->user_key2_u4;
	default:
		return NULL;
	}
}

const uint8_t* odd_ctx_input_key_ref(
	const odd_ctx* ctx,
	odd_input_key_id id,
	size_t* len
) {
	if (len) {
		*len = 0;
	}
	else {
		return NULL;
	}
	if (!ctx) {
		return NULL;
	}
	switch (id) {
	case ODD_INPUT_KEY_1:
		*len = 16;
		return ctx->input_key1;
	case ODD_INPUT_KEY_2:
		*len = 16;
		return ctx->input_key2;
	default:
		return NULL;
	}
}

const uint8_t* odd_ctx_const_ref(
	const odd_ctx* ctx,
	odd_const_id id,
	size_t* len
) {
	if (len) {
		*len = 0;
	}
	else {
		return NULL;
	}
	if (!ctx) {
		return NULL;
	}
	switch (id) {
	case ODD_CONST_1:
		*len = 8;
		return ctx->const1;
	case ODD_CONST_2:
		*len = 8;
		return ctx->const2;
	case ODD_CONST_3:
		*len = 8;
		return ctx->const3;
	default:
		return NULL;
	}
}

const uint8_t* odd_ctx_paramset_ref(
	const odd_ctx* ctx,
	odd_paramset_id id,
	size_t* len
) {
	if (len) {
		*len = 0;
	}
	else {
		return NULL;
	}
	if (!ctx) {
		return NULL;
	}
	switch (id) {
	case ODD_PARAMSET_0:
		*len = 80;
		return ctx->paramset_0;
	case ODD_PARAMSET_1:
		*len = 80;
		return ctx->paramset_1;
	case ODD_PARAMSET_2:
		*len = 80;
		return ctx->paramset_2;
	case ODD_PARAMSET_3:
		*len = 80;
		return ctx->paramset_3;
	case ODD_PARAMSET_4:
		*len = 80;
		return ctx->paramset_4;
	default:
		return NULL;
	}
}

const uint8_t* odd_ctx_unwrap_key_ref(
	const odd_ctx* ctx,
	odd_unwrap_key_id id,
	size_t* len
) {
	if (len) {
		*len = 0;
	}
	else {
		return NULL;
	}
	if (!ctx) {
		return NULL;
	}
	switch (id) {
	case ODD_UNWRAP_KEY_1:
		*len = 16;
		return ctx->unwrap_key1;
	case ODD_UNWRAP_KEY_2:
		*len = 16;
		return ctx->unwrap_key2;
	default:
		return NULL;
	}
}
