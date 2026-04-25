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
#pragma once
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct odd_ctx odd_ctx;

typedef enum _odd_iv_id {
	ODD_IV_1,
	ODD_IV_2,
	ODD_IV_3,
	ODD_IV_4
} odd_iv_id;

typedef enum _odd_default_key_id {
	ODD_DEFAULT_KEY_1,
	ODD_DEFAULT_KEY_2
} odd_default_key_id;

typedef enum _odd_user_key_id {
	ODD_USER_KEY_1_0,
	ODD_USER_KEY_2_0,
	ODD_USER_KEY_1_1,
	ODD_USER_KEY_2_1,
	ODD_USER_KEY_1_2,
	ODD_USER_KEY_2_2,
	ODD_USER_KEY_1_3,
	ODD_USER_KEY_2_3,
	ODD_USER_KEY_1_4,
	ODD_USER_KEY_2_4
} odd_user_key_id;

typedef enum _odd_input_key_id {
	ODD_INPUT_KEY_1,
	ODD_INPUT_KEY_2
} odd_input_key_id;

typedef enum _odd_const_id {
	ODD_CONST_1,
	ODD_CONST_2,
	ODD_CONST_3
} odd_const_id;

typedef enum _odd_paramset_id {
	ODD_PARAMSET_0,
	ODD_PARAMSET_1,
	ODD_PARAMSET_2,
	ODD_PARAMSET_3,
	ODD_PARAMSET_4
} odd_paramset_id;

typedef enum _odd_unwrap_key_id {
	ODD_UNWRAP_KEY_1,
	ODD_UNWRAP_KEY_2
} odd_unwrap_key_id;

odd_ctx* odd_ctx_create(void);
void odd_ctx_destroy(
	odd_ctx* ctx
);
void odd_ctx_load_ivs(
	odd_ctx* ctx
);
void odd_ctx_load_default_keys(
	odd_ctx* ctx
);
void odd_ctx_load_user_keys(
	odd_ctx* ctx
);
void odd_ctx_load_input_keys(
	odd_ctx* ctx
);
void odd_ctx_load_const(
	odd_ctx* ctx
);
void odd_ctx_load_params(
	odd_ctx* ctx
);
void odd_ctx_load_unwrap_keys(
	odd_ctx* ctx
);

const uint8_t* odd_ctx_iv_ref(
	const odd_ctx* ctx,
	odd_iv_id id,
	size_t* len
);
const uint8_t* odd_ctx_default_key_ref(
	const odd_ctx* ctx,
	odd_default_key_id id,
	size_t* len
);
const uint8_t* odd_ctx_user_key_ref(
	const odd_ctx* ctx,
	odd_user_key_id id,
	size_t* len
);
const uint8_t* odd_ctx_input_key_ref(
	const odd_ctx* ctx,
	odd_input_key_id id,
	size_t* len
);
const uint8_t* odd_ctx_const_ref(
	const odd_ctx* ctx,
	odd_const_id id,
	size_t* len
);
const uint8_t* odd_ctx_paramset_ref(
	const odd_ctx* ctx,
	odd_paramset_id id,
	size_t* len
);
const uint8_t* odd_ctx_unwrap_key_ref(
	const odd_ctx* ctx,
	odd_unwrap_key_id id,
	size_t* len
);

#ifdef __cplusplus
}
#endif
