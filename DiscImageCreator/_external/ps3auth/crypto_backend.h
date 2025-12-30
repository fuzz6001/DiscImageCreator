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

typedef struct crypto_backend crypto_backend;

typedef struct crypto_backend_vtbl {
	int (*aes128_cbc_nopad_enc)(
		void* u,
		const uint8_t key[16],
		const uint8_t iv[16],
		const uint8_t* in,
		size_t in_len,
		uint8_t* out,
		size_t out_cap,
		size_t* out_len
		);
	int (*aes128_cbc_nopad_dec)(
		void* u,
		const uint8_t key[16],
		const uint8_t iv[16],
		const uint8_t* in,
		size_t in_len,
		uint8_t* out,
		size_t out_cap,
		size_t* out_len
		);
	int (*tdes_ede_cbc_nopad_enc)(
		void* u,
		const uint8_t key[16],
		const uint8_t iv[8],
		const uint8_t* in,
		size_t in_len,
		uint8_t* out,
		size_t out_cap,
		size_t* out_len
		);
	int (*tdes_ede_cbc_nopad_dec)(
		void* u,
		const uint8_t key[16],
		const uint8_t iv[8],
		const uint8_t* in,
		size_t in_len,
		uint8_t* out,
		size_t out_cap,
		size_t* out_len
		);
} crypto_backend_vtbl;

struct crypto_backend {
	void* user;
	const crypto_backend_vtbl* v;
};

crypto_backend crypto_backend_make(void);

#ifdef __cplusplus
}
#endif
