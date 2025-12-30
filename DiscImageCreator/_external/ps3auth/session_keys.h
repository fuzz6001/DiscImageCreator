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
#include "odd_ctx.h"
#include "crypto_backend.h"
#include "drive_transport.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct session_keys session_keys;

session_keys* session_keys_create(void);
void session_keys_destroy(
	session_keys* sk
);

int session_keys_establish(
	odd_ctx* ctx,
	const crypto_backend* crypto,
	const drive_transport* tr,
	session_keys* sk,
	int selection
);

#ifdef __cplusplus
}
#endif
