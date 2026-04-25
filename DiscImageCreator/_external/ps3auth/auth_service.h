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
#include "drive_transport.h"
#include "odd_ctx.h"
#include "crypto_backend.h"
#include "session_keys.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum _select_cmd {
	auth,
	get
} select_cmd;

typedef struct auth_result {
	uint8_t enc_a[16], enc_b[16];
	uint8_t dec_a[16], dec_b[16];
} auth_result;

int auth_service_run(
	void* device_handle,
	select_cmd select,
	auth_result* result
);

#ifdef __cplusplus
}
#endif
