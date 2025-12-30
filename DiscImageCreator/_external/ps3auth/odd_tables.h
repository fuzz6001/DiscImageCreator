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
#include "odd_ctx.h"

#ifdef __cplusplus
extern "C" {
#endif

const uint8_t* odd_tables_iv_ref(
	odd_iv_id id,
	size_t* len
);
const uint8_t* odd_tables_default_key_ref(
	odd_default_key_id id,
	size_t* len
);
const uint8_t* odd_tables_user_key_ref(
	odd_user_key_id id,
	size_t* len
);
const uint8_t* odd_tables_input_key_ref(
	odd_input_key_id id,
	size_t* len
);
const uint8_t* odd_tables_const_ref(
	odd_const_id id,
	size_t* len
);
const uint8_t* odd_tables_paramset_ref(
	odd_paramset_id id,
	size_t* len
);
const uint8_t* odd_tables_unwrap_key_ref(
	odd_unwrap_key_id id,
	size_t* len
);

#ifdef __cplusplus
}
#endif
