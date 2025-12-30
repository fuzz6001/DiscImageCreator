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

typedef struct drive_transport drive_transport;

typedef struct drive_transport_vtbl {
	int (*send_blob)(
		void* dev,
		int selector,
		const uint8_t* data,
		size_t len
		);
	int (*recv_blob)(
		void* dev,
		int selector,
		uint8_t* out,
		size_t cap,
		size_t* out_len
		);
	int (*vendor_cmd_a)(
		void* dev,
		const uint8_t* in,
		size_t in_len,
		uint8_t* out,
		size_t out_cap,
		size_t* out_len
		);
	int (*vendor_cmd_b)(
		void* dev,
		const uint8_t* in,
		size_t in_len,
		uint8_t* out,
		size_t out_cap,
		size_t* out_len
		);
} drive_transport_vtbl;

struct drive_transport {
	void* dev;
	const drive_transport_vtbl* v;
};

drive_transport drive_transport_make_execscsi(void* dev);

#ifdef __cplusplus
}
#endif
