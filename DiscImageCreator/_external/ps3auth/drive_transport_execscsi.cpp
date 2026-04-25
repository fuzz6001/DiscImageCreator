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
#include "drive_transport.h"
#include "forwardDeclaration.h"
#include "execScsiCmd.h"

static int exec_send_blob(
	void* dev,
	int selector,
	const uint8_t* data,
	size_t len
) {
	if (len > 0xFFFF) {
		return -1;
	}
	BOOL ok = SendKey(NULL, (PDEVICE)dev, 0, (BYTE)selector, (LPBYTE)data, (WORD)len);
	return ok ? 0 : -1;
}

static int exec_recv_blob(
	void* dev,
	int selector,
	uint8_t* out,
	size_t cap,
	size_t* out_len
) {
	if (cap > 0xFFFF) {
		return -1;
	}
	BOOL ok = ReportKey(NULL, (PDEVICE)dev, 0, (BYTE)selector, (LPBYTE)out, (WORD)cap);
	if (ok && out_len) {
		*out_len = cap;
	}
	return ok ? 0 : -1;
}

static int exec_vendor_cmd_a(
	void* dev,
	const uint8_t* in,
	size_t in_len,
	uint8_t* out,
	size_t out_cap,
	size_t* out_len
) {
	(void)in_len;
	BOOL ok = Ps3DriveSpecificE0((PDEVICE)dev, (LPBYTE)in, (LPBYTE)out, out_cap);
	if (ok && out_len) {
		*out_len = out_cap;
	}
	return ok ? 0 : -1;
}

static int exec_vendor_cmd_b(
	void* dev,
	const uint8_t* in,
	size_t in_len,
	uint8_t* out,
	size_t out_cap,
	size_t* out_len
) {
	(void)in_len;
	BOOL ok = Ps3DriveSpecificE1((PDEVICE)dev, (LPBYTE)in, (LPBYTE)out, out_cap);
	if (ok && out_len) {
		*out_len = out_cap;
	}
	return ok ? 0 : -1;
}

drive_transport drive_transport_make_execscsi(void* dev)
{
	static const drive_transport_vtbl V = {
		exec_send_blob,
		exec_recv_blob,
		exec_vendor_cmd_a,
		exec_vendor_cmd_b
	};

	drive_transport tr;
	tr.dev = dev;
	tr.v = &V;
	return tr;
}
