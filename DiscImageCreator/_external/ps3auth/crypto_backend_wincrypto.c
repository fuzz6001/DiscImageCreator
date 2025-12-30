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
#include "crypto_backend.h"
#include <Windows.h>
#include <WinCrypt.h>

static int ImportPlaintextKey(
	HCRYPTPROV* phProv,
	HCRYPTKEY* phKey,
	ALG_ID algId,
	const unsigned char* key,
	DWORD keyLen
) {
	*phProv = 0;
	*phKey = 0;

	// CRYPT_VERIFYCONTEXT is used due to no container
	if (!CryptAcquireContextA(
		phProv,
		NULL,
		MS_ENH_RSA_AES_PROV_A,   // support AES + 3DES
		PROV_RSA_AES,
		CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
	{
		return -1;
	}

	// generate PLAINTEXTKEYBLOB
	BYTE blob[sizeof(BLOBHEADER) + sizeof(DWORD) + 64]; // 64: it's enough for AES/3DES key length
	if (keyLen > 64) {
		CryptReleaseContext(*phProv, 0);
		*phProv = 0;
		return -1;
	}

	BLOBHEADER* hdr = (BLOBHEADER*)blob;
	hdr->bType = PLAINTEXTKEYBLOB;
	hdr->bVersion = CUR_BLOB_VERSION;
	hdr->reserved = 0;
	hdr->aiKeyAlg = algId;

	DWORD* pdwKeySize = (DWORD*)(blob + sizeof(BLOBHEADER));
	*pdwKeySize = keyLen;

	memcpy(blob + sizeof(BLOBHEADER) + sizeof(DWORD), key, keyLen);

	DWORD blobLen = sizeof(BLOBHEADER) + sizeof(DWORD) + keyLen;

	if (!CryptImportKey(*phProv, blob, blobLen, 0, 0, phKey)) {
		CryptReleaseContext(*phProv, 0);
		*phProv = 0;
		return -1;
	}

	return 0;
}

inline static int AESEncrypt_CAPI(
	const unsigned char* key,
	const unsigned char* iv,
	const unsigned char* src,
	size_t len,
	unsigned char* dst
) {
	if (!key || !iv || !src || !dst) {
		return -1;
	}
	if (len == 0 || (len % 16) != 0) {
		return -1; // block size is 16
	}

	HCRYPTPROV hProv = 0;
	HCRYPTKEY  hKey = 0;
	int result = -1;

	if (ImportPlaintextKey(&hProv, &hKey, CALG_AES_128, key, 16) == -1) {
		goto cleanup;
	}

	DWORD mode = CRYPT_MODE_CBC;
	if (!CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&mode, 0)) {
		goto cleanup;
	}

	// setting IV (16 byte)
	if (!CryptSetKeyParam(hKey, KP_IV, (BYTE*)iv, 0)) {
		goto cleanup;
	}

	memcpy(dst, src, len);

	DWORD dataLen = (DWORD)len;
	DWORD bufLen = (DWORD)len;

	// Final = FALSE (no pading)
	if (!CryptEncrypt(hKey, 0, FALSE, 0, dst, &dataLen, bufLen)) {
		goto cleanup;
	}

	// dataLen == len, due to NoPadding
	if (dataLen != len) {
		goto cleanup;
	}

	result = 0;

cleanup:
	if (hKey) {
		CryptDestroyKey(hKey);
	}
	if (hProv) {
		CryptReleaseContext(hProv, 0);
	}
	return result;
}

inline static int AESDecrypt_CAPI(
	const unsigned char* key,
	const unsigned char* iv,
	const unsigned char* src,
	size_t len,
	unsigned char* dst
) {
	if (!key || !iv || !src || !dst) {
		return -1;
	}
	if (len == 0 || (len % 16) != 0) {
		return -1;
	}

	HCRYPTPROV hProv = 0;
	HCRYPTKEY  hKey = 0;
	int result = -1;

	if (ImportPlaintextKey(&hProv, &hKey, CALG_AES_128, key, 16) == -1) {
		goto cleanup;
	}

	DWORD mode = CRYPT_MODE_CBC;
	if (!CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&mode, 0)) {
		goto cleanup;
	}

	if (!CryptSetKeyParam(hKey, KP_IV, (BYTE*)iv, 0)) {
		goto cleanup;
	}

	memcpy(dst, src, len);

	DWORD dataLen = (DWORD)len;

	// Final = FALSE (no padding)
	if (!CryptDecrypt(hKey, 0, FALSE, 0, dst, &dataLen)) {
		goto cleanup;
	}

	if (dataLen != len) {
		// if padding is removed, length is different
		goto cleanup;
	}

	result = 0;

cleanup:
	if (hKey) {
		CryptDestroyKey(hKey);
	}
	if (hProv) {
		CryptReleaseContext(hProv, 0);
	}
	return result;
}

inline static int TripleDESEncrypt_CAPI(
	const unsigned char* key16,
	const unsigned char* iv8,
	const unsigned char* src,
	size_t len,
	unsigned char* dst
) {
	if (!key16 || !iv8 || !src || !dst) {
		return -1;
	}
	if (len == 0 || (len % 8) != 0) {
		return -1;  // 3DES block size is 8
	}
	// Key7 is 16 bytes (2-key 3DES)
	HCRYPTPROV hProv = 0;
	HCRYPTKEY  hKey = 0;
	int result = -1;

	if (ImportPlaintextKey(&hProv, &hKey, CALG_3DES_112, key16, 16) == -1) {
		goto cleanup;
	}

	DWORD mode = CRYPT_MODE_CBC;
	if (!CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&mode, 0)) {
		goto cleanup;
	}

	// IV is 8 bytes
	if (!CryptSetKeyParam(hKey, KP_IV, (BYTE*)iv8, 0)) {
		goto cleanup;
	}

	memcpy(dst, src, len);

	DWORD dataLen = (DWORD)len;
	DWORD bufLen = (DWORD)len;

	// Final = FALSE (no padding)
	if (!CryptEncrypt(hKey, 0, FALSE, 0, dst, &dataLen, bufLen)) {
		goto cleanup;
	}

	if (dataLen != len) {
		// if padding is removed, length is different
		goto cleanup;
	}

	result = 0;

cleanup:
	if (hKey) {
		CryptDestroyKey(hKey);
	}
	if (hProv) {
		CryptReleaseContext(hProv, 0);
	}
	return result;
}

inline static int TripleDESDecrypt_CAPI(
	const unsigned char* key16,
	const unsigned char* iv8,
	const unsigned char* src,
	size_t len,
	unsigned char* dst
) {
	if (!key16 || !iv8 || !src || !dst) {
		return -1;
	}
	if (len == 0 || (len % 8) != 0) {
		return -1;
	}

	HCRYPTPROV hProv = 0;
	HCRYPTKEY  hKey = 0;
	int result = -1;

	if (ImportPlaintextKey(&hProv, &hKey, CALG_3DES_112, key16, 16) == -1) {
		goto cleanup;
	}

	DWORD mode = CRYPT_MODE_CBC;
	if (!CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&mode, 0)) {
		goto cleanup;
	}

	if (!CryptSetKeyParam(hKey, KP_IV, (BYTE*)iv8, 0)) {
		goto cleanup;
	}

	memcpy(dst, src, len);

	DWORD dataLen = (DWORD)len;

	// Final = FALSE (no padding)
	if (!CryptDecrypt(hKey, 0, FALSE, 0, dst, &dataLen)) {
		goto cleanup;
	}

	if (dataLen != len) {
		// if padding is removed, length is different
		goto cleanup;
	}

	result = 0;

cleanup:
	if (hKey) {
		CryptDestroyKey(hKey);
	}
	if (hProv) {
		CryptReleaseContext(hProv, 0);
	}
	return result;
}

int exec_aes128_cbc_nopad_enc(
	void* u,
	const uint8_t key[16],
	const uint8_t iv[16],
	const uint8_t* in,
	size_t in_len,
	uint8_t* out,
	size_t out_cap,
	size_t* out_len
) {
	(void)u;
	if (!out_len) {
		return -1;
	}
	if (out_cap < in_len) {
		return -1;
	}
	int rc = AESEncrypt_CAPI(key, iv, in, in_len, out);
	if (rc != 0) {
		return rc;
	}
	*out_len = in_len;
	return 0;
}

int exec_aes128_cbc_nopad_dec(
	void* u,
	const uint8_t key[16],
	const uint8_t iv[16],
	const uint8_t* in,
	size_t in_len,
	uint8_t* out,
	size_t out_cap,
	size_t* out_len
) {
	(void)u;
	if (!out_len) {
		return -1;
	}
	if (out_cap < in_len) {
		return -1;
	}
	int rc = AESDecrypt_CAPI(key, iv, in, in_len, out);
	if (rc != 0) {
		return rc;
	}
	*out_len = in_len;
	return 0;
}

int exec_tdes_ede_cbc_nopad_enc(
	void* u, 
	const uint8_t key[16],
	const uint8_t iv[8],
	const uint8_t* in,
	size_t in_len,
	uint8_t* out,
	size_t out_cap,
	size_t* out_len
) {
	(void)u;
	if (!out_len) {
		return -1;
	}
	if (out_cap < in_len) {
		return -1;
	}
	int rc = TripleDESEncrypt_CAPI(key, iv, in, in_len, out);
	if (rc != 0) {
		return rc;
	}
	*out_len = in_len;
	return 0;
}

int exec_tdes_ede_cbc_nopad_dec(
	void* u,
	const uint8_t key[16],
	const uint8_t iv[8],
	const uint8_t* in,
	size_t in_len,
	uint8_t* out,
	size_t out_cap,
	size_t* out_len
) {
	(void)u;
	if (!out_len) {
		return -1;
	}
	if (out_cap < in_len) {
		return -1;
	}
	int rc = TripleDESDecrypt_CAPI(key, iv, in, in_len, out);
	if (rc != 0) {
		return rc;
	}
	*out_len = in_len;
	return 0;
}

crypto_backend crypto_backend_make(void)
{
	static const crypto_backend_vtbl CRYPTO_VTBL = {
		.aes128_cbc_nopad_enc = exec_aes128_cbc_nopad_enc,
		.aes128_cbc_nopad_dec = exec_aes128_cbc_nopad_dec,
		.tdes_ede_cbc_nopad_enc = exec_tdes_ede_cbc_nopad_enc,
		.tdes_ede_cbc_nopad_dec = exec_tdes_ede_cbc_nopad_dec
	};
	crypto_backend c = {
		.user = NULL,
		.v = &CRYPTO_VTBL,
	};
	return c;
}
