#include "crypto_backend.h"
#include <openssl/evp.h>
#include <openssl/err.h>

static void openssl_log_errors(void)
{
	ERR_print_errors_fp(stderr);
}

static int AESEncrypt_OpenSSL(
	const unsigned char* key16,
	const unsigned char* iv16,
	const unsigned char* src,
	unsigned int len,
	unsigned char* dst
) {
	if (!key16 || !iv16 || !src || !dst) {
		return -1;
	}
	if (len == 0 || (len % 16) != 0) {
		return -1; // block size is 16
	}

	int ok = -1;
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		return -1;
	}

	int outlen1 = 0, outlen2 = 0;

	if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, NULL, NULL) != 1) {
		openssl_log_errors();
		goto done;
	}

	// no padding
	if (EVP_CIPHER_CTX_set_padding(ctx, 0) != 1) {
		openssl_log_errors();
		goto done;
	}

	// set key and iv
	if (EVP_EncryptInit_ex(ctx, NULL, NULL, key16, iv16) != 1) {
		openssl_log_errors();
		goto done;
	}

	if (EVP_EncryptUpdate(ctx, dst, &outlen1, src, (int)len) != 1) {
		openssl_log_errors();
		goto done;
	}

	// outlen2 is 0 due to no padding
	if (EVP_EncryptFinal_ex(ctx, dst + outlen1, &outlen2) != 1) {
		openssl_log_errors();
		goto done;
	}

	if ((unsigned int)(outlen1 + outlen2) != len) {
		goto done;
	}

	ok = 0;

done:
	EVP_CIPHER_CTX_free(ctx);
	return ok;
}

static int AESDecrypt_OpenSSL(
	const unsigned char* key16,
	const unsigned char* iv16,
	const unsigned char* src,
	unsigned int len,
	unsigned char* dst
) {
	if (!key16 || !iv16 || !src || !dst) {
		return -1;
	}
	if (len == 0 || (len % 16) != 0) {
		return -1;
	}

	int ok = -1;
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		return -1;
	}

	int outlen1 = 0, outlen2 = 0;

	if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, NULL, NULL) != 1) {
		openssl_log_errors();
		goto done;
	}

	// no padding
	if (EVP_CIPHER_CTX_set_padding(ctx, 0) != 1) {
		openssl_log_errors();
		goto done;
	}

	if (EVP_DecryptInit_ex(ctx, NULL, NULL, key16, iv16) != 1) {
		openssl_log_errors();
		goto done;
	}

	if (EVP_DecryptUpdate(ctx, dst, &outlen1, src, (int)len) != 1) {
		openssl_log_errors();
		goto done;
	}

	if (EVP_DecryptFinal_ex(ctx, dst + outlen1, &outlen2) != 1) {
		openssl_log_errors();
		goto done;
	}

	if ((unsigned int)(outlen1 + outlen2) != len) {
		goto done;
	}

	ok = 0;

done:
	EVP_CIPHER_CTX_free(ctx);
	return ok;
}

/*
 * 2-key 3DES (112bit) / CBC / NoPadding
 * - key16: 16 bytes (K1 || K2)
 * - iv8  : 8 bytes
 */

static int TripleDESEncrypt_OpenSSL(
	const unsigned char* key16,
	const unsigned char* iv8,
	const unsigned char* src,
	unsigned int len,
	unsigned char* dst
) {
	if (!key16 || !iv8 || !src || !dst) {
		return -1;
	}
	if (len == 0 || (len % 8) != 0) {
		return -1;  // block size is 8
	}

	int ok = -1;
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		return -1;
	}

	int outlen1 = 0, outlen2 = 0;

	// 2-key 3DES is EVP_des_ede_cbc()
	if (EVP_EncryptInit_ex(ctx, EVP_des_ede_cbc(), NULL, NULL, NULL) != 1) {
		openssl_log_errors();
		goto done;
	}

	// no padding
	if (EVP_CIPHER_CTX_set_padding(ctx, 0) != 1) {
		openssl_log_errors();
		goto done;
	}

	// set key (16 bytes) and IV (8 bytes)
	if (EVP_EncryptInit_ex(ctx, NULL, NULL, key16, iv8) != 1) {
		openssl_log_errors();
		goto done;
	}

	if (EVP_EncryptUpdate(ctx, dst, &outlen1, src, (int)len) != 1) {
		openssl_log_errors();
		goto done;
	}

	if (EVP_EncryptFinal_ex(ctx, dst + outlen1, &outlen2) != 1) {
		openssl_log_errors();
		goto done;
	}

	if ((unsigned int)(outlen1 + outlen2) != len) {
		goto done;
	}

	ok = 0;

done:
	EVP_CIPHER_CTX_free(ctx);
	return ok;
}

static int TripleDESDecrypt_OpenSSL(
	const unsigned char* key16,
	const unsigned char* iv8,
	const unsigned char* src,
	unsigned int len,
	unsigned char* dst
) {
	if (!key16 || !iv8 || !src || !dst) {
		return -1;
	}
	if (len == 0 || (len % 8) != 0) {
		return -1;
	}

	int ok = -1;
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		return -1;
	}

	int outlen1 = 0, outlen2 = 0;

	if (EVP_DecryptInit_ex(ctx, EVP_des_ede_cbc(), NULL, NULL, NULL) != 1) {
		openssl_log_errors();
		goto done;
	}

	if (EVP_CIPHER_CTX_set_padding(ctx, 0) != 1) {
		openssl_log_errors();
		goto done;
	}

	if (EVP_DecryptInit_ex(ctx, NULL, NULL, key16, iv8) != 1) {
		openssl_log_errors();
		goto done;
	}

	if (EVP_DecryptUpdate(ctx, dst, &outlen1, src, (int)len) != 1) {
		openssl_log_errors();
		goto done;
	}

	if (EVP_DecryptFinal_ex(ctx, dst + outlen1, &outlen2) != 1) {
		openssl_log_errors();
		goto done;
	}

	if ((unsigned int)(outlen1 + outlen2) != len) {
		goto done;
	}

	ok = 0;

done:
	EVP_CIPHER_CTX_free(ctx);
	return ok;
}

int exec_aes128_cbc_nopad_enc(void* u, const uint8_t key[16], const uint8_t iv[16],
                         const uint8_t* in, size_t in_len, uint8_t* out, size_t out_cap, size_t* out_len)
{
	(void)u;
	if (!in || !out || !out_len) {
		return -1;
	}
	if (in_len > UINT_MAX) {
		return -1;
	}
	if (out_cap < in_len) {
		return -1;
	}
	if (AESEncrypt_OpenSSL(key, iv, in, (unsigned int)in_len, out) == -1) {
		return -1;
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
	if (!in || !out || !out_len) {
		return -1;
	}
	if (in_len > UINT_MAX) {
		return -1;
	}
	if (out_cap < in_len) {
		return -1;
	}
	if (AESDecrypt_OpenSSL(key, iv, in, (unsigned int)in_len, out) == -1) {
		return -1;
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
	if (!in || !out || !out_len) {
		return -1;
	}
	if ((in_len % 8) != 0) {
		return -1;
	}
	if (in_len > UINT_MAX) {
		return -1;
	}
	if (out_cap < in_len) {
		return -1;
	}
	if (TripleDESEncrypt_OpenSSL(key, iv, in, (unsigned int)in_len, out) == -1) {
		return -1;
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
	if (!in || !out || !out_len) {
		return -1;
	}
	if ((in_len % 8) != 0) {
		return -1;
	}
	if (in_len > UINT_MAX) {
		return -1;
	}
	if (out_cap < in_len) {
		return -1;
	}
	if (TripleDESDecrypt_OpenSSL(key, iv, in, (unsigned int)in_len, out) == -1) {
		return -1;
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
