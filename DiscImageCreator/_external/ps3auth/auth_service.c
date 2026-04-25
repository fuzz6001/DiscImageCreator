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
#include "auth_service.h"
#include "drive_proto.h"
#include "data_unwrap.h"
#include <stdio.h>
#include <string.h>

int auth_service_run(
	void* device_handle,
	select_cmd select,
	auth_result* result
) {
	odd_ctx* ctx = odd_ctx_create();
	odd_ctx_load_ivs(ctx);
	odd_ctx_load_default_keys(ctx);
	odd_ctx_load_user_keys(ctx);
	odd_ctx_load_input_keys(ctx);
	odd_ctx_load_const(ctx);
	odd_ctx_load_params(ctx);

	crypto_backend crypto = crypto_backend_make();
	drive_transport tr = drive_transport_make_execscsi(device_handle);
	session_keys* sk = session_keys_create();
	if (!sk) {
		return -1;
	}

	int ret = session_keys_establish(ctx, &crypto, &tr, sk, 0);
	if (ret == -1) {
		fprintf(stderr, "session keys establish Failed\n");
		session_keys_destroy(sk);
		odd_ctx_destroy(ctx);
		return -1;
	}
	
	if (select == auth) {
		ret = drive_proto_authenticate(ctx, &crypto, &tr, sk);
		if (ret == -1) {
			fprintf(stderr, "Drive Authentication Failed\n");
			session_keys_destroy(sk);
			odd_ctx_destroy(ctx);
			return -1;
		}
		
		ret = session_keys_establish(ctx, &crypto, &tr, sk, 1);
		if (ret == -1) {
			fprintf(stderr, "session keys establish Failed\n");
			session_keys_destroy(sk);
			odd_ctx_destroy(ctx);
			return -1;
		}
		printf("Drive Authenticated OK\n");
	}
	else if (select == get) {
		proto_out pout;
		ret = drive_proto_get_two_blobs(ctx, &crypto, &tr, sk, &pout);
		if (ret == -1) {
			fprintf(stderr, "Can't get D1/D2 values\n");
			session_keys_destroy(sk);
			odd_ctx_destroy(ctx);
			return -1;
		}
		memcpy(result->enc_a, pout.a, 16);
		memcpy(result->enc_b, pout.b, 16);

		odd_ctx_load_unwrap_keys(ctx);
		ret = data_unwrap_finalize(ctx, &crypto, &pout);
		if (ret == -1) {
			fprintf(stderr, "Can't unwrap finalize D1/D2 values\n");
			session_keys_destroy(sk);
			odd_ctx_destroy(ctx);
			return -1;
		}
		memcpy(result->dec_a, pout.a, 16);
		memcpy(result->dec_b, pout.b, 16);
	}
	session_keys_destroy(sk);
	odd_ctx_destroy(ctx);
	return 0;
}
