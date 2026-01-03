/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (C) 2018 Intel Corporation.
 *   All rights reserved.
 *   Copyright (c) 2022, NVIDIA CORPORATION & AFFILIATES.
 *   All rights reserved.
 */

#include "vbdev_crypto.h"

#include "spdk/hexlify.h"
#include "spdk/keyring.h"

#include "spdk/base64.h"
#include "spdk/util.h"

#include <openssl/evp.h>

/* Reasonable bdev name length + cipher's name len */
#define MAX_KEY_NAME_LEN 128

/* Structure to hold the parameters for this RPC method. */
struct rpc_construct_crypto {
	char *base_bdev_name;
	char *name;
	char *crypto_pmd;
	struct spdk_accel_crypto_key_create_param param;
	char *wrapped_key_b64;
	char *wrapped_key2_b64;
	char *kek_id;
	char *kek_hex;
};

/* Free the allocated memory resource after the RPC handling. */
static void
free_rpc_construct_crypto(struct rpc_construct_crypto *r)
{
	free(r->base_bdev_name);
	free(r->name);
	free(r->crypto_pmd);
	free(r->param.cipher);
	if (r->param.hex_key) {
		memset(r->param.hex_key, 0, strnlen(r->param.hex_key, SPDK_ACCEL_CRYPTO_KEY_MAX_HEX_LENGTH));
		free(r->param.hex_key);
	}
	if (r->param.hex_key2) {
		memset(r->param.hex_key2, 0, strnlen(r->param.hex_key2, SPDK_ACCEL_CRYPTO_KEY_MAX_HEX_LENGTH));
		free(r->param.hex_key2);
	}
	free(r->param.key_name);
	free(r->wrapped_key_b64);
	free(r->wrapped_key2_b64);
	free(r->kek_id);
	free(r->kek_hex);
}

/* Structure to decode the input parameters for this RPC method. */
static const struct spdk_json_object_decoder rpc_bdev_crypto_create_decoders[] = {
	{"base_bdev_name", offsetof(struct rpc_construct_crypto, base_bdev_name), spdk_json_decode_string},
	{"name", offsetof(struct rpc_construct_crypto, name), spdk_json_decode_string},
	{"crypto_pmd", offsetof(struct rpc_construct_crypto, crypto_pmd), spdk_json_decode_string, true},
	{"key", offsetof(struct rpc_construct_crypto, param.hex_key), spdk_json_decode_string, true},
	{"cipher", offsetof(struct rpc_construct_crypto, param.cipher), spdk_json_decode_string, true},
	{"key2", offsetof(struct rpc_construct_crypto, param.hex_key2), spdk_json_decode_string, true},
	{"key_name", offsetof(struct rpc_construct_crypto, param.key_name), spdk_json_decode_string, true},
	{"wrapped_key", offsetof(struct rpc_construct_crypto, wrapped_key_b64), spdk_json_decode_string, true},
	{"wrapped_key2", offsetof(struct rpc_construct_crypto, wrapped_key2_b64), spdk_json_decode_string, true},
	{"kek_id", offsetof(struct rpc_construct_crypto, kek_id), spdk_json_decode_string, true},
	{"kek_hex", offsetof(struct rpc_construct_crypto, kek_hex), spdk_json_decode_string, true},
};

static struct vbdev_crypto_opts *
create_crypto_opts(struct rpc_construct_crypto *rpc, struct spdk_accel_crypto_key *key,
		   bool key_owner)
{
	struct vbdev_crypto_opts *opts = calloc(1, sizeof(*opts));

	if (!opts) {
		return NULL;
	}

	opts->bdev_name = strdup(rpc->base_bdev_name);
	if (!opts->bdev_name) {
		free_crypto_opts(opts);
		return NULL;
	}
	opts->vbdev_name = strdup(rpc->name);
	if (!opts->vbdev_name) {
		free_crypto_opts(opts);
		return NULL;
	}

	opts->key = key;
	opts->key_owner = key_owner;

	return opts;
}

static int
calc_dek_fp_from_hex(const char *hex1, const char *hex2, uint8_t out_fp[VBDEV_CRYPTO_DEK_FP_LEN])
{
    uint8_t *k1 = NULL, *k2 = NULL;
    size_t k1_len = 0, k2_len = 0;
    EVP_MD_CTX *md = NULL;
    unsigned int md_len = 0;
    int rc = -EINVAL;

    if (!hex1 || !hex2 || !out_fp) {
        return -EINVAL;
    }
    if ((strlen(hex1) % 2) || (strlen(hex2) % 2)) {
        return -EINVAL;
    }

    k1_len = strlen(hex1) / 2;
    k2_len = strlen(hex2) / 2;

    k1 = (uint8_t *)spdk_unhexlify(hex1);
    k2 = (uint8_t *)spdk_unhexlify(hex2);
    if (!k1 || !k2) {
        rc = -ENOMEM;
        goto out;
    }

    md = EVP_MD_CTX_new();
    if (!md) {
        rc = -ENOMEM;
        goto out;
    }

    if (EVP_DigestInit_ex(md, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(md, k1, k1_len) != 1 ||
        EVP_DigestUpdate(md, k2, k2_len) != 1 ||
        EVP_DigestFinal_ex(md, out_fp, &md_len) != 1 ||
        md_len != VBDEV_CRYPTO_DEK_FP_LEN) {
        rc = -EINVAL;
        goto out;
    }

    rc = 0;

out:
    if (md) {
        EVP_MD_CTX_free(md);
    }
    if (k1) {
        spdk_memset_s(k1, k1_len, 0, k1_len);
        free(k1);
    }
    if (k2) {
        spdk_memset_s(k2, k2_len, 0, k2_len);
        free(k2);
    }
    return rc;
}

static int
get_kek_bytes(const char *kek_id, const char *kek_hex, uint8_t **out_kek, size_t *out_len)
{
	struct spdk_key *key = NULL;
	uint8_t *kek = NULL;
	size_t len = 0;
	int rc;

	if (out_kek == NULL || out_len == NULL) {
		return -EINVAL;
	}

	*out_kek = NULL;
	*out_len = 0;

	/* Preferred: fetch KEK from SPDK keyring by id */
	if (kek_id && kek_id[0] != '\0') {
		key = spdk_keyring_get_key(kek_id);
		if (key == NULL) {
			SPDK_ERRLOG("Failed to get KEK from keyring by kek_id='%s'\n", kek_id);
			return -ENOENT;
		}

		kek = calloc(1, 32);
		if (kek == NULL) {
			spdk_keyring_put_key(key);
			return -ENOMEM;
		}

		rc = spdk_key_get_key(key, kek, 32);
		spdk_keyring_put_key(key);

		if (rc < 0) {
			SPDK_ERRLOG("Failed to read KEK bytes from keyring kek_id='%s' rc=%d\n", kek_id, rc);
			spdk_memset_s(kek, 32, 0, 32);
			free(kek);
			return rc;
		}

		if (rc != 32) {
			SPDK_ERRLOG("KEK from keyring must be %u bytes for AES-256-GCM, got %zu\n",
				    32, rc);
			spdk_memset_s(kek, 32, 0, 32);
			free(kek);
			return -EINVAL;
		}

		*out_kek = kek;
		*out_len = len;
		return 0;
	}

	/* Fallback: accept kek_hex (NOT preferred, but ok) */
	SPDK_ERRLOG("Failed to get KEK from keyring by kek_id='%s'\n", kek_id);
	if (kek_hex && kek_hex[0] != '\0') {
		if (strlen(kek_hex) % 2 != 0) {
			SPDK_ERRLOG("kek_hex length must be even\n");
			return -EINVAL;
		}

		len = strlen(kek_hex) / 2;
		if (len != 32) {
			SPDK_ERRLOG("kek_hex must be %u bytes (64 hex chars), got %zu bytes\n",
				    32, len);
			return -EINVAL;
		}

		kek = (uint8_t *)spdk_unhexlify(kek_hex);
		if (kek == NULL) {
			SPDK_ERRLOG("Failed to unhexlify kek_hex\n");
			return -EINVAL;
		}

		*out_kek = kek;
		*out_len = len;
		return 0;
	}

	SPDK_ERRLOG("Neither kek_id nor kek_hex provided\n");
	return -EINVAL;
}

static int
decrypt_wrapped_key_to_hex(const char *wrapped_b64, const char *kek_id, const char *kek_hex, char **out_hex)
{
	EVP_CIPHER_CTX *ctx = NULL;
	uint8_t *blob = NULL;
	size_t blob_len = 0;

	uint8_t *kek_bin = NULL;
	size_t kek_len = 0;

	uint8_t *pt = NULL;
	int pt_len = 0;
	int len = 0;

	const uint8_t *iv = NULL;
	const uint8_t *tag = NULL;
	const uint8_t *ct = NULL;
	size_t ct_len = 0;

	int rc = -EINVAL;

	if (!wrapped_b64 || !out_hex) {
		return -EINVAL;
	}

	*out_hex = NULL;

	rc = get_kek_bytes(kek_id, kek_hex, &kek_bin, &kek_len);
	if (rc != 0) {
		SPDK_ERRLOG("Failed to obtain KEK\n");
		goto cleanup;
	}

	/* Decode base64(wrapped_blob). Format:
	 * [0..11]   IV (12 bytes)
	 * [12..27]  TAG (16 bytes)
	 * [28..]    Ciphertext
	 */
	blob_len = spdk_base64_get_decoded_len(strlen(wrapped_b64));
	if (blob_len < (12 + 16 + 1)) {
		SPDK_ERRLOG("wrapped_key blob too small\n");
		rc = -EINVAL;
		goto cleanup;
	}

	blob = calloc(1, blob_len);
	if (!blob) {
		rc = -ENOMEM;
		goto cleanup;
	}

	if (spdk_base64_decode(blob, &blob_len, wrapped_b64) != 0) {
		SPDK_ERRLOG("Failed to base64 decode wrapped_key\n");
		rc = -EINVAL;
		goto cleanup;
	}

	if (blob_len < (12 + 16 + 1)) {
		SPDK_ERRLOG("wrapped_key decoded blob too small\n");
		rc = -EINVAL;
		goto cleanup;
	}

	iv = blob;
	tag = blob + 12;
	ct = blob + 12 + 16;
	ct_len = blob_len - (12 + 16);

	pt = calloc(1, ct_len);
	if (!pt) {
		rc = -ENOMEM;
		goto cleanup;
	}

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		rc = -ENOMEM;
		goto cleanup;
	}

	if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
		SPDK_ERRLOG("EVP_DecryptInit_ex failed\n");
		rc = -EINVAL;
		goto cleanup;
	}

	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) {
		SPDK_ERRLOG("EVP_CTRL_GCM_SET_IVLEN failed\n");
		rc = -EINVAL;
		goto cleanup;
	}

	if (EVP_DecryptInit_ex(ctx, NULL, NULL, kek_bin, iv) != 1) {
		SPDK_ERRLOG("EVP_DecryptInit_ex(key,iv) failed\n");
		rc = -EINVAL;
		goto cleanup;
	}

	if (EVP_DecryptUpdate(ctx, pt, &len, ct, (int)ct_len) != 1) {
		SPDK_ERRLOG("EVP_DecryptUpdate failed\n");
		rc = -EINVAL;
		goto cleanup;
	}
	pt_len = len;

	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag) != 1) {
		SPDK_ERRLOG("EVP_CTRL_GCM_SET_TAG failed\n");
		rc = -EINVAL;
		goto cleanup;
	}

	if (EVP_DecryptFinal_ex(ctx, pt + pt_len, &len) != 1) {
		SPDK_ERRLOG("wrapped_key authentication failed (bad tag)\n");
		rc = -EACCES;
		goto cleanup;
	}
	pt_len += len;

	/* Convert plaintext bytes to hex string for SPDK accel key API */
	*out_hex = spdk_hexlify((const char *)pt, (size_t)pt_len);
	if (!*out_hex) {
		rc = -ENOMEM;
		goto cleanup;
	}

	rc = 0;

cleanup:
	if (ctx) {
		EVP_CIPHER_CTX_free(ctx);
	}
	if (pt) {
		spdk_memset_s(pt, ct_len, 0, ct_len);
		free(pt);
	}
	if (kek_bin) {
		spdk_memset_s(kek_bin, kek_len, 0, kek_len);
		free(kek_bin);
	}
	if (blob) {
		spdk_memset_s(blob, blob_len, 0, blob_len);
		free(blob);
	}

	return rc;
}

/* Decode the parameters for this RPC method and properly construct the crypto
 * device. Error status returned in the failed cases.
 */
static void
rpc_bdev_crypto_create(struct spdk_jsonrpc_request *request,
		       const struct spdk_json_val *params)
{
	struct rpc_construct_crypto req = {};
	struct vbdev_crypto_opts *crypto_opts = NULL;
	struct spdk_json_write_ctx *w;
	struct spdk_accel_crypto_key *key = NULL;
	struct spdk_accel_crypto_key *created_key = NULL;
	int rc = 0;

	if (spdk_json_decode_object(params, rpc_bdev_crypto_create_decoders,
				    SPDK_COUNTOF(rpc_bdev_crypto_create_decoders),
				    &req)) {
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_PARSE_ERROR,
						 "Failed to decode crypto disk create parameters.");
		goto cleanup;
	}

	if (!req.name) {
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						 "crypto_bdev name is missing");
		goto cleanup;
	}

	if (req.param.key_name) {
		/* New config version */
		key = spdk_accel_crypto_key_get(req.param.key_name);
		if (key) {
			if (req.param.hex_key || req.param.cipher || req.crypto_pmd) {
				SPDK_NOTICELOG("Key name specified, other parameters are ignored\n");
			}
			SPDK_NOTICELOG("Found key \"%s\"\n", req.param.key_name);
		}
	}

	/* No key_name. Support legacy configuration */
	if (!key) {
		if (req.param.key_name) {
			spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
							 "Key was not found");
			goto cleanup;
		}

		if (req.wrapped_key_b64 || req.wrapped_key2_b64) {
			if ((!req.kek_id || req.kek_id[0] == '\0') && (!req.kek_hex || req.kek_hex[0] == '\0')) {
					spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
													 "kek_id (preferred) or kek_hex (fallback) is required when wrapped_key is used");
					goto cleanup;
			}

			if (req.wrapped_key_b64) {
				char *hex = NULL;
				rc = decrypt_wrapped_key_to_hex(req.wrapped_key_b64, req.kek_id, req.kek_hex, &hex);
				if (rc) {
					spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
									 "Failed to decrypt wrapped_key");
					goto cleanup;
				}
				/* Override/define hex_key for accel key creation */
				req.param.hex_key = hex;
			}

			if (req.wrapped_key2_b64) {
				char *hex2 = NULL;
				rc = decrypt_wrapped_key_to_hex(req.wrapped_key2_b64, req.kek_id, req.kek_hex, &hex2);
				if (rc) {
					spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
									 "Failed to decrypt wrapped_key2");
					goto cleanup;
				}
				req.param.hex_key2 = hex2;
			}

			if (req.kek_id && req.kek_id[0] != '\0') {
				crypto_opts->kek_id = strdup(req.kek_id);
			}
			if (req.wrapped_key_b64) {
				crypto_opts->wrapped_key_b64 = strdup(req.wrapped_key_b64);
			}
			if (req.wrapped_key2_b64) {
				crypto_opts->wrapped_key2_b64 = strdup(req.wrapped_key2_b64);
			}

			if (req.param.hex_key && req.param.hex_key2) {
				rc = calc_dek_fp_from_hex(req.param.hex_key, req.param.hex_key2, crypto_opts->dek_fp);
				if (rc != 0) {
					spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
												 	"Failed to calculate DEK fingerprint");
					free_crypto_opts(crypto_opts);
					goto cleanup;
				}
				crypto_opts->dek_fp_valid = true;
			}
		}

		if (req.param.cipher == NULL) {
			req.param.cipher = strdup(BDEV_CRYPTO_DEFAULT_CIPHER);
			if (req.param.cipher == NULL) {
				spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
								 "Unable to allocate memory for req.cipher");
				goto cleanup;
			}
		}
		if (req.crypto_pmd) {
			SPDK_WARNLOG("\"crypto_pmd\" parameters is obsolete and ignored\n");
		}

		req.param.key_name = calloc(1, MAX_KEY_NAME_LEN);
		if (!req.param.key_name) {
			/* The new API requires key name. Create it as pmd_name + cipher */
			spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
							 "Unable to allocate memory for key_name");
			goto cleanup;
		}
		snprintf(req.param.key_name, MAX_KEY_NAME_LEN, "%s_%s", req.name, req.param.cipher);

		/* Try to find a key with generated name, we may be loading from a json config where crypto_bdev had no key_name parameter */
		key = spdk_accel_crypto_key_get(req.param.key_name);
		if (key) {
			SPDK_NOTICELOG("Found key \"%s\"\n", req.param.key_name);
		} else {
			rc = spdk_accel_crypto_key_create(&req.param);
			if (!rc) {
				key = spdk_accel_crypto_key_get(req.param.key_name);
				created_key = key;
			}
		}
	}

	if (!key) {
		/* We haven't found an existing key or were not able to create a new one */
		SPDK_ERRLOG("No key was found\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "No key was found");
		goto cleanup;
	}

	crypto_opts = create_crypto_opts(&req, key, created_key != NULL);
	if (!crypto_opts) {
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "Memory allocation failed");
		goto cleanup;
	}

	rc = create_crypto_disk(crypto_opts);
	if (rc) {
		spdk_jsonrpc_send_error_response(request, rc, spdk_strerror(-rc));
		free_crypto_opts(crypto_opts);
		goto cleanup;
	}

	w = spdk_jsonrpc_begin_result(request);
	spdk_json_write_string(w, req.name);
	spdk_jsonrpc_end_result(request, w);

cleanup:
	if (rc && created_key) {
		spdk_accel_crypto_key_destroy(created_key);
	}
	free_rpc_construct_crypto(&req);
}
SPDK_RPC_REGISTER("bdev_crypto_create", rpc_bdev_crypto_create, SPDK_RPC_RUNTIME)

struct rpc_crypto_update_wrapped {
	char *name;
	char *kek_id;
	char *kek_hex;            /* fallback */
	char *wrapped_key_b64;
	char *wrapped_key2_b64;
};

static void
free_rpc_crypto_update_wrapped(struct rpc_crypto_update_wrapped *r)
{
	free(r->name);
	free(r->kek_id);
	free(r->kek_hex);
	free(r->wrapped_key_b64);
	free(r->wrapped_key2_b64);
}

static const struct spdk_json_object_decoder rpc_crypto_update_wrapped_decoders[] = {
	{"name", offsetof(struct rpc_crypto_update_wrapped, name), spdk_json_decode_string},
	{"kek_id", offsetof(struct rpc_crypto_update_wrapped, kek_id), spdk_json_decode_string, true},
	{"kek_hex", offsetof(struct rpc_crypto_update_wrapped, kek_hex), spdk_json_decode_string, true},
	{"wrapped_key", offsetof(struct rpc_crypto_update_wrapped, wrapped_key_b64), spdk_json_decode_string},
	{"wrapped_key2", offsetof(struct rpc_crypto_update_wrapped, wrapped_key2_b64), spdk_json_decode_string},
};

static void
rpc_bdev_crypto_update_wrapped_keys(struct spdk_jsonrpc_request *request,
                                   const struct spdk_json_val *params)
{
	struct rpc_crypto_update_wrapped req = {};
	struct vbdev_crypto_opts *opts;
	char *hex1 = NULL, *hex2 = NULL;
	uint8_t fp[VBDEV_CRYPTO_DEK_FP_LEN];
	int rc;

	if (spdk_json_decode_object(params, rpc_crypto_update_wrapped_decoders,
                                SPDK_COUNTOF(rpc_crypto_update_wrapped_decoders),
                                &req)) {
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_PARSE_ERROR,
                                         "Failed to decode params");
		goto out;
	}

	if (!req.name) {
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
                                         "name is required");
		goto out;
	}

	if ((!req.kek_id || req.kek_id[0] == '\0') && (!req.kek_hex || req.kek_hex[0] == '\0')) {
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
                                         "kek_id (preferred) or kek_hex (fallback) is required");
		goto out;
	}

	opts = vbdev_crypto_get_opts_by_name(req.name);
	if (!opts) {
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
                                         "crypto bdev not found");
		goto out;
	}

	if (!opts->dek_fp_valid) {
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
                                         "DEK fingerprint is not available for this bdev");
		goto out;
	}

	rc = decrypt_wrapped_key_to_hex(req.wrapped_key_b64, req.kek_id, req.kek_hex, &hex1);
	if (rc != 0) {
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
                                         "Failed to decrypt wrapped_key");
		goto out;
	}

	rc = decrypt_wrapped_key_to_hex(req.wrapped_key2_b64, req.kek_id, req.kek_hex, &hex2);
	if (rc != 0) {
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
                                         "Failed to decrypt wrapped_key2");
		goto out;
	}

	rc = calc_dek_fp_from_hex(hex1, hex2, fp);
	if (rc != 0) {
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
                                         "Failed to calculate DEK fingerprint");
		goto out;
	}

	if (memcmp(fp, opts->dek_fp, VBDEV_CRYPTO_DEK_FP_LEN) != 0) {
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
                                         "Plaintext DEK changed (not a rewrap). Refusing.");
		goto out;
	}

	/* update metadata */
	free(opts->kek_id);
	free(opts->wrapped_key_b64);
	free(opts->wrapped_key2_b64);

	opts->kek_id = req.kek_id ? strdup(req.kek_id) : NULL;
	opts->wrapped_key_b64 = strdup(req.wrapped_key_b64);
	opts->wrapped_key2_b64 = strdup(req.wrapped_key2_b64);

	spdk_jsonrpc_send_bool_response(request, true);

out:
	if (hex1) {
		spdk_memset_s(hex1, strlen(hex1), 0, strlen(hex1));
		free(hex1);
	}
	if (hex2) {
		spdk_memset_s(hex2, strlen(hex2), 0, strlen(hex2));
		free(hex2);
	}
	free_rpc_crypto_update_wrapped(&req);
}

SPDK_RPC_REGISTER("bdev_crypto_update_wrapped_keys", rpc_bdev_crypto_update_wrapped_keys, SPDK_RPC_RUNTIME)

struct rpc_delete_crypto {
	char *name;
};

static void
free_rpc_delete_crypto(struct rpc_delete_crypto *req)
{
	free(req->name);
}

static const struct spdk_json_object_decoder rpc_bdev_crypto_delete_decoders[] = {
	{"name", offsetof(struct rpc_delete_crypto, name), spdk_json_decode_string},
};

static void
rpc_bdev_crypto_delete_cb(void *cb_arg, int bdeverrno)
{
	struct spdk_jsonrpc_request *request = cb_arg;

	if (bdeverrno == 0) {
		spdk_jsonrpc_send_bool_response(request, true);
	} else {
		spdk_jsonrpc_send_error_response(request, bdeverrno, spdk_strerror(-bdeverrno));
	}
}

static void
rpc_bdev_crypto_delete(struct spdk_jsonrpc_request *request,
		       const struct spdk_json_val *params)
{
	struct rpc_delete_crypto req = {NULL};

	if (spdk_json_decode_object(params, rpc_bdev_crypto_delete_decoders,
				    SPDK_COUNTOF(rpc_bdev_crypto_delete_decoders),
				    &req)) {
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						 "Invalid parameters");
		goto cleanup;
	}

	delete_crypto_disk(req.name, rpc_bdev_crypto_delete_cb, request);

	free_rpc_delete_crypto(&req);

	return;

cleanup:
	free_rpc_delete_crypto(&req);
}
SPDK_RPC_REGISTER("bdev_crypto_delete", rpc_bdev_crypto_delete, SPDK_RPC_RUNTIME)
