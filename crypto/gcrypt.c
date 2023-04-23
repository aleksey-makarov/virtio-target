#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <linux/virtio_ids.h>
#include <sys/uio.h>
#include <gcrypt.h>

#include "virtio_crypto.h"
#include "crypto.h"
#include "device.h"
#include "fabrics.h"
#include "utils.h"
#include "log.h"
#include "rsakey.h"

#define MAX_SESSIONS	1024

struct virtiot_crypto_gcrypt_rsa_session {
	gcry_sexp_t key;
	int padding_alg;
	int hash_alg;
};

struct virtiot_crypto_gcrypt_session {
	bool inuse;
	int alg;
	union {
		struct virtiot_crypto_gcrypt_rsa_session rsa;
	};
};

struct virtiot_crypto_gcrypt_context {
	struct virtiot_crypto_gcrypt_session sessions[MAX_SESSIONS];
};

static const char *virtio_rsa_padding_alg_str(int alg)
{
	switch (alg) {
	case VIRTIO_CRYPTO_RSA_RAW_PADDING:
		return "raw";

	case VIRTIO_CRYPTO_RSA_PKCS1_PADDING:
		return "pkcs1";

	default:
		return NULL;
	}
}

static const char *virtio_rsa_hash_alg_str(int alg)
{
	switch (alg) {
	case VIRTIO_CRYPTO_RSA_MD5:
		return "md5";

	case VIRTIO_CRYPTO_RSA_SHA1:
		return "sha1";

	case VIRTIO_CRYPTO_RSA_SHA256:
		return "sha256";

	case VIRTIO_CRYPTO_RSA_SHA512:
		return "sha512";

	default:
		return NULL;
	}
}

static void *virtiot_crypto_gcrypt_open(const char *backend)
{
	struct virtiot_crypto_gcrypt_context *ctx;

	ctx = calloc(sizeof(struct virtiot_crypto_gcrypt_context), 1);
	assert(ctx);
	/* gcry_control(GCRYCTL_SET_DEBUG_FLAGS,  3); XXX: DEBUG ONLY */

	return ctx;
}

static void virtiot_crypto_gcrypt_close(void *context)
{
	free(context);
}

static int virtiot_crypto_gcrypt_parse_rsa_private_key(
	struct virtiot_crypto_gcrypt_rsa_session *rsa,
	const uint8_t *key, size_t key_len)
{
	struct virtiot_crypto_rsa_key *rsa_key = virtiot_crypto_akcipher_rsa_key_parse(
		VIRTIO_CRYPTO_AKCIPHER_KEY_TYPE_PRIVATE, key, key_len);
	gcry_mpi_t n = NULL, e = NULL, d = NULL, p = NULL, q = NULL, u = NULL;
	bool compute_mul_inv = false;
	int ret = -1;
	gcry_error_t err;

	if (!rsa_key) {
		return ret;
	}

	err = gcry_mpi_scan(&n, GCRYMPI_FMT_STD, rsa_key->n.data, rsa_key->n.len, NULL);
	if (gcry_err_code(err) != 0) {
		log_error("Failed to parse RSA parameter n: %s/%s",
				gcry_strsource(err), gcry_strerror(err));
		goto cleanup;
	}

	err = gcry_mpi_scan(&e, GCRYMPI_FMT_STD, rsa_key->e.data, rsa_key->e.len, NULL);
	if (gcry_err_code(err) != 0) {
		log_error("Failed to parse RSA parameter e: %s/%s",
				gcry_strsource(err), gcry_strerror(err));
		goto cleanup;
	}

	err = gcry_mpi_scan(&d, GCRYMPI_FMT_STD, rsa_key->d.data, rsa_key->d.len, NULL);
	if (gcry_err_code(err) != 0) {
		log_error("Failed to parse RSA parameter d: %s/%s",
				gcry_strsource(err), gcry_strerror(err));
		goto cleanup;
	}

	err = gcry_mpi_scan(&p, GCRYMPI_FMT_STD, rsa_key->p.data, rsa_key->p.len, NULL);
	if (gcry_err_code(err) != 0) {
		log_error("Failed to parse RSA parameter p: %s/%s",
				gcry_strsource(err), gcry_strerror(err));
		goto cleanup;
	}

	err = gcry_mpi_scan(&q, GCRYMPI_FMT_STD, rsa_key->q.data, rsa_key->q.len, NULL);
	if (gcry_err_code(err) != 0) {
		log_error("Failed to parse RSA parameter q: %s/%s",
				gcry_strsource(err), gcry_strerror(err));
		goto cleanup;
	}

	if (gcry_mpi_cmp_ui(p, 0) > 0 && gcry_mpi_cmp_ui(q, 0) > 0) {
		compute_mul_inv = true;

		u = gcry_mpi_new(0);
		if (gcry_mpi_cmp(p, q) > 0) {
			gcry_mpi_swap(p, q);
		}
		gcry_mpi_invm(u, p, q);
	}

	if (compute_mul_inv) {
		err = gcry_sexp_build(&rsa->key, NULL,
				"(private-key (rsa (n %m) (e %m) (d %m) (p %m) (q %m) (u %m)))",
				n, e, d, p, q, u);
	} else {
		err = gcry_sexp_build(&rsa->key, NULL,
				"(private-key (rsa (n %m) (e %m) (d %m)))", n, e, d);
	}
	if (gcry_err_code(err) != 0) {
		log_error("Failed to build RSA private key: %s/%s",
				gcry_strsource(err), gcry_strerror(err));
		goto cleanup;
	}
	ret = 0;

cleanup:
	gcry_mpi_release(n);
	gcry_mpi_release(e);
	gcry_mpi_release(d);
	gcry_mpi_release(p);
	gcry_mpi_release(q);
	gcry_mpi_release(u);
	virtiot_crypto_akcipher_rsa_key_free(rsa_key);
	return ret;
}

static int virtiot_crypto_gcrypt_parse_rsa_public_key(struct virtiot_crypto_gcrypt_rsa_session *rsa, const uint8_t *key, size_t key_len)
{

	struct virtiot_crypto_rsa_key *rsa_key = virtiot_crypto_akcipher_rsa_key_parse(
			VIRTIO_CRYPTO_AKCIPHER_KEY_TYPE_PUBLIC, key, key_len);
	gcry_mpi_t n = NULL, e = NULL;
	int ret = -1;
	gcry_error_t err;

	if (!rsa_key) {
		return ret;
	}

	err = gcry_mpi_scan(&n, GCRYMPI_FMT_STD, rsa_key->n.data, rsa_key->n.len, NULL);
	if (gcry_err_code(err) != 0) {
		log_error("Failed to parse RSA parameter n: %s/%s",
				gcry_strsource(err), gcry_strerror(err));
		goto cleanup;
	}

	err = gcry_mpi_scan(&e, GCRYMPI_FMT_STD, rsa_key->e.data, rsa_key->e.len, NULL);
	if (gcry_err_code(err) != 0) {
		log_error("Failed to parse RSA parameter e: %s/%s",
				gcry_strsource(err), gcry_strerror(err));
		goto cleanup;
	}

	err = gcry_sexp_build(&rsa->key, NULL, "(public-key (rsa (n %m) (e %m)))", n, e);
	if (gcry_err_code(err) != 0) {
		log_error("Failed to build RSA public key: %s/%s",
				gcry_strsource(err), gcry_strerror(err));
		goto cleanup;
	}
	ret = 0;

cleanup:
	gcry_mpi_release(n);
	gcry_mpi_release(e);
	virtiot_crypto_akcipher_rsa_key_free(rsa_key);
	return ret;
}

static void virtiot_crypto_gcrypt_rsa_clean(struct virtiot_crypto_gcrypt_rsa_session *rsa)
{
	if (!rsa) {
		return;
	}
	gcry_sexp_release(rsa->key);
}

static int virtiot_crypto_gcrypt_create_session(void *context,
	struct virtio_crypto_akcipher_create_session_req *req, void *key, __u32 key_len)
{
	struct virtiot_crypto_gcrypt_context *ctx = context;
	struct virtiot_crypto_gcrypt_session *session;
	int i;

	for (i = 0; i < MAX_SESSIONS; i++) {
		session = &ctx->sessions[i];
		if (!session->inuse) {
			break;
		}
	}

	if (i == MAX_SESSIONS) {
		return -EBUSY;
	}

	session->inuse = true;
	if (req->para.algo != VIRTIO_CRYPTO_AKCIPHER_RSA) {
		log_error("Unsupported alg: %d", req->para.algo);
		return -1;
	}

	session->rsa.padding_alg = req->para.u.rsa.padding_algo;
	session->rsa.hash_alg = req->para.u.rsa.hash_algo;
	switch (req->para.keytype) {
	case VIRTIO_CRYPTO_AKCIPHER_KEY_TYPE_PRIVATE:
		if (virtiot_crypto_gcrypt_parse_rsa_private_key(&session->rsa, key, key_len) != 0) {
			goto error;
		}
		break;

	case VIRTIO_CRYPTO_AKCIPHER_KEY_TYPE_PUBLIC:
		if (virtiot_crypto_gcrypt_parse_rsa_public_key(&session->rsa, key, key_len) != 0) {
			goto error;
		}
		break;

	default:
		log_error("Unknown akcipher key type %d", req->para.algo);
		goto error;
	}
	return i;

error:
	virtiot_crypto_gcrypt_rsa_clean(&session->rsa);
	return -1;
}

static int virtiot_crypto_gcrypt_destroy_session(void *context, __u64 id)
{
	struct virtiot_crypto_gcrypt_context *ctx = context;
	struct virtiot_crypto_gcrypt_session *session;

	if (id >= MAX_SESSIONS) {
		return -EINVAL;
	}

	session = &ctx->sessions[id];
	session->inuse = false;

	virtiot_crypto_gcrypt_rsa_clean(&session->rsa);

	return 0;
}

static int virtiot_crypto_gcrypt_ak_encrypt(void *context, __u64 id, const void *in, size_t src_len, void *out, size_t dst_len)
{
	struct virtiot_crypto_gcrypt_context *ctx = (struct virtiot_crypto_gcrypt_context *)context;
	struct virtiot_crypto_gcrypt_rsa_session *rsa = &ctx->sessions[id].rsa;
	int ret = -1;
	gcry_sexp_t data_sexp = NULL, cipher_sexp = NULL;
	gcry_sexp_t cipher_sexp_item = NULL;
	gcry_mpi_t cipher_mpi = NULL;
	const char *result;
	gcry_error_t err;
	size_t actual_len;

	err = gcry_sexp_build(&data_sexp, NULL,
	                      "(data (flags %s) (value %b))",
	                      virtio_rsa_padding_alg_str(rsa->padding_alg),
	                      src_len, in);
	if (gcry_err_code(err) != 0) {
		log_error("Failed to build plaintext: %s/%s",
		           gcry_strsource(err), gcry_strerror(err));
		goto cleanup;
	}

	err = gcry_pk_encrypt(&cipher_sexp, data_sexp, rsa->key);
	if (gcry_err_code(err) != 0) {
		log_error("Failed to encrypt: %s/%s",
		           gcry_strsource(err), gcry_strerror(err));
		goto cleanup;
	}

	/* S-expression of cipher: (enc-val (rsa (a a-mpi))) */
	cipher_sexp_item = gcry_sexp_find_token(cipher_sexp, "a", 0);
	if (!cipher_sexp_item || gcry_sexp_length(cipher_sexp_item) != 2) {
		log_error("Invalid ciphertext result");
		goto cleanup;
	}

	if (rsa->padding_alg == VIRTIO_CRYPTO_RSA_RAW_PADDING) {
		cipher_mpi = gcry_sexp_nth_mpi(cipher_sexp_item, 1, GCRYMPI_FMT_USG);
		if (!cipher_mpi) {
		    log_error("Invalid ciphertext result");
		    goto cleanup;
		}
		err = gcry_mpi_print(GCRYMPI_FMT_USG, out, dst_len,
		                     &actual_len, cipher_mpi);
		if (gcry_err_code(err) != 0) {
		    log_error("Failed to print MPI: %s/%s",
		               gcry_strsource(err), gcry_strerror(err));
		    goto cleanup;
		}

		if (actual_len > dst_len) {
		    log_error("Ciphertext buffer length is too small");
		    goto cleanup;
		}

		/* We always padding leading-zeros for RSA-RAW */
		if (actual_len < dst_len) {
		    memmove((uint8_t *)out + (dst_len - actual_len), out, actual_len);
		    memset(out, 0, dst_len - actual_len);
		}
		ret = dst_len;

	} else {
		result = gcry_sexp_nth_data(cipher_sexp_item, 1, &actual_len);
		if (!result) {
		    log_error("Invalid ciphertext result");
		    goto cleanup;
		}
		if (actual_len > dst_len) {
		    log_error("Ciphertext buffer length is too small");
		    goto cleanup;
		}
		memcpy(out, result, actual_len);
		ret = actual_len;
	}

cleanup:
	gcry_sexp_release(data_sexp);
	gcry_sexp_release(cipher_sexp);
	gcry_sexp_release(cipher_sexp_item);
	gcry_mpi_release(cipher_mpi);
	return ret;
}

static int virtiot_crypto_gcrypt_ak_decrypt(void *context, __u64 id, const void *in, size_t src_len, void *out, size_t dst_len)
{
	struct virtiot_crypto_gcrypt_context *ctx = (struct virtiot_crypto_gcrypt_context *)context;
	struct virtiot_crypto_gcrypt_rsa_session *rsa = &ctx->sessions[id].rsa;
	int ret = -1;
	gcry_sexp_t data_sexp = NULL, cipher_sexp = NULL;
	gcry_mpi_t data_mpi = NULL;
	gcry_error_t err;
	size_t actual_len;
	const char *result;

	err = gcry_sexp_build(&cipher_sexp, NULL,
		                  "(enc-val (flags %s) (rsa (a %b) ))",
		                  virtio_rsa_padding_alg_str(rsa->padding_alg),
		                  src_len, in);
	if (gcry_err_code(err) != 0) {
		log_error("Failed to build ciphertext: %s/%s",
		           gcry_strsource(err), gcry_strerror(err));
		goto cleanup;
	}

	err = gcry_pk_decrypt(&data_sexp, cipher_sexp, rsa->key);
	if (gcry_err_code(err) != 0) {
		log_error("Failed to decrypt: %s/%s",
		           gcry_strsource(err), gcry_strerror(err));
		goto cleanup;
	}

	/* S-expression of plaintext: (value plaintext) */
	if (rsa->padding_alg == VIRTIO_CRYPTO_RSA_RAW_PADDING) {
		data_mpi = gcry_sexp_nth_mpi(data_sexp, 1, GCRYMPI_FMT_USG);
		if (!data_mpi) {
		    log_error("Invalid plaintext result");
		    goto cleanup;
		}
		err = gcry_mpi_print(GCRYMPI_FMT_USG, out, dst_len,
		                     &actual_len, data_mpi);
		if (gcry_err_code(err) != 0) {
		    log_error("Failed to print MPI: %s/%s",
		               gcry_strsource(err), gcry_strerror(err));
		    goto cleanup;
		}
		if (actual_len > dst_len) {
		    log_error("Plaintext buffer length is too small");
		    goto cleanup;
		}
		/* We always padding leading-zeros for RSA-RAW */
		if (actual_len < dst_len) {
		    memmove((uint8_t *)out + (dst_len - actual_len), out, actual_len);
		    memset(out, 0, dst_len - actual_len);
		}
		ret = dst_len;
	} else {
		result = gcry_sexp_nth_data(data_sexp, 1, &actual_len);
		if (!result) {
		    log_error("Invalid plaintext result");
		    goto cleanup;
		}
		if (actual_len > dst_len) {
		    log_error("Plaintext buffer length is too small");
		    goto cleanup;
		}
		memcpy(out, result, actual_len);
		ret = actual_len;
	}

cleanup:
	gcry_sexp_release(cipher_sexp);
	gcry_sexp_release(data_sexp);
	gcry_mpi_release(data_mpi);
	return ret;
}

static int virtiot_crypto_gcrypt_ak_sign(void *context, __u64 id, const void *in, size_t src_len, void *out, size_t dst_len)
{
	struct virtiot_crypto_gcrypt_context *ctx = (struct virtiot_crypto_gcrypt_context *)context;
	struct virtiot_crypto_gcrypt_rsa_session *rsa = &ctx->sessions[id].rsa;
	int ret = -1;
	gcry_sexp_t dgst_sexp = NULL, sig_sexp = NULL;
	gcry_sexp_t sig_sexp_item = NULL;
	const char *result;
	gcry_error_t err;
	size_t actual_len;

	if (rsa->padding_alg != VIRTIO_CRYPTO_RSA_PKCS1_PADDING) {
		log_error("Invalid padding %u", rsa->padding_alg);
		return ret;
	}

	err = gcry_sexp_build(&dgst_sexp, NULL,
		                  "(data (flags pkcs1) (hash %s %b))",
		                  virtio_rsa_hash_alg_str(rsa->hash_alg),
		                  src_len, in);
	if (gcry_err_code(err) != 0) {
		log_error("Failed to build dgst: %s/%s",
		           gcry_strsource(err), gcry_strerror(err));
		goto cleanup;
	}

	err = gcry_pk_sign(&sig_sexp, dgst_sexp, rsa->key);
	if (gcry_err_code(err) != 0) {
		log_error("Failed to make signature: %s/%s",
		           gcry_strsource(err), gcry_strerror(err));
		goto cleanup;
	}

	/* S-expression of signature: (sig-val (rsa (s s-mpi))) */
	sig_sexp_item = gcry_sexp_find_token(sig_sexp, "s", 0);
	if (!sig_sexp_item || gcry_sexp_length(sig_sexp_item) != 2) {
		log_error("Invalid signature result");
		goto cleanup;
	}

	result = gcry_sexp_nth_data(sig_sexp_item, 1, &actual_len);
	if (!result) {
		log_error("Invalid signature result");
		goto cleanup;
	}

	if (actual_len > dst_len) {
		log_error("Signature buffer length is too small");
		goto cleanup;
	}
	memcpy(out, result, actual_len);
	ret = actual_len;

cleanup:
	gcry_sexp_release(dgst_sexp);
	gcry_sexp_release(sig_sexp);
	gcry_sexp_release(sig_sexp_item);

	return ret;
}

static int virtiot_crypto_gcrypt_ak_verify(void *context, __u64 id, const void *in1, size_t src_len1, void *in2, size_t src_len2)
{
	struct virtiot_crypto_gcrypt_context *ctx = (struct virtiot_crypto_gcrypt_context *)context;
	struct virtiot_crypto_gcrypt_rsa_session *rsa = &ctx->sessions[id].rsa;
	int ret = -1;
	gcry_sexp_t sig_sexp = NULL, dgst_sexp = NULL;
	gcry_error_t err;

	if (rsa->padding_alg != VIRTIO_CRYPTO_RSA_PKCS1_PADDING) {
		log_error("Invalid padding %u", rsa->padding_alg);
		return ret;
	}

	err = gcry_sexp_build(&sig_sexp, NULL,
		                  "(sig-val (rsa (s %b)))", src_len1, in1);
	if (gcry_err_code(err) != 0) {
		log_error("Failed to build signature: %s/%s",
		           gcry_strsource(err), gcry_strerror(err));
		goto cleanup;
	}

	err = gcry_sexp_build(&dgst_sexp, NULL,
		                  "(data (flags pkcs1) (hash %s %b))",
		                  virtio_rsa_hash_alg_str(rsa->hash_alg),
		                  src_len2, in2);
	if (gcry_err_code(err) != 0) {
		log_error("Failed to build dgst: %s/%s",
		           gcry_strsource(err), gcry_strerror(err));
		goto cleanup;
	}

	err = gcry_pk_verify(sig_sexp, dgst_sexp, rsa->key);
	if (gcry_err_code(err) != 0) {
		log_error("Failed to verify signature: %s/%s",
		           gcry_strsource(err), gcry_strerror(err));
		goto cleanup;
	}
	ret = 0;

cleanup:
	gcry_sexp_release(dgst_sexp);
	gcry_sexp_release(sig_sexp);

	return ret;
}

static struct virtiot_crypto_driver virtiot_crypto_gcrypt = {
	.vtdrv = {
		.vtobj = {
			.id = "crypto-gcrypt",
			.type = virtiot_object_driver,
		},
	},
	.open = virtiot_crypto_gcrypt_open,
	.close = virtiot_crypto_gcrypt_close,
	.create_session = virtiot_crypto_gcrypt_create_session,
	.destroy_session = virtiot_crypto_gcrypt_destroy_session,
	.ak_encrypt = virtiot_crypto_gcrypt_ak_encrypt,
	.ak_decrypt = virtiot_crypto_gcrypt_ak_decrypt,
	.ak_sign = virtiot_crypto_gcrypt_ak_sign,
	.ak_verify = virtiot_crypto_gcrypt_ak_verify,
};

static void __attribute__((constructor)) virtiot_be_crypto_init(void)
{
	virtiot_driver_register(&virtiot_crypto_gcrypt.vtdrv);
}
