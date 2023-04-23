#include "rsakey.h"

#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "der.h"
#include "virtio_crypto.h"

void virtiot_crypto_akcipher_rsa_key_free(struct virtiot_crypto_rsa_key *rsa_key)
{
	if (!rsa_key) {
		return;
	}
	free(rsa_key->n.data);
	free(rsa_key->e.data);
	free(rsa_key->d.data);
	free(rsa_key->p.data);
	free(rsa_key->q.data);
	free(rsa_key->dp.data);
	free(rsa_key->dq.data);
	free(rsa_key->u.data);
	free(rsa_key);
}

static int extract_mpi(void *ctx, const uint8_t *value, size_t vlen)
{
	struct virtiot_crypto_mpi *mpi = (struct virtiot_crypto_mpi *)ctx;
	if (vlen == 0) {
		log_error("Empty mpi field");
		return -1;
	}
	mpi->data = malloc(vlen);
	memcpy(mpi->data, value, vlen);
	mpi->len = vlen;
	return 0;
}

static int extract_version(void *ctx, const uint8_t *value,
                           size_t vlen)
{
	uint8_t *version = (uint8_t *)ctx;
	if (vlen != 1 || *value > 1) {
		log_error("Invalid rsa_key version");
		return -1;
	}
	*version = *value;
	return 0;
}

static int extract_seq_content(void *ctx, const uint8_t *value, size_t vlen)
{
	const uint8_t **content = (const uint8_t **)ctx;
	if (vlen == 0) {
		log_error("Empty sequence");
		return -1;
	}
	*content = value;
	return 0;
}

/**
 *
 *        RsaPubKey ::= SEQUENCE {
 *             n           INTEGER
 *             e           INTEGER
 *         }
 */
static struct virtiot_crypto_rsa_key *virtiot_crypto_rsa_public_key_parse(
	const uint8_t *key, size_t keylen)
{
	struct virtiot_crypto_rsa_key *rsa = malloc(sizeof(struct virtiot_crypto_rsa_key));
	const uint8_t *seq;
	size_t seq_length;
	int decode_ret;

	memset(rsa, 0, sizeof(*rsa));
	decode_ret = virtiot_crypto_der_decode_seq(&key, &keylen, extract_seq_content, &seq);
	if (decode_ret < 0 || keylen != 0) {
		goto error;
	}
	seq_length = decode_ret;

	if (virtiot_crypto_der_decode_int(&seq, &seq_length, extract_mpi, &rsa->n) < 0 ||
	    virtiot_crypto_der_decode_int(&seq, &seq_length, extract_mpi, &rsa->e) < 0) {
		goto error;
	}
	if (seq_length != 0) {
		goto error;
	}

	return rsa;

error:
	virtiot_crypto_akcipher_rsa_key_free(rsa);
	return NULL;
}

/**
 *        RsaPrivKey ::= SEQUENCE {
 *             version     INTEGER
 *             n           INTEGER
 *             e           INTEGER
 *             d           INTEGER
 *             p           INTEGER
 *             q           INTEGER
 *             dp          INTEGER
 *             dq          INTEGER
 *             u           INTEGER
 *       otherPrimeInfos   OtherPrimeInfos OPTIONAL
 *         }
 */
static struct virtiot_crypto_rsa_key *virtiot_crypto_rsa_private_key_parse(
	const uint8_t *key, size_t keylen)
{
	struct virtiot_crypto_rsa_key *rsa = malloc(sizeof(struct virtiot_crypto_rsa_key));
	uint8_t version;
	const uint8_t *seq;
	int decode_ret;
	size_t seq_length;

	memset(rsa, 0, sizeof(*rsa));
	decode_ret = virtiot_crypto_der_decode_seq(&key, &keylen, extract_seq_content, &seq);
	if (decode_ret < 0 || keylen != 0) {
		goto error;
	}
	seq_length = decode_ret;

	decode_ret = virtiot_crypto_der_decode_int(&seq, &seq_length, extract_version, &version);

	if (virtiot_crypto_der_decode_int(&seq, &seq_length, extract_mpi, &rsa->n) < 0 ||
	    virtiot_crypto_der_decode_int(&seq, &seq_length, extract_mpi, &rsa->e) < 0 ||
	    virtiot_crypto_der_decode_int(&seq, &seq_length, extract_mpi, &rsa->d) < 0 ||
	    virtiot_crypto_der_decode_int(&seq, &seq_length, extract_mpi, &rsa->p) < 0 ||
	    virtiot_crypto_der_decode_int(&seq, &seq_length, extract_mpi, &rsa->q) < 0 ||
	    virtiot_crypto_der_decode_int(&seq, &seq_length, extract_mpi, &rsa->dp) < 0 ||
	    virtiot_crypto_der_decode_int(&seq, &seq_length, extract_mpi, &rsa->dq) < 0 ||
	    virtiot_crypto_der_decode_int(&seq, &seq_length, extract_mpi, &rsa->u) < 0) {
		goto error;
	}

	/**
	 * According to the standard, otherPrimeInfos must be present for version 1.
	 * There is no strict verification here, this is to be compatible with
	 * the unit test of the kernel. TODO: remove this until linux kernel's
	 * unit-test is fixed.
	 */
	if (version == 1 && seq_length != 0) {
		if (virtiot_crypto_der_decode_seq(&seq, &seq_length, NULL, NULL) < 0) {
			goto error;
		}
		if (seq_length != 0) {
			goto error;
		}
		return rsa;
	}
	if (seq_length != 0) {
		goto error;
	}

	return rsa;

error:
	virtiot_crypto_akcipher_rsa_key_free(rsa);
	return NULL;
}

struct virtiot_crypto_rsa_key *virtiot_crypto_akcipher_rsa_key_parse(
	int type, const uint8_t *key, size_t keylen)
{
	switch (type) {
	case VIRTIO_CRYPTO_AKCIPHER_KEY_TYPE_PRIVATE:
		return virtiot_crypto_rsa_private_key_parse(key, keylen);

	case VIRTIO_CRYPTO_AKCIPHER_KEY_TYPE_PUBLIC:
		return virtiot_crypto_rsa_public_key_parse(key, keylen);

	default:
		log_error("Unknown key type: %d", type);
		return NULL;
	}
}
