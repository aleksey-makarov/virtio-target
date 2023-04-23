#ifndef VIRTIOT_CRYPTO_RSAKEY_H
#define VIRTIOT_CRYPTO_RSAKEY_H

#include "types.h"

struct virtiot_crypto_mpi {
	uint8_t *data;
	size_t len;
};

/* See rfc2437: https://datatracker.ietf.org/doc/html/rfc2437 */
struct virtiot_crypto_rsa_key {
	/* The modulus */
	struct virtiot_crypto_mpi n;
	/* The public exponent */
	struct virtiot_crypto_mpi e;
	/* The private exponent */
	struct virtiot_crypto_mpi d;
	/* The first factor */
	struct virtiot_crypto_mpi p;
	/* The second factor */
	struct virtiot_crypto_mpi q;
	/* The first factor's exponent */
	struct virtiot_crypto_mpi dp;
	/* The second factor's exponent */
	struct virtiot_crypto_mpi dq;
	/* The CRT coefficient */
	struct virtiot_crypto_mpi u;
};

/**
 * Parse DER encoded ASN.1 RSA keys, expected ASN.1 schemas:
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
 *
 *        RsaPubKey ::= SEQUENCE {
 *             n           INTEGER
 *             e           INTEGER
 *         }
 *
 * Returns: On success virtiot_crypto_rsa_key is returned, otherwise returns NULL
 */
struct virtiot_crypto_rsa_key *virtiot_crypto_akcipher_rsa_key_parse(int key_type,
                                                       const uint8_t *key, size_t key_len);

void virtiot_crypto_akcipher_rsa_key_free(struct virtiot_crypto_rsa_key *key);

#endif
