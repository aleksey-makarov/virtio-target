#ifndef VIRTIOT_CRYPTO_DER_H
#define VIRTIOT_CRYPTO_DER_H

#include <stddef.h>

#include "types.h"


/* rsaEncryption: 1.2.840.113549.1.1.1 */
#define VIRTIOT_CRYPTO_OID_rsaEncryption "\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01"

struct virtiot_crypto_der_encode_context;

/* Simple decoder used to parse DER encoded rsa keys. */
/**
 *  @opaque: user context.
 *  @value: the starting address of |value| part of 'Tag-Length-Value' pattern.
 *  @vlen: length of the |value|.
 *  Returns: 0 for success, any other value is considered an error.
 */
typedef int (*virtiot_crypto_der_decode_cb) (void *opaque, const uint8_t *value, size_t vlen);

/**
 * virtiot_crypto_der_decode_int:
 * @data: pointer to address of input data
 * @dlen: pointer to length of input data
 * @cb: callback invoked when decode succeed, if cb equals NULL, no
 * callback will be invoked
 * @opaque: parameter passed to cb
 *
 * Decode integer from DER-encoded data.
 *
 * Returns: On success, *data points to rest data, and *dlen
 * will be set to the rest length of data, if cb is not NULL, must
 * return 0 to make decode success, at last, the length of the data
 * part of the decoded INTEGER will be returned. Otherwise, -1 is
 * returned and the valued of *data and *dlen keep unchanged.
 */
int virtiot_crypto_der_decode_int(const uint8_t **data,
                                  size_t *dlen,
                                  virtiot_crypto_der_decode_cb cb,
                                  void *opaque);
/**
 * virtiot_crypto_der_decode_seq:
 *
 * Decode sequence from DER-encoded data, similar with der_decode_int.
 *
 * @data: pointer to address of input data
 * @dlen: pointer to length of input data
 * @cb: callback invoked when decode succeed, if cb equals NULL, no
 * callback will be invoked
 * @opaque: parameter passed to cb
 *
 * Returns: On success, *data points to rest data, and *dlen
 * will be set to the rest length of data, if cb is not NULL, must
 * return 0 to make decode success, at last, the length of the data
 * part of the decoded SEQUENCE will be returned. Otherwise, -1 is
 * returned and the valued of *data and *dlen keep unchanged.
 */
int virtiot_crypto_der_decode_seq(const uint8_t **data,
                                  size_t *dlen,
                                  virtiot_crypto_der_decode_cb cb,
                                  void *opaque);

/**
 * virtiot_crypto_der_decode_oid:
 *
 * Decode OID from DER-encoded data, similar with der_decode_int.
 *
 * @data: pointer to address of input data
 * @dlen: pointer to length of input data
 * @cb: callback invoked when decode succeed, if cb equals NULL, no
 * callback will be invoked
 * @opaque: parameter passed to cb
 *
 * Returns: On success, *data points to rest data, and *dlen
 * will be set to the rest length of data, if cb is not NULL, must
 * return 0 to make decode success, at last, the length of the data
 * part of the decoded OID will be returned. Otherwise, -1 is
 * returned and the valued of *data and *dlen keep unchanged.
 */
int virtiot_crypto_der_decode_oid(const uint8_t **data,
                                  size_t *dlen,
                                  virtiot_crypto_der_decode_cb cb,
                                  void *opaque);

/**
 * virtiot_crypto_der_decode_octet_str:
 *
 * Decode OCTET STRING from DER-encoded data, similar with der_decode_int.
 *
 * @data: pointer to address of input data
 * @dlen: pointer to length of input data
 * @cb: callback invoked when decode succeed, if cb equals NULL, no
 * callback will be invoked
 * @opaque: parameter passed to cb
 *
 * Returns: On success, *data points to rest data, and *dlen
 * will be set to the rest length of data, if cb is not NULL, must
 * return 0 to make decode success, at last, the length of the data
 * part of the decoded OCTET STRING will be returned. Otherwise, -1 is
 * returned and the valued of *data and *dlen keep unchanged.
 */
int virtiot_crypto_der_decode_octet_str(const uint8_t **data,
                                        size_t *dlen,
                                        virtiot_crypto_der_decode_cb cb,
                                        void *opaque);

/**
 * virtiot_crypto_der_decode_bit_str:
 *
 * Decode BIT STRING from DER-encoded data, similar with der_decode_int.
 *
 * @data: pointer to address of input data
 * @dlen: pointer to length of input data
 * @cb: callback invoked when decode succeed, if cb equals NULL, no
 * callback will be invoked
 * @opaque: parameter passed to cb
 *
 * Returns: On success, *data points to rest data, and *dlen
 * will be set to the rest length of data, if cb is not NULL, must
 * return 0 to make decode success, at last, the length of the data
 * part of the decoded BIT STRING will be returned. Otherwise, -1 is
 * returned and the valued of *data and *dlen keep unchanged.
 */
int virtiot_crypto_der_decode_bit_str(const uint8_t **data,
                                      size_t *dlen,
                                      virtiot_crypto_der_decode_cb cb,
                                      void *opaque);

/**
 * virtiot_crypto_der_decode_ctx_tag:
 *
 * Decode context specific tag
 *
 * @data: pointer to address of input data
 * @dlen: pointer to length of input data
 * @tag: expected value of context specific tag
 * @cb: callback invoked when decode succeed, if cb equals NULL, no
 * callback will be invoked
 * @opaque: parameter passed to cb
 *
 * Returns: On success, *data points to rest data, and *dlen
 * will be set to the rest length of data, if cb is not NULL, must
 * return 0 to make decode success, at last, the length of the data
 * part of the decoded BIT STRING will be returned. Otherwise, -1 is
 * returned and the valued of *data and *dlen keep unchanged.
 */
int virtiot_crypto_der_decode_ctx_tag(const uint8_t **data,
                                      size_t *dlen, int tag_id,
                                      virtiot_crypto_der_decode_cb cb,
                                      void *opaque);

/**
 * virtiot_crypto_der_encode_ctx_new:
 *
 * Allocate a context used for der encoding.
 */
struct virtiot_crypto_der_encode_context *virtiot_crypto_der_encode_ctx_new(void);

/**
 * virtiot_crypto_der_encode_seq_begin:
 * @ctx: the encode context.
 *
 * Start encoding a SEQUENCE for ctx.
 *
 */
void virtiot_crypto_der_encode_seq_begin(struct virtiot_crypto_der_encode_context *ctx);

/**
 * virtiot_crypto_der_encode_seq_begin:
 * @ctx: the encode context.
 *
 * Finish uencoding a SEQUENCE for ctx.
 *
 */
void virtiot_crypto_der_encode_seq_end(struct virtiot_crypto_der_encode_context *ctx);


/**
 * virtiot_crypto_der_encode_oid:
 * @ctx: the encode context.
 * @src: the source data of oid, note it should be already encoded, this
 * function only add tag and length part for it.
 *
 * Encode an oid into ctx.
 */
void virtiot_crypto_der_encode_oid(struct virtiot_crypto_der_encode_context *ctx,
                                   const uint8_t *src, size_t src_len);

/**
 * virtiot_crypto_der_encode_int:
 * @ctx: the encode context.
 * @src: the source data of integer, note it should be already encoded, this
 * function only add tag and length part for it.
 *
 * Encode an integer into ctx.
 */
void virtiot_crypto_der_encode_int(struct virtiot_crypto_der_encode_context *ctx,
                                   const uint8_t *src, size_t src_len);

/**
 * virtiot_crypto_der_encode_null:
 * @ctx: the encode context.
 *
 * Encode a null into ctx.
 */
void virtiot_crypto_der_encode_null(struct virtiot_crypto_der_encode_context *ctx);

/**
 * virtiot_crypto_der_encode_octet_str:
 * @ctx: the encode context.
 * @src: the source data of the octet string.
 *
 * Encode a octet string into ctx.
 */
void virtiot_crypto_der_encode_octet_str(struct virtiot_crypto_der_encode_context *ctx,
                                         const uint8_t *src, size_t src_len);

/**
 * virtiot_crypto_der_encode_octet_str_begin:
 * @ctx: the encode context.
 *
 * Start encoding a octet string, All fields between
 * virtiot_crypto_der_encode_octet_str_begin and virtiot_crypto_der_encode_octet_str_end
 * are encoded as an octet string. This is useful when we need to encode a
 * encoded SEQUNCE as OCTET STRING.
 */
void virtiot_crypto_der_encode_octet_str_begin(struct virtiot_crypto_der_encode_context *ctx);

/**
 * virtiot_crypto_der_encode_octet_str_end:
 * @ctx: the encode context.
 *
 * Finish encoding a octet string, All fields between
 * virtiot_crypto_der_encode_octet_str_begin and virtiot_crypto_der_encode_octet_str_end
 * are encoded as an octet string. This is useful when we need to encode a
 * encoded SEQUNCE as OCTET STRING.
 */
void virtiot_crypto_der_encode_octet_str_end(struct virtiot_crypto_der_encode_context *ctx);

/**
 * virtiot_crypto_der_encode_ctx_buffer_len:
 * @ctx: the encode context.
 *
 * Compute the expected buffer size to save all encoded things.
 */
size_t virtiot_crypto_der_encode_ctx_buffer_len(struct virtiot_crypto_der_encode_context *ctx);

/**
 * virtiot_crypto_der_encode_ctx_flush_and_free:
 * @ctx: the encode context.
 * @dst: the distination to save the encoded data, the length of dst should
 * not less than virtiot_crypto_der_encode_cxt_buffer_len
 *
 * Flush all encoded data into dst, then free ctx.
 */
void virtiot_crypto_der_encode_ctx_flush_and_free(struct virtiot_crypto_der_encode_context *ctx,
                                                  uint8_t *dst);

#endif  /* VIRTIOT_CRYPTO_DER_H */
