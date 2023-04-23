#include "der.h"

#include <stdlib.h>
#include <string.h>

#include "log.h"

struct virtiot_crypto_der_encode_node {
	uint8_t tag;
	struct virtiot_crypto_der_encode_node *parent;
	struct virtiot_crypto_der_encode_node *next;
	/* for constructed type, data is null */
	const uint8_t *data;
	size_t dlen;
};

struct virtiot_crypto_der_encode_context {
	struct virtiot_crypto_der_encode_node root;
	struct virtiot_crypto_der_encode_node *current_parent;
	struct virtiot_crypto_der_encode_node *tail;
};

enum virtiot_crypto_der_type_tag {
	VIRTIOT_CRYPTO_DER_TYPE_TAG_BOOL = 0x1,
	VIRTIOT_CRYPTO_DER_TYPE_TAG_INT = 0x2,
	VIRTIOT_CRYPTO_DER_TYPE_TAG_BIT_STR = 0x3,
	VIRTIOT_CRYPTO_DER_TYPE_TAG_OCT_STR = 0x4,
	VIRTIOT_CRYPTO_DER_TYPE_TAG_NULL = 0x5,
	VIRTIOT_CRYPTO_DER_TYPE_TAG_OID = 0x6,
	VIRTIOT_CRYPTO_DER_TYPE_TAG_SEQ = 0x10,
	VIRTIOT_CRYPTO_DER_TYPE_TAG_SET = 0x11,
};

enum virtiot_crypto_der_tag_class {
	VIRTIOT_CRYPTO_DER_TAG_CLASS_UNIV = 0x0,
	VIRTIOT_CRYPTO_DER_TAG_CLASS_APPL = 0x1,
	VIRTIOT_CRYPTO_DER_TAG_CLASS_CONT = 0x2,
	VIRTIOT_CRYPTO_DER_TAG_CLASS_PRIV = 0x3,
};

enum virtiot_crypto_der_tag_enc {
	VIRTIOT_CRYPTO_DER_TAG_ENC_PRIM = 0x0,
	VIRTIOT_CRYPTO_DER_TAG_ENC_CONS = 0x1,
};

#define VIRTIOT_CRYPTO_DER_TAG_ENC_MASK 0x20
#define VIRTIOT_CRYPTO_DER_TAG_ENC_SHIFT 5

#define VIRTIOT_CRYPTO_DER_TAG_CLASS_MASK 0xc0
#define VIRTIOT_CRYPTO_DER_TAG_CLASS_SHIFT 6

#define VIRTIOT_CRYPTO_DER_TAG_VAL_MASK 0x1f
#define VIRTIOT_CRYPTO_DER_SHORT_LEN_MASK 0x80

#define VIRTIOT_CRYPTO_DER_TAG(class, enc, val)           \
	(((class) << VIRTIOT_CRYPTO_DER_TAG_CLASS_SHIFT) |    \
	 ((enc) << VIRTIOT_CRYPTO_DER_TAG_ENC_SHIFT) | (val))

/**
 * virtiot_crypto_der_encode_length:
 * @src_len: the length of source data
 * @dst: distination to save the encoded 'length', if dst is NULL, only compute
 * the expected buffer size in bytes.
 * @dst_len: output parameter, indicates how many bytes wrote.
 *
 * Encode the 'length' part of TLV tuple.
 */
static void virtiot_crypto_der_encode_length(size_t src_len,
					     uint8_t *dst, size_t *dst_len)
{
	size_t max_length = 0xFF;
	uint8_t length_bytes = 0, header_byte;

	if (src_len < VIRTIOT_CRYPTO_DER_SHORT_LEN_MASK) {
		header_byte = src_len;
		*dst_len = 1;
	} else {
		for (length_bytes = 1; max_length < src_len; length_bytes++) {
			max_length = (max_length << 8) + max_length;
		}
		header_byte = length_bytes;
		header_byte |= VIRTIOT_CRYPTO_DER_SHORT_LEN_MASK;
		*dst_len = length_bytes + 1;
	}
	if (!dst) {
		return;
	}
	*dst++ = header_byte;
	/* Bigendian length bytes */
	for (; length_bytes > 0; length_bytes--) {
		*dst++ = ((src_len >> (length_bytes - 1) * 8) & 0xFF);
	}
}

static uint8_t virtiot_crypto_der_peek_byte(const uint8_t **data, size_t *dlen)
{
	return **data;
}

static void virtiot_crypto_der_cut_nbytes(const uint8_t **data,
					  size_t *dlen,
					  size_t nbytes)
{
	*data += nbytes;
	*dlen -= nbytes;
}

static uint8_t virtiot_crypto_der_cut_byte(const uint8_t **data, size_t *dlen)
{
	uint8_t val = virtiot_crypto_der_peek_byte(data, dlen);

	virtiot_crypto_der_cut_nbytes(data, dlen, 1);

	return val;
}

static int virtiot_crypto_der_invoke_callback(virtiot_crypto_der_decode_cb cb, void *ctx,
					      const uint8_t *value, size_t vlen)
{
	if (!cb) {
		return 0;
	}

	return cb(ctx, value, vlen);
}

static int virtiot_crypto_der_extract_definite_data(const uint8_t **data, size_t *dlen,
						    virtiot_crypto_der_decode_cb cb, void *ctx)
{
	const uint8_t *value;
	size_t vlen = 0;
	uint8_t byte_count = virtiot_crypto_der_cut_byte(data, dlen);

	/* short format of definite-length */
	if (!(byte_count & VIRTIOT_CRYPTO_DER_SHORT_LEN_MASK)) {
		if (byte_count > *dlen) {
			log_error("Invalid content length: %u", byte_count);
			return -1;
		}

		value = *data;
		vlen = byte_count;
		virtiot_crypto_der_cut_nbytes(data, dlen, vlen);

		if (virtiot_crypto_der_invoke_callback(cb, ctx, value, vlen) != 0) {
			return -1;
		}
		return vlen;
	}

	/* Ignore highest bit */
	byte_count &= ~VIRTIOT_CRYPTO_DER_SHORT_LEN_MASK;

	/*
	 * size_t is enough to store the value of length, although the DER
	 * encoding standard supports larger length.
	 */
	if (byte_count > sizeof(size_t)) {
		log_error("Invalid byte count of content length: %u", byte_count);
		return -1;
	}

	if (byte_count > *dlen) {
		log_error("Invalid content length: %u", byte_count);
		return -1;
	}
	while (byte_count--) {
		vlen <<= 8;
		vlen += virtiot_crypto_der_cut_byte(data, dlen);
	}

	if (vlen > *dlen) {
		log_error("Invalid content length: %zu", vlen);
		return -1;
	}

	value = *data;
	virtiot_crypto_der_cut_nbytes(data, dlen, vlen);

	if (virtiot_crypto_der_invoke_callback(cb, ctx, value, vlen) != 0) {
		return -1;
	}
	return vlen;
}

static int virtiot_crypto_der_extract_data(const uint8_t **data, size_t *dlen,
					   virtiot_crypto_der_decode_cb cb, void *ctx)
{
	uint8_t val;
	if (*dlen < 1) {
		log_error("Need more data");
		return -1;
	}
	val = virtiot_crypto_der_peek_byte(data, dlen);

	/* must use definite length format */
	if (val == VIRTIOT_CRYPTO_DER_SHORT_LEN_MASK) {
		log_error("Only definite length format is allowed");
		return -1;
	}

	return virtiot_crypto_der_extract_definite_data(data, dlen, cb, ctx);
}

static int virtiot_crypto_der_decode_tlv(const uint8_t expected_tag,
					 const uint8_t **data, size_t *dlen,
					 virtiot_crypto_der_decode_cb cb,
					 void *ctx)
{
	const uint8_t *saved_data = *data;
	size_t saved_dlen = *dlen;
	uint8_t tag;
	int data_length;

	if (*dlen < 1) {
		log_error("Need more data");
		return -1;
	}
	tag = virtiot_crypto_der_cut_byte(data, dlen);
	if (tag != expected_tag) {
		log_error("Unexpected tag: expected: %u, actual: %u", expected_tag, tag);
		goto error;
	}

	data_length = virtiot_crypto_der_extract_data(data, dlen, cb, ctx);
	if (data_length < 0) {
		goto error;
	}
	return data_length;

error:
	*data = saved_data;
	*dlen = saved_dlen;
	return -1;
}

int virtiot_crypto_der_decode_int(const uint8_t **data, size_t *dlen,
                                  virtiot_crypto_der_decode_cb cb, void *ctx)
{
	const uint8_t tag = VIRTIOT_CRYPTO_DER_TAG(VIRTIOT_CRYPTO_DER_TAG_CLASS_UNIV,
	                                           VIRTIOT_CRYPTO_DER_TAG_ENC_PRIM,
	                                           VIRTIOT_CRYPTO_DER_TYPE_TAG_INT);
	return virtiot_crypto_der_decode_tlv(tag, data, dlen, cb, ctx);
}

int virtiot_crypto_der_decode_seq(const uint8_t **data, size_t *dlen,
				  virtiot_crypto_der_decode_cb cb, void *ctx)
{
	uint8_t tag = VIRTIOT_CRYPTO_DER_TAG(VIRTIOT_CRYPTO_DER_TAG_CLASS_UNIV,
	                                     VIRTIOT_CRYPTO_DER_TAG_ENC_CONS,
	                                     VIRTIOT_CRYPTO_DER_TYPE_TAG_SEQ);
	return virtiot_crypto_der_decode_tlv(tag, data, dlen, cb, ctx);
}

int virtiot_crypto_der_decode_octet_str(const uint8_t **data, size_t *dlen,
                                        virtiot_crypto_der_decode_cb cb, void *ctx)
{
	uint8_t tag = VIRTIOT_CRYPTO_DER_TAG(VIRTIOT_CRYPTO_DER_TAG_CLASS_UNIV,
	                                     VIRTIOT_CRYPTO_DER_TAG_ENC_PRIM,
	                                     VIRTIOT_CRYPTO_DER_TYPE_TAG_OCT_STR);
	return virtiot_crypto_der_decode_tlv(tag, data, dlen, cb, ctx);
}

int virtiot_crypto_der_decode_bit_str(const uint8_t **data, size_t *dlen,
                                      virtiot_crypto_der_decode_cb cb, void *ctx)
{
	uint8_t tag = VIRTIOT_CRYPTO_DER_TAG(VIRTIOT_CRYPTO_DER_TAG_CLASS_UNIV,
					              VIRTIOT_CRYPTO_DER_TAG_ENC_PRIM,
					              VIRTIOT_CRYPTO_DER_TYPE_TAG_BIT_STR);
	return virtiot_crypto_der_decode_tlv(tag, data, dlen, cb, ctx);
}

int virtiot_crypto_der_decode_oid(const uint8_t **data, size_t *dlen,
                                  virtiot_crypto_der_decode_cb cb, void *ctx)
{
	uint8_t tag = VIRTIOT_CRYPTO_DER_TAG(VIRTIOT_CRYPTO_DER_TAG_CLASS_UNIV,
	                                     VIRTIOT_CRYPTO_DER_TAG_ENC_PRIM,
	                                     VIRTIOT_CRYPTO_DER_TYPE_TAG_OID);
	return virtiot_crypto_der_decode_tlv(tag, data, dlen, cb, ctx);
}

int virtiot_crypto_der_decode_ctx_tag(const uint8_t **data, size_t *dlen, int tag_id,
                                      virtiot_crypto_der_decode_cb cb, void *ctx)
{
	uint8_t tag = VIRTIOT_CRYPTO_DER_TAG(VIRTIOT_CRYPTO_DER_TAG_CLASS_CONT,
	                                     VIRTIOT_CRYPTO_DER_TAG_ENC_CONS,
	                                     tag_id);
	return virtiot_crypto_der_decode_tlv(tag, data, dlen, cb, ctx);
}

static void virtiot_crypto_der_encode_prim(struct virtiot_crypto_der_encode_context *ctx, uint8_t tag,
                                           const uint8_t *data, size_t dlen)
{
	struct virtiot_crypto_der_encode_node *node = malloc(sizeof(struct virtiot_crypto_der_encode_node));
	size_t nbytes_len;

	memset(node, 0, sizeof(*node));
	node->tag = tag;
	node->data = data;
	node->dlen = dlen;
	node->parent = ctx->current_parent;

	virtiot_crypto_der_encode_length(dlen, NULL, &nbytes_len);
	/* 1 byte for Tag, nbyte_len for Length, and dlen for Value */
	node->parent->dlen += 1 + nbytes_len + dlen;

	ctx->tail->next = node;
	ctx->tail = node;
}

struct virtiot_crypto_der_encode_context *virtiot_crypto_der_encode_ctx_new(void)
{
	struct virtiot_crypto_der_encode_context *ctx = malloc(sizeof(struct virtiot_crypto_der_encode_context));

	memset(ctx, 0, sizeof(*ctx));
	ctx->current_parent = &ctx->root;
	ctx->tail = &ctx->root;
	return ctx;
}

static void virtiot_crypto_der_encode_cons_begin(struct virtiot_crypto_der_encode_context *ctx,
                                                 uint8_t tag)
{
	struct virtiot_crypto_der_encode_node *node = malloc(sizeof(struct virtiot_crypto_der_encode_node));

	memset(node, 0, sizeof(*node));
	node->tag = tag;
	node->parent = ctx->current_parent;
	ctx->current_parent = node;
	ctx->tail->next = node;
	ctx->tail = node;
}

static void virtiot_crypto_der_encode_cons_end(struct virtiot_crypto_der_encode_context *ctx)
{
	struct virtiot_crypto_der_encode_node *cons_node = ctx->current_parent;
	size_t nbytes_len;

	virtiot_crypto_der_encode_length(cons_node->dlen, NULL, &nbytes_len);
	/* 1 byte for Tag, nbyte_len for Length, and dlen for Value */
	cons_node->parent->dlen += 1 + nbytes_len + cons_node->dlen;
	ctx->current_parent = cons_node->parent;
}

void virtiot_crypto_der_encode_seq_begin(struct virtiot_crypto_der_encode_context *ctx)
{
	uint8_t tag = VIRTIOT_CRYPTO_DER_TAG(VIRTIOT_CRYPTO_DER_TAG_CLASS_UNIV,
	                                     VIRTIOT_CRYPTO_DER_TAG_ENC_CONS,
	                                     VIRTIOT_CRYPTO_DER_TYPE_TAG_SEQ);
	virtiot_crypto_der_encode_cons_begin(ctx, tag);
}

void virtiot_crypto_der_encode_seq_end(struct virtiot_crypto_der_encode_context *ctx)
{
	virtiot_crypto_der_encode_cons_end(ctx);
}

void virtiot_crypto_der_encode_oid(struct virtiot_crypto_der_encode_context *ctx,
                                   const uint8_t *src, size_t src_len)
{
	uint8_t tag = VIRTIOT_CRYPTO_DER_TAG(VIRTIOT_CRYPTO_DER_TAG_CLASS_UNIV,
					              VIRTIOT_CRYPTO_DER_TAG_ENC_PRIM,
					              VIRTIOT_CRYPTO_DER_TYPE_TAG_OID);
	virtiot_crypto_der_encode_prim(ctx, tag, src, src_len);
}

void virtiot_crypto_der_encode_int(struct virtiot_crypto_der_encode_context *ctx,
                                   const uint8_t *src, size_t src_len)
{
	uint8_t tag = VIRTIOT_CRYPTO_DER_TAG(VIRTIOT_CRYPTO_DER_TAG_CLASS_UNIV,
	                                     VIRTIOT_CRYPTO_DER_TAG_ENC_PRIM,
	                                     VIRTIOT_CRYPTO_DER_TYPE_TAG_INT);
	virtiot_crypto_der_encode_prim(ctx, tag, src, src_len);
}

void virtiot_crypto_der_encode_null(struct virtiot_crypto_der_encode_context *ctx)
{
	uint8_t tag = VIRTIOT_CRYPTO_DER_TAG(VIRTIOT_CRYPTO_DER_TAG_CLASS_UNIV,
	                                     VIRTIOT_CRYPTO_DER_TAG_ENC_PRIM,
	                                     VIRTIOT_CRYPTO_DER_TYPE_TAG_NULL);
	virtiot_crypto_der_encode_prim(ctx, tag, NULL, 0);
}

void virtiot_crypto_der_encode_octet_str(struct virtiot_crypto_der_encode_context *ctx,
                                         const uint8_t *src, size_t src_len)
{
	uint8_t tag = VIRTIOT_CRYPTO_DER_TAG(VIRTIOT_CRYPTO_DER_TAG_CLASS_UNIV,
	                                     VIRTIOT_CRYPTO_DER_TAG_ENC_PRIM,
	                                     VIRTIOT_CRYPTO_DER_TYPE_TAG_OCT_STR);
	virtiot_crypto_der_encode_prim(ctx, tag, src, src_len);
}

void virtiot_crypto_der_encode_octet_str_begin(struct virtiot_crypto_der_encode_context *ctx)
{
	uint8_t tag = VIRTIOT_CRYPTO_DER_TAG(VIRTIOT_CRYPTO_DER_TAG_CLASS_UNIV,
	                                     VIRTIOT_CRYPTO_DER_TAG_ENC_PRIM,
	                                     VIRTIOT_CRYPTO_DER_TYPE_TAG_OCT_STR);
	virtiot_crypto_der_encode_cons_begin(ctx, tag);
}

void virtiot_crypto_der_encode_octet_str_end(struct virtiot_crypto_der_encode_context *ctx)
{
	virtiot_crypto_der_encode_cons_end(ctx);
}

size_t virtiot_crypto_der_encode_ctx_buffer_len(struct virtiot_crypto_der_encode_context *ctx)
{
	return ctx->root.dlen;
}

void virtiot_crypto_der_encode_ctx_flush_and_free(struct virtiot_crypto_der_encode_context *ctx,
                                                  uint8_t *dst)
{
	struct virtiot_crypto_der_encode_node *node, *prev;
	size_t len;

	for (prev = &ctx->root;
		 (node = prev->next) && (prev->next = node->next, 1);) {
		/* Tag */
		*dst++ = node->tag;

		/* Length */
		virtiot_crypto_der_encode_length(node->dlen, dst, &len);
		dst += len;

		/* Value */
		if (node->data) {
			memcpy(dst, node->data, node->dlen);
			dst += node->dlen;
		}
		free(node);
	}
	free(ctx);
}
