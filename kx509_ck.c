/*
 * Copyright (c) 2006-2007 Secure Endpoints Inc.
 *  
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include <stdio.h>
#if 0
#include "cryptlib.h"
#else
#include "openssl/crypto.h"
#endif
#include "openssl/err.h"
#include "openssl/asn1_mac.h"
#include "kx509_asn.h"
#include "openssl/hmac.h"
#if SSLEAY_VERSION_NUMBER < 0x00900000
#define ASN1_VISIBLESTRING ASN1_STRING 
#define ASN1_VISIBLESTRING_new()	(ASN1_VISIBLESTRING *)ASN1_STRING_type_new(V_ASN1_VISIBLESTRING)
#define i2d_ASN1_VISIBLESTRING(a,pp) i2d_ASN1_bytes((ASN1_STRING *)(a),(pp),V_ASN1_VISIBLESTRING,V_ASN1_UNIVERSAL)
#define d2i_ASN1_VISIBLESTRING(a,pp,l)	d2i_ASN1_bytes((ASN1_STRING **)(a),(pp),(l),V_ASN1_VISIBLESTRING,V_ASN1_UNIVERSAL)
#define ASN1_VISIBLESTRING_free(a)	ASN1_STRING_free((ASN1_STRING*)(a))
#endif

int
KX509_REQUEST_compute_checksum(unsigned char vs[4],
			       KX509_REQUEST *a,
			       ASN1_OCTET_STRING *o,
			       char *key,
			       int klen)
{
	HMAC_CTX hctx[1];
	const EVP_MD *md;
	char *digest;
	int dlen;
	int result = 0;

	md = EVP_sha1();
	HMAC_Init(hctx, key, klen, md);
	dlen = HMAC_size(hctx);
	if (o->length != dlen)
	{
		if (!(digest = Malloc(dlen)))
		{
			result = -1;
		}
		Free(o->data);
		o->data = (unsigned char *)digest;
		o->length = dlen;
	} else digest = (char *)o->data;
	/*
	 * Note: The following was changed from "sizeof vs" to "4"
	 * to fix 64-bit clients where "vs" is a pointer and
	 * "sizeof vs" is not 4.  Thanks to Ken McInnis.
	 */
	HMAC_Update(hctx, vs, 4);
	HMAC_Update(hctx, a->pkey->data, a->pkey->length);
	HMAC_Final(hctx, (unsigned char *)digest, 0);
	HMAC_cleanup(hctx);
	return result;
}

int
KX509_RESPONSE_compute_checksum(unsigned char vs[4],
				KX509_RESPONSE *a,
				ASN1_OCTET_STRING *o,
				char *key,
				int klen)
{
	HMAC_CTX hctx[1];
	const EVP_MD *md;
	char *digest;
	int dlen;
	int result = 0;
	char status_bytes[8];
	unsigned int temp;
	char *sp;

	md = EVP_sha1();
	HMAC_Init(hctx, key, klen, md);
	dlen = HMAC_size(hctx);
	if (o->length != dlen)
	{
		if (!(digest = Malloc(dlen)))
		{
			result = -1;
		}
		Free(o->data);
		o->data = (unsigned char *)digest;
		o->length = dlen;
	} else digest = (char *)o->data;
	/*
	 * Note: The following was changed from "sizeof vs" to "4"
	 * to fix 64-bit clients where "vs" is a pointer and
	 * "sizeof vs" is not 4.  Thanks to Ken McInnis.
	 */
	HMAC_Update(hctx, vs, 4);
	if (temp = a->status)
	{
		sp = status_bytes+sizeof status_bytes;
		do {
			*--sp = (char)temp;
			temp >>= 8;
		} while (temp);
		HMAC_Update(hctx, (unsigned char *)sp, (status_bytes+sizeof status_bytes)-sp);
	}
	if (a->certificate)
		HMAC_Update(hctx, a->certificate->data, a->certificate->length);
	if (a->error_message)
		HMAC_Update(hctx, a->error_message->data, a->error_message->length);
	HMAC_Final(hctx, (unsigned char *)digest, 0);
	HMAC_cleanup(hctx);
	return result;
}
