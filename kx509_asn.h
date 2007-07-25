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

/*
 *	kx509 ASN.1 send/receive structures.
 *
 * these hold the parsed packet contents.
 */

typedef struct kx509_request {
	ASN1_OCTET_STRING *authenticator;
	ASN1_OCTET_STRING *hash;
	ASN1_OCTET_STRING *pkey;
} KX509_REQUEST;

typedef struct kx509_response {
	int status;
	ASN1_OCTET_STRING *hash;
	ASN1_OCTET_STRING *certificate;
	ASN1_PRINTABLESTRING *error_message;
} KX509_RESPONSE;

/* these are bogus error codes.  Yuck. */
#define ASN1_F_D2I_KX509_REQUEST 900
#define ASN1_F_D2I_KX509_RESPONSE 901
#define ASN1_F_D2I_KX509_REQUEST_NEW 902
#define ASN1_F_D2I_KX509_RESPONSE_NEW 903

/* routines to allocate, free, and parse, a la openssl */
KX509_REQUEST * KX509_REQUEST_new(void);

void KX509_REQUEST_free(KX509_REQUEST *);
KX509_RESPONSE *KX509_RESPONSE_new(void);
void KX509_RESPONSE_free(KX509_RESPONSE *);
int i2d_KX509_REQUEST(KX509_REQUEST *, unsigned char **);
int i2d_KX509_RESPONSE(KX509_RESPONSE *, unsigned char **);
KX509_REQUEST *d2i_KX509_REQUEST(KX509_REQUEST **,unsigned char **, long);
KX509_RESPONSE *d2i_KX509_RESPONSE(KX509_RESPONSE **,unsigned char **, long);

/* routines to compute key'd hash values based on a supplied session key */
int KX509_REQUEST_compute_checksum(unsigned char[], KX509_REQUEST *,ASN1_OCTET_STRING *,char *key, int);
int KX509_RESPONSE_compute_checksum(unsigned char[], KX509_RESPONSE *, ASN1_OCTET_STRING *, char *, int);

/* "#define" macros that were dropped as-of OpenSSL-0.9.6 -- billdo 2000.1205 */
#if SSLEAY_VERSION_NUMBER > 0x0090600e
# define        Malloc          OPENSSL_malloc
# define        Realloc         OPENSSL_realloc
# ifdef Free
#  undef	Free
# endif /* Free */
# define        Free(addr)      OPENSSL_free(addr)
#endif

