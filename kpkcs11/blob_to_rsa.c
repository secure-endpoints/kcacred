/*
 * Copyright (c) 1999
 * The Trustees of Columbia University in the City of New York.
 * All rights reserved.
 * 
 * Permission is granted to you to use, copy, create derivative works,
 * and redistribute this software and such derivative works for any
 * purpose, so long as the name of Columbia University is not used in any
 * advertising, publicity, or for any other purpose pertaining to the use
 * or distribution of this software, other than for including the
 * copyright notice set forth herein, without specific, written prior
 * authorization.  Columbia University reserves the rights to use, copy,
 * and distribute any such derivative works for any purposes.  The above
 * copyright notice must be included in any copy of any portion of this
 * software and the disclaimer below must also be included.
 * 
 *   THIS SOFTWARE IS PROVIDED AS IS, WITHOUT REPRESENTATION FROM THE
 *   TRUSTEES OF COLUMBIA UNIVERSITY IN THE CITY OF NEW YORK AS TO ITS
 *   FITNESS FOR ANY PURPOSE, AND WITHOUT WARRANTY BY THE TRUSTEES OF
 *   COLUMBIA UNIVERSITY IN THE CITY OF NEW YORK OF ANY KIND, EITHER
 *   EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION THE IMPLIED
 *   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *   THE TRUSTEES OF COLUMBIA UNIVERSITY IN THE CITY OF NEW YORK SHALL
 *   NOT BE LIABLE FOR ANY DAMAGES, INCLUDING SPECIAL, INDIRECT,
 *   INCIDENTAL, OR CONSEQUENTIAL DAMAGES, WITH RESPECT TO ANY CLAIM
 *   ARISING OUT OR IN CONNECTION WITH THE USE OF THE SOFTWARE, EVEN IF
 *   IT HAS BEEN OR IS HEREAFTER ADVISED OF THE POSSIBILITY OF SUCH
 *   DAMAGES.  YOU SHALL INDEMNIFY AND HOLD HARMLESS THE TRUSTEES OF
 *   COLUMBIA UNIVERSITY IN THE CITY OF NEW YORK, ITS EMPLOYEES AND
 *   AGENTS FROM AND AGAINST ANY AND ALL CLAIMS, DEMANDS, LOSS, DAMAGE OR
 *   EXPENSE (INCLUDING ATTORNEYS' FEES) ARISING OUT OF YOUR USE OF THIS
 *   SOFTWARE. 
 * 
 * The Trustees of Columbia University in the City of New York reserves
 * the right to revoke this permission if any of the terms of use set
 * forth above are breached.
 */ 

/*
 * Copyright  ©  2000
 * The Regents of the University of Michigan
 * ALL RIGHTS RESERVED
 *
 * permission is granted to use, copy, create derivative works 
 * and redistribute this software and such derivative works 
 * for any purpose, so long as the name of the university of 
 * michigan is not used in any advertising or publicity 
 * pertaining to the use or distribution of this software 
 * without specific, written prior authorization.  if the 
 * above copyright notice or any other identification of the 
 * university of michigan is included in any copy of any 
 * portion of this software, then the disclaimer below must 
 * also be included.
 *
 * this software is provided as is, without representation 
 * from the university of michigan as to its fitness for any 
 * purpose, and without warranty by the university of 
 * michigan of any kind, either express or implied, including 
 * without limitation the implied warranties of 
 * merchantability and fitness for a particular purpose. the 
 * regents of the university of michigan shall not be liable 
 * for any damages, including special, indirect, incidental, or 
 * consequential damages, with respect to any claim arising 
 * out of or in connection with the use of the software, even 
 * if it has been or is hereafter advised of the possibility of 
 * such damages.
 */

/*
 * Copyright  ©  2006
 * Secure Endpoints Inc.
 * ALL RIGHTS RESERVED
 *
 */

/*================================================================================
 *
 * Convert a Private key blob into an RSA Private Key structure
 *
 *================================================================================*/

#ifdef _WIN32
# include <tchar.h>
#else
# include "cki_types.h"
#endif /* WIN32 */

#include <stdio.h>

#ifdef _WIN32
# ifndef _WIN32_WINNT
# define  _WIN32_WINNT	0x0400	// Now needed to get WinCrypt.h
# endif
# include <windows.h>
#endif  /* WIN32 */

#include <openssl/x509v3.h>
#include "debug.h"
#include "blob_to_rsa.h"

void hexdump(void *pin, char *label, int len);

/*
	The Private Key Blob consists of the following:

	PUBLICKEYSTRUC		blobheader;
	RSAPUBKEY		rsapubkey;
	DWORD			beginning[1];
	BYTE			modulus[KEYBITS/8];		// "n"
	BYTE			prime1[KEYBITS/16];		// "p"
	BYTE			prime2[KEYBITS/16];		// "q"
	BYTE			exponent1[KEYBITS/16];		// "dmp1"
	BYTE			exponent2[KEYBITS/16];		// "dmq1"
	BYTE			coefficient[KEYBITS/16];	// "iqmp"
	BYTE			privateExponent[KEYBITS/8];	// "d"
*/

/*--------------------------------------------------------------------------
// This routine began life as the BN_bin2bn() routine
// from the OpenSSL/SSLeay code written by Eric A. Young.
// (I'm doing a memcpy instead of the reverse-byte thing
// that the original code (delimited with the #ifdef
// ORIGINAL_OPENSSL_CODE) does.
//
// This makes things happier
*/

/* ignore negative */
BIGNUM *BN_bin2bn_mangled(const unsigned char *s, int len, BIGNUM *ret)
{
#ifdef ORIGINAL_OPENSSL_CODE
    unsigned int i,m;
#endif
    unsigned int n;
    BN_ULONG l;
	
    if (ret == NULL) ret=BN_new();
    if (ret == NULL) return(NULL);
    l=0;
    n=len;
    if (n == 0)
    {
	ret->top=0;
	return(ret);
    }
    if (bn_expand(ret,(int)(n+2)*8) == NULL)
	return(NULL);

#ifdef ORIGINAL_OPENSSL_CODE
    i=((n-1)/BN_BYTES)+1;
    m=((n-1)%(BN_BYTES));
    ret->top=i;
    while (n-- > 0)
    {
	l=(l<<8L)| *(s++);
	if (m-- == 0)
	{
	    ret->d[--i]=l;
	    l=0;
	    m=BN_BYTES-1;
	}
    }
    /* need to call this due to clear byte at top if avoiding
     * having the top bit set (-ve number) */
    bn_fix_top(ret);
#else
    ret->top = ((n-1)/BN_BYTES)+1;
    memcpy(ret->d, s, len);
#endif

    return(ret);
}



#define MAX_UNIQNAME_LEN	8

int privkeyblob_to_rsa(char *pBlob, RSA **rsaret)
{
    RSA *rsa;
    char *bin_n, *bin_e, *bin_d, *bin_p, *bin_q, *bin_dmp1, *bin_dmq1, *bin_iqmp;
    DWORD keybits, keybitsdiv8, keybitsdiv16;

    RSAPUBKEY *pRSApubkey = (RSAPUBKEY *)(pBlob + sizeof(BLOBHEADER));

    /* Possibly do some sanity checks on the blob header, etc. */
    if(pBlob == NULL)
    {
	log_printf("privkeyblob_to_rsa: called with NULL blob pointer!\n");
	return -1;
    }

    if (!rsaret)
    {
	log_printf("privkeyblob_to_rsa: called with invalid return for RSA ptr\n");
	return -1;
    }

    /* Allocate an RSA structure */
    rsa = RSA_new();
    if (rsa == NULL)
    {
	log_printf("privkeyblob_to_rsa: could not allocate RSA structure\n");
	return -1;
    }

    /* Figure out how many bits the key is, from there we	*/
    /* can figure out how big each component is going to be	*/
    keybits = pRSApubkey->bitlen;
    keybitsdiv8 = keybits >> 3;
    keybitsdiv16 = keybits >> 4; 

    log_printf("privkeyblob_to_rsa: blob presented has a key with %d bits\n", keybits);

    /* Modulus (n) */
    bin_n = pBlob + sizeof(BLOBHEADER) + sizeof(RSAPUBKEY);
    rsa->n = BN_bin2bn_mangled(bin_n, keybitsdiv8, NULL);

    /* Prime1 (p) */
    bin_p = bin_n + keybitsdiv8;
    rsa->p = BN_bin2bn_mangled(bin_p, keybitsdiv16, NULL);

    /* Prime2 (q) */
    bin_q = bin_p + keybitsdiv16;
    rsa->q = BN_bin2bn_mangled(bin_q, keybitsdiv16, NULL);

    /* Exponent1 (dmp1) */
    bin_dmp1 = bin_q + keybitsdiv16;
    rsa->dmp1 = BN_bin2bn_mangled(bin_dmp1, keybitsdiv16, NULL);

    /* Exponent2 (dmq1) */
    bin_dmq1 = bin_dmp1 + keybitsdiv16;
    rsa->dmq1 = BN_bin2bn_mangled(bin_dmq1, keybitsdiv16, NULL);

    /* Coefficient (iqmp) */
    bin_iqmp = bin_dmq1 + keybitsdiv16;
    rsa->iqmp = BN_bin2bn_mangled(bin_iqmp, keybitsdiv16, NULL);

    /* Private Exponent (d) */
    bin_d = bin_iqmp + keybitsdiv16;
    rsa->d = BN_bin2bn_mangled(bin_d, keybitsdiv8, NULL);

    /* Public Exponent */
    bin_e = (char *) &(pRSApubkey->pubexp);
    rsa->e = BN_bin2bn_mangled(bin_e, sizeof(DWORD), NULL);

    /* print out our findings... */
    hexdump(bin_n,	"pk->modulus",			rsa->n->top);
    hexdump(bin_p,	"pk->prime1",			rsa->p->top);
    hexdump(bin_q,	"pk->prime2",			rsa->q->top);
    hexdump(bin_dmp1,	"pk->exponent1",		rsa->dmp1->top);
    hexdump(bin_dmq1,	"pk->exponent2",		rsa->dmq1->top);
    hexdump(bin_iqmp,	"pk->coefficient",		rsa->iqmp->top);
    hexdump(bin_d,	"pk->privateExponent",		rsa->d->top);

    *rsaret = rsa;

    return(0);
}
