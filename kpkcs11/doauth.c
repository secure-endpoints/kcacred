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
 * Copyright  ©  2000,2002
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

#include "config.h"
#include <stdio.h>
#include <stdlib.h>

#ifndef _WIN32
#  include <unistd.h>
#else
#  ifndef  _WIN32_WINNT
#  define  _WIN32_WINNT	0x0400	// Now needed to get WinCrypt.h ... ?!?!!
#  endif
#  include <windows.h>
#endif /* !WIN32 */

#ifndef macintosh
#  include <sys/types.h>
#endif /* !macintosh */

#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#if defined(macintosh)
#define USE_KRB5
#endif /* macintosh */

#ifndef WIN32
#  if defined(USE_KRB5)
#    include "krb5.h"
#  else /* !USE_KRB5 */
#    include <openssl/des.h>
#    if !defined(linux) && !defined(HPUX)	/* Actually KRB5 1.1 */
#      define DES_DEFS
#    endif /* !linux */
#    ifdef macintosh
#      include <KClient.h>
#    else /* !macintosh */
#      include "des-openssl-hack.h"
#      include <krb.h>
#    endif /* macintosh */
#  endif /* !USE_KRB5 */
#endif /* WIN32 */

#include <openssl/evp.h>
#include <openssl/buffer.h>

#include "pkcs11_types.h"
#include "cki_funcs.h"
#include "pkcs11_new_free.h"
#include "doauth.h"
#include "b64.h"
#include "debug.h"

#ifndef WIN32
#  include "store_tkt.h"
#  include <sys/stat.h>
#else
#  include "blob_to_rsa.h"
#endif

#ifdef macintosh
#  define KSUCCESS 0
#  define KFAILURE 255
#  define TKT_FILE "tktfile"
#  define R_TKT_FIL 0
#  define W_TKT_FIL 1
#  define MAX_K_NAME_SZ (ANAME_SZ + INST_SZ + REALM_SZ + 2)
#endif /* macintosh */

/* Forward reference prototypes */
int checkTokenValidity_W32();
int checkTokenValidity_KRB5();

char *getelt(struct a_t **alist, char *name) {
  int i;

  if (!alist) return(NULL);
  i=0;
  while (alist[i]) {
   if (!strcmp(alist[i]->name,name)) return(alist[i]->value);
   i++;
  }
  return(NULL);
}

#if defined(_WIN32)

/*----------------------------------------------------------------------*/
/* Define global context pointer.  We continually check to see if this  */
/* certificate is still the current one.  If not, we free it up and get */
/* the context for the new one.                                         */

PCCERT_CONTEXT		gpCertContext = NULL;

#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)

#define HandleError(x) \
{\
    log_printf("============  An error occurred ============\n"); \
    log_printf(x); \
    log_printf("Error number %x.\n", GetLastError()); \
    return(0); \
}

/* UnicodeStrToAnsi converts Unicode strings stored in certificate 
 * data structures to Ansi strings used in this module.
 */
int UnicodeStrToAnsi(char * dest, size_t cbdest, const wchar_t *src)
{
    size_t nc;

    if(cbdest == 0)
        return 0;

    dest[0] = 0;

    if((nc = wcslen(src) <= 0) || nc*sizeof(char) >= cbdest)
        // note that cbdest counts the terminating NULL, while nc doesn't
        return 0;

    nc = WideCharToMultiByte(
        CP_ACP,
        WC_NO_BEST_FIT_CHARS,
        src,
        (int) nc,
        dest,
        (int) cbdest,
        NULL,
        NULL);

    dest[nc] = 0;

    return (int) nc;
}


/*----------------------------------------------------------------------*/
/* Microsoft reserves this property id value, but it doesn't specify	*/
/* it.   We'll have to specify it ourself...				*/
/*									*/
#define UM_DESIRED_CERT_PROP_ID		32

/*----------------------------------------------------------------------*/
/* This structure is also not defined (or at least published).		*/
/* The second DWORD could also be a flag, but they all seem to		*/
/* be one in the stuff we've gotten back...				*/
/*									*/
typedef struct _property_header
{
    DWORD	propid;		/* Property ID (as defined in wincrypt.h) */
    DWORD	version;	/* This could also be a flag?		  */
    DWORD	length;		/* Length of the property data that	  */
                                /*    follows this structure		  */
} UM_PROPERTY_HEADER;

/*----------------------------------------------------------------------*/
/* This routine takes a pointer to the serialized output of		*/
/* a certificate storage and finds the Property that we are		*/
/* interested in (the subject's certificate itself)			*/
/* The serialized output area is not documented, but we			*/
/* can see the structure...						*/
/*----------------------------------------------------------------------*/

int locateCertPropertyFromSerializedOutput(void *pSerializedData, 
					   int totlen, char **ppCert, int *pLen)
{
    UM_PROPERTY_HEADER *pH;

    if (!ppCert)
	return(-2);
    if (!pLen)
	return(-2);

    pH = (UM_PROPERTY_HEADER *)pSerializedData;
    /* Keep looking until we've found the one we're looking		*/
    /* for, or we've gone past the end of the serialized data	*/
    while ( (char *)pH < ((char *)pSerializedData + totlen) )
    {
	if (pH->propid == UM_DESIRED_CERT_PROP_ID && pH->version == 1)
	{
	    *pLen = pH->length;
	    *ppCert = ((char *)pH + sizeof(UM_PROPERTY_HEADER));

	    *ppCert = (char*) malloc(*pLen);
	    if (!*ppCert)
		return -1;
	    memcpy(*ppCert, ((char *)pH + sizeof(UM_PROPERTY_HEADER)), *pLen);
	    return 0;
	}
	else
	{
	    pH = (UM_PROPERTY_HEADER*) ((char *)pH + pH->length + sizeof(UM_PROPERTY_HEADER));
	}
    }
    return(-1);
}

/*----------------------------------------------------------------------*/
/* This routine gets the Common Name attribute from a CERT_INFO		*/
/* structure.  It returns TRUE if successful, or FALSE otherwise.	*/
/*----------------------------------------------------------------------*/

BOOL getCommonNameFromCertContext(PCCERT_CONTEXT pCertContext, char **ppName, int*pNamelen)
{
    DWORD cbDecoded;		/* Length of decoded output */
    BYTE *pbDecoded = NULL;		/* Decoded output of subject name */
    PCERT_NAME_INFO pNameInfo;	/* Ptr to NAME_INFO structure */
    DWORD i;
    BOOL retval = FALSE;		/* Be a pessimist */
	
    if (pCertContext == NULL || ppName == NULL || pNamelen == NULL)
    {
	log_printf("getCommonNameFromCertContext: missing param (0x%08x 0x%08x 0x%08x)\n",
		    pCertContext, ppName, pNamelen);
	return retval;
    }
	
    /* First get the length needed for the decoded output */
    if (!CryptDecodeObject( MY_ENCODING_TYPE,	/* Encoding type */
		((LPCSTR) 7),	/* (X509_NAME) this definition from */
			                        /* wincrypt.h conflicts with a */
					        /* definition in OpenSSL ... */
		pCertContext->pCertInfo->Subject.pbData,	/* The thing to be decoded */
		pCertContext->pCertInfo->Subject.cbData,	/* Length of thing to be decoded */
		0,			    /* Flags */
		NULL,			/* Just getting req'd length */
		&cbDecoded))		/* where to return the length */
    {
	log_printf("getCommonNameFromCertContext: error (0x%08x) "
		    "getting length of decoded subject name\n", GetLastError());
	return retval;
    }
	
    /* Allocate the space for the decoded Subject data */
    if ( (pbDecoded = (BYTE*)malloc(cbDecoded)) == NULL )
    {
	log_printf("getCommonNameFromCertContext: Could not obtain %d bytes "
		    "for decoded subject.\n", cbDecoded);
	return retval;
    }
	
    /* Now, get the decoded subject output */
    if (!CryptDecodeObject( MY_ENCODING_TYPE,	/* Encoding type */
                ((LPCSTR) 7),		/* (X509_NAME) this definition from */
					/* wincrypt.h conflicts with a */
					/* definition in OpenSSL ... */
		pCertContext->pCertInfo->Subject.pbData,	/* The thing to be decoded */
		pCertContext->pCertInfo->Subject.cbData,	/* Length of thing to be decoded */
		0,			/* Flags */
		pbDecoded,		/* Return the decoded subject info */
		&cbDecoded))		/* and it's length */
    {
	log_printf("getCommonNameFromCertContext: error (0x%08x) decoding subject name\n",
		    GetLastError());
	free(pbDecoded);
	return retval;
    }

    pNameInfo = (PCERT_NAME_INFO)pbDecoded;

    /* Loop through all the RDN elements, looking for the Common Name */
    for (i = 0; i < pNameInfo->cRDN; i++)
    {
	log_printf("getCommonNameFromCertContext: RDN %d\tOID '%s'\tString '%s'\n",
		    i, pNameInfo->rgRDN[i].rgRDNAttr->pszObjId,
		    pNameInfo->rgRDN[i].rgRDNAttr->Value.pbData);
	if (!strcmp(pNameInfo->rgRDN[i].rgRDNAttr->pszObjId, szOID_COMMON_NAME))
	{
	    log_printf("getCommonNameFromCertContext: Found Common Name at index %d\n",
			i);
	    break;
	}
    }
	
    /* If we found the right RDN, get it's value into a string */
    if (i < pNameInfo->cRDN)
    {
	if (CertRDNValueToStr( CERT_RDN_PRINTABLE_STRING,
		&pNameInfo->rgRDN[i].rgRDNAttr->Value,
	        *ppName,
		*pNamelen) != 0)
	{
	    log_printf("getCommonNameFromCertContext: Certificate for %s has "
			"been retrieved.\n", *ppName);
	    retval = TRUE;	/* SUCCESS! */
	}
	else
	{
	    log_printf("getCommonNameFromCertContext: CertNameToStr failed "
			"(error 0x%08x).\n", GetLastError());
	}
    }
    else
    {
	log_printf("getCommonNameFromCertContext: Could not locate Common Name RDN value!\n");
    }
	
    if (pbDecoded)
	free(pbDecoded);

    return retval;
}

/*----------------------------------------------------------------------*/
/* Retrieve a certificate from the user's Root store that		*/
/* contains the KCA_AUTHREALM or a Kerberos Issuer OtherName extension. */
/*                                                                      */
/* If there is more than one KCA certificate, then this function returns*/
/* the first one found.  This needs to be re-written to return a list of*/
/* of certificates.                                                     */
/*----------------------------------------------------------------------*/

#define szOID_KCA_AUTHREALM		"1.3.6.1.4.1.250.42.1"
#define szOID_PKINIT_PRINCIPAL_NAME     "1.3.6.1.5.2.2"

static void ReleaseTokenObjects(PKCS11_TOKEN_PTR pToken)
{
    int i,j;

    /* Remove any old token objects not associated with a session */
    if (pToken->ppTokenObject!=NULL) {
	for (i =0; pToken->ppTokenObject[i]; i++) {
	    if (pToken->ppTokenObject[i]->ulSessionHandle == 0) {
		PKCS11_Object_Free(pToken->ppTokenObject[i]);
		pToken->ppTokenObject[i] = NULL_PTR;

		for ( j=i; pToken->ppTokenObject[j+1]; j++ ) {
		    pToken->ppTokenObject[j] = pToken->ppTokenObject[j+1];
		    pToken->ppTokenObject[j+1] = NULL_PTR;
		}
		i--;
	    }
	}	
    }
}

int win32_getCertAndKeyFromContext( PCCERT_CONTEXT pCertContext,
				    char	   **cert_der,
				    int		   *cert_len,
				    char	   **key_der,
				    int		   *key_len,
				    char	   *name,
				    int		   namelen
				    );

void LoadTokenObjects(PKCS11_TOKEN_PTR pToken)
{
    HCERTSTORE		hSystemStore;
    PCCERT_CONTEXT	pCertContext = NULL;
    PCCERT_CONTEXT	pPrevCertContext = NULL;
    CERT_INFO		*pCertInfo = NULL;
    DWORD		dwCertEncodingType = MY_ENCODING_TYPE;
    DWORD		dwFindFlags = 0;
    DWORD		dwFindType = CERT_FIND_ANY;
    PCERT_EXTENSION	pCertExt = NULL;
    CRYPT_OBJID_BLOB	*p = NULL;
    int			i = 0;
    BOOL		bFound = FALSE;
    char         	idname[256];
    char         	issuer[256];

    ReleaseTokenObjects(pToken);

    /*--------------------------------------------------------------*/
    /* Open system certificate store.				*/

    if (hSystemStore = CertOpenSystemStore(0, "MY"))
    {
	log_printf("getKCACertificate: MY system store is open. Continue.\n");
    }
    else
    {
	log_printf("getKCACertificate: The first system store did not open.");
	goto error;
    }

    while ( (pCertContext = CertFindCertificateInStore( /**/
	        hSystemStore,			/* Handle to the certificate store	*/
		dwCertEncodingType, 		/* Encoding type			*/
		dwFindFlags,			/* Flags				*/
		dwFindType, 			/* Says what the parameter must match	*/
		NULL,				/* in				 	*/
		pPrevCertContext)) != NULL) 	/* First time is null, after that it	*/
						/* should be the one we previously got	*/
    {
	CertGetNameString(pCertContext,
			   CERT_NAME_EMAIL_TYPE,
			   0, NULL, idname, sizeof(idname));

	CertGetNameString(pCertContext,
			   CERT_NAME_SIMPLE_DISPLAY_TYPE,
			   CERT_NAME_ISSUER_FLAG,
			   NULL,
			   issuer,
			   sizeof(issuer));
	
	log_printf("getKCACertificate: A certificate was found. Continue.\n");
        log_printf("     E : %s\n", idname);
        log_printf("     I : %s\n", issuer);

	if (pCertInfo = pCertContext->pCertInfo) {
	    char *cert_der = NULL;
	    char *key_der = NULL;
	    int cert_len;
	    int key_len;
	    RSA *rsa = NULL;
	    X509 *x509 = NULL;
	    char *subject_der = NULL;
	    X509_NAME *subject = NULL;
	    CK_CHAR_PTR pID = NULL;
	    int subject_len;
	    char *ptr;
	    char user[256]="";
	    CK_RV res = CKR_OK;

	    if (win32_getCertAndKeyFromContext(pCertContext, &cert_der, &cert_len,
						&key_der, &key_len, user, sizeof(user))) 
	    {
		ptr=cert_der;
		x509=NULL;
		d2i_X509(&x509,(unsigned char **)&ptr, cert_len);
		if (x509==NULL)
		{
		    log_printf("PKCS11_Init2_Session: Login here with null x\n");
		    res = CKR_FUNCTION_FAILED;
		    goto error2;
		}
   
		res = PKCS11_X509_to_X509Certificate(0L,x509,user,&pID);
		if (res) {
		    log_printf("PKCS11_X509_to_X509Certificate: Failed with 0x%0x\n", res);
		    res = CKR_FUNCTION_FAILED;
		    goto error2;
		}
		subject=X509_get_subject_name(x509);
		subject_len=i2d_X509_NAME(subject,NULL);
		subject_der=(char *)malloc(subject_len);
		if (!subject_der) {
		    res = CKR_HOST_MEMORY;
		    goto error2;
		}
		ptr=subject_der;
		i2d_X509_NAME(subject,(unsigned char **)&ptr);

		ptr=key_der;
		d2i_RSAPrivateKey(&rsa,(unsigned char **)&ptr,key_len);   
		res=PKCS11_RSA_to_RsaPrivateKey(0L,rsa,user,subject_der,subject_len,pID);
		res=PKCS11_RSA_to_RsaPublicKey(0L,rsa,user,subject_der,subject_len,pID);

	      error2:
		if (cert_der)
		    free(cert_der);
		if (key_der)
		    free(key_der);
		if (subject_der)
		    free(subject_der);
		if (rsa)
		    RSA_free(rsa);
		if (pID)
		    free(pID);
	    }
	}
	/*----------------------------------------------------------------------*/
	/* Set previous context to the current one so we don't loop forever	*/
	pPrevCertContext = pCertContext;
    }	/* while (cert) */

    /*------------------------------------------------------------------------------*/
    /* Close the system certificate store, we're done with it...			*/
    CertCloseStore(hSystemStore, 0);

error:
	;
}


PCCERT_CONTEXT getKCACertificate()
{
    HCERTSTORE		hSystemStore;
    PCCERT_CONTEXT	pCertContext = NULL;
    PCCERT_CONTEXT	pPrevCertContext = NULL;
    CERT_INFO		*pCertInfo = NULL;
    DWORD		dwCertEncodingType = MY_ENCODING_TYPE;
    DWORD		dwFindFlags = 0;
    DWORD		dwFindType = CERT_FIND_ANY;
    PCERT_EXTENSION	pCertExt = NULL;
    CRYPT_OBJID_BLOB	*p = NULL;
    int			i = 0;
    BOOL		bFound = FALSE;
    char           	strRealm[256];
    char         	idname[256];
    char         	issuer[256];

    /*--------------------------------------------------------------*/
    /* Open system certificate store.				*/

    if (hSystemStore = CertOpenSystemStore(0, "MY"))
    {
	log_printf("getKCACertificate: MY system store is open. Continue.\n");
    }
    else
    {
	HandleError("getKCACertificate: The first system store did not open.");
    }

    while ( (pCertContext = CertFindCertificateInStore( /**/
	        hSystemStore,			/* Handle to the certificate store	*/
		dwCertEncodingType, 		/* Encoding type			*/
		dwFindFlags,			/* Flags				*/
		dwFindType, 			/* Says what the parameter must match	*/
		NULL,				/* in				 	*/
		pPrevCertContext)) != NULL) 	/* First time is null, after that it	*/
						/* should be the one we previously got	*/
    {
	CertGetNameString(pCertContext,
			   CERT_NAME_EMAIL_TYPE,
			   0, NULL, idname, sizeof(idname));

	CertGetNameString(pCertContext,
			   CERT_NAME_SIMPLE_DISPLAY_TYPE,
			   CERT_NAME_ISSUER_FLAG,
			   NULL,
			   issuer,
			   sizeof(issuer));
	
	log_printf("getKCACertificate: A certificate was found. Continue.\n");
        log_printf("     E : %s\n", idname);
        log_printf("     I : %s\n", issuer);

	if (pCertInfo = pCertContext->pCertInfo) {
	    BOOL bGotRealm = FALSE, bGotIdentity = FALSE;

	    for (i = pCertInfo->cExtension; i; i--) {
		pCertExt = &pCertInfo->rgExtension[i-1];
		p = &pCertExt->Value;

		if (!strcmp(pCertExt->pszObjId, szOID_KCA_AUTHREALM))
		{
		    log_printf("getKCACertificate: Found KCA_AUTHREALM Extension\n");
		    
		    /* Should be able to pass pValue into the OpenSSL ASN.1 routine
		     * for proper processing once it is implemented.  Until then ...
		     */
		    if (p->pbData[4] == 4) {
			size_t len = (size_t) p->pbData[1];

			if (len > p->cbData) {
			    log_printf("  Malformed value! len=%d, buffersize=%d\n", len, p->cbData);
			    goto done_with_cert;
			}
		    
			memcpy(strRealm, &p->pbData[2], len);
			strRealm[len] ='\0';
			bGotRealm = TRUE;

			log_printf("getKCACertificate:   value is: '%s'\n", strRealm);
		    } else {
			log_printf("   Malformed value! type is %d\n", (int) p->pbData[0]);
			goto done_with_cert;
		    }
		} else if (!strcmp(pCertExt->pszObjId, szOID_ISSUER_ALT_NAME2) && !bGotRealm) {
		    DWORD  cbStructInfo = 0;
		    PCERT_ALT_NAME_INFO pAltNameInfo = NULL;
		    unsigned int j;

		    log_printf("Found ISSUER_ALT_NAME2 Extension\n");

		    if (CryptDecodeObjectEx(X509_ASN_ENCODING, szOID_ISSUER_ALT_NAME2, p->pbData, p->cbData,
					    CRYPT_DECODE_ALLOC_FLAG, NULL, &pAltNameInfo, &cbStructInfo)) {

			for ( j=0; j < pAltNameInfo->cAltEntry; j++ ) {
			    PCERT_ALT_NAME_ENTRY pAltEntry = pAltNameInfo->rgAltEntry;

			    if (pAltEntry->dwAltNameChoice == CERT_ALT_NAME_DNS_NAME) {
				/* Assume its a realm name */
				UnicodeStrToAnsi(strRealm, sizeof(strRealm), pAltEntry->pwszDNSName);
				bGotRealm = TRUE;
				break;
			    }
			}
			LocalFree(pAltNameInfo);
			pAltNameInfo = NULL;

                        log_printf("   value is: '%s'\n", strRealm);
		    }
		} else if (!strcmp(pCertExt->pszObjId, szOID_SUBJECT_ALT_NAME2)) {
		    DWORD  cbStructInfo = 0;
		    PCERT_ALT_NAME_INFO pAltNameInfo = NULL;
		    unsigned int j;

		    log_printf("Found SUBJECT_ALT_NAME2 Extension\n");

		    if (CryptDecodeObjectEx(X509_ASN_ENCODING, szOID_SUBJECT_ALT_NAME2, p->pbData, p->cbData,
                                            CRYPT_DECODE_ALLOC_FLAG, NULL, &pAltNameInfo, &cbStructInfo)) {

			for ( j=0; j < pAltNameInfo->cAltEntry; j++ ) {
			    PCERT_ALT_NAME_ENTRY pAltEntry = &pAltNameInfo->rgAltEntry[j];

			    if (pAltEntry->dwAltNameChoice == CERT_ALT_NAME_OTHER_NAME) {
				if ( !strcmp(pAltEntry->pOtherName->pszObjId, szOID_PKINIT_PRINCIPAL_NAME) ) {
				    PCRYPT_OBJID_BLOB pValue = &pAltEntry->pOtherName->Value;

				    /* Should be able to pass pValue into the OpenSSL ASN.1 routine for
				     * proper parsing; until we have it implemented ...
				     */
#if 0
				    PKINIT_KRB5_PRINCNAME * princname = NULL;
				    unsigned char * p = pValue->pbData;

				    princname = PKINIT_KRB5_PRINCNAME_new();
				    
				    princname = d2i_PKINIT_KRB5_PRINCNAME(princname, &p, pValue->cbData);
				    bGotIdentity = TRUE;	
#endif
				}
			    }
			}
			LocalFree(pAltNameInfo);
			pAltNameInfo = NULL;

                        log_printf("   value is: '%s'\n", idname);
		    }
		}

		if (bGotRealm) {
		    bFound = TRUE;
		    break;
		}
	    }	/* while (extension) */

	    if (bFound) {
		log_printf("KCA certificate selected\n");
		break;
	    }
	}
    
      done_with_cert:
	/*----------------------------------------------------------------------*/
	/* Set previous context to the current one so we don't loop forever	*/
	pPrevCertContext = pCertContext;
    }	/* while (cert) */

    /*------------------------------------------------------------------------------*/
    /* Close the system certificate store, we're done with it...			*/
    CertCloseStore(hSystemStore, 0);

    log_printf("pCertContext = 0x%p\n", pCertContext);
    return pCertContext;
}

/********************************************************************************
 *
 * os_getCertAndKey for WIN32
 *
 * On WIN32, cert and key are accessed via CryptoAPI
 *                    not from KerberosIV Ticket File
 *                    nor from KerberosV  Cred Cache
 * 
 * non-zero on success
 *
 ********************************************************************************/
int win32_getCertAndKeyFromContext( PCCERT_CONTEXT pCertContext,
				    char	   **cert_der,
				    int		   *cert_len,
				    char	   **key_der,
				    int		   *key_len,
				    char	   *name,
				    int		   namelen
				    )				     

{
    CERT_INFO		*pCertInfo = NULL;
    BYTE*		pbElement = NULL;
    DWORD		cbElement;
    HCRYPTPROV		hCryptProvider = 0L;
    BOOL 		fCallerFreeProv = FALSE;
    DWORD		whichKey;
    HCRYPTKEY		hXchgKey = 0L;
    DWORD		dwBlobLen;
    BYTE		*pbKeyBlob = NULL;	/* Pointer to a simple key blob */
    char		*pChar = NULL;
    RSA 		*pRSA = NULL;

    if (cert_der == NULL || key_der == NULL || cert_len == NULL ||
	key_len == NULL || name == NULL)
	return 0;

    *cert_der = NULL;
    *key_der  = NULL;

    /*----------------------------------------------------------------------*/
    /* obtain the handle to the private key associated with the certificate */
    /* if we can't acquire the handle, there is no point doing any of the   */
    /* rest of the work.
    /*----------------------------------------------------------------------*/

    if (!CryptAcquireCertificatePrivateKey( pCertContext,
					    CRYPT_ACQUIRE_COMPARE_KEY_FLAG | CRYPT_ACQUIRE_SILENT_FLAG,
					    NULL,
					    &hCryptProvider,		/* Handle to the CSP		*/
					    &whichKey,
					    &fCallerFreeProv
					    ))
    {
	log_printf("win32_getCertAndKey: initial CryptAcquireCertificatePrivateKey returned 0x%8X\n", 
		    GetLastError());

	/*--------------------------------------------------------------*/
	/* User's container should have been created in kx509!		*/
	log_printf("Unable to get CSP handle -- key not exportable?\n");
	goto error;
    }
	
    /*----------------------------------------------------------------------*/
    /* Obtain the common name from the certificate				*/

    if (getCommonNameFromCertContext(pCertContext, &name, &namelen))
    {
	log_printf("win32_getCertAndKey: Certificate for %s has been retrieved.\n", name);
    }
    else
    {
	log_printf("win32_getCertAndKey: getCommonNameFromCertContext failed. \n");
    }

    /*----------------------------------------------------------------------*/
    /* Find out how much memory to allocate for the serialized element.	*/

    if (CertSerializeCertificateStoreElement( pCertContext,	/* The existing certificate.		*/
					     0,			/* Accept default for dwFlags, 		*/
					     NULL,		/* NULL for the first function call.	*/
					     &cbElement))	/* Address where the length of the 	*/
	                                                        /* serialized element will be placed.	*/
    {
	log_printf("win32_getCertAndKey: The length of the serialized string is %d.\n",cbElement);
    }
    else
    {
	log_printf("Finding the length of the serialized element failed.\n");
	goto error;
    }
    /*----------------------------------------------------------------------*/
    /* Allocate memory for the serialized element.				*/
	
    if (pbElement = (BYTE*)malloc(cbElement))
    {
	log_printf("win32_getCertAndKey: Memory has been allocated. Continue.\n");
    }
    else
    {
	log_printf("The allocation of memory failed.\n");
	goto error;
    }
    /*----------------------------------------------------------------------*/
    /* Create the serialized element from a certificate context.		*/

    if (CertSerializeCertificateStoreElement( pCertContext,	/* The certificate context source for	*/
					                        /*    the serialized element.		*/
					     0,			/* dwFlags. Accept the default.		*/
					     pbElement,		/* A pointer to where the new element	*/
					                        /*    will be stored.			*/
					     &cbElement))	/* The length of the serialized element,*/
    {
	log_printf("win32_getCertAndKey: The encoded element has been serialized. \n");
    }
    else
    {
	log_printf("The element could not be serialized.\n");
	goto error;
    }

    /* retrieve the DER encoded certificate part */
    if (locateCertPropertyFromSerializedOutput(pbElement, cbElement, cert_der, cert_len))
    {
	log_printf("win32_getCertAndKey: could not find proper property in serialized certificate data\n");
	goto error;
    }

    log_printf("win32_getCertAndKey: cert_len=%0d\n", *cert_len);
	
    /*----------------------------------------------------------------------*/
    /* Now get a HANDLE to the key itself					*/
    if (CryptGetUserKey( hCryptProvider,
			whichKey,
			&hXchgKey))
    {
	log_printf("win32_getCertAndKey: The key exchange key has been acquired. \n");
    }
    else
    {
	log_printf("Error during CryptGetUserKey exchange key.\n");
	goto error;
    }
	
	
    /*----------------------------------------------------------------------*/
    /* Now try to export the key...						*/
    /* Determine the size of the key blob and allocate memory.		*/

    if (CryptExportKey( hXchgKey,	/* Handle of the key we want to export 	*/
		       (HCRYPTKEY)NULL,	/* Session key used to encrypt the blob	*/
					/* We don't want it encrypted...	*/
		       PRIVATEKEYBLOB, 	/* We want the whole thing		*/
					/*   (public/private key pair)		*/
		       0,		/* Flags				*/
		       NULL,		/* We're just getting the length	*/
					/*    right now				*/
		       &dwBlobLen))	/* The returned length			*/
    {
	log_printf("win32_getCertAndKey: Size of the blob for the session key determined. \n");
    }
    else
    {
	log_printf("Error computing blob length.\n");
	goto error;
    }

    if (pbKeyBlob = (BYTE*)malloc(dwBlobLen)) 
    {
	log_printf("win32_getCertAndKey: Memory has been allocated for the blob. \n");
    }
    else
    {
	log_printf("Out of memory. \n");
	goto error;
    }

    /*----------------------------------------------------------------------*/
    /* Export the key into a Private Key Blob.				*/

    if (CryptExportKey( hXchgKey,	/* Handle of the key we want to export	*/
		       (HCRYPTKEY)NULL,	/* Session key used to encrypt the blob	*/
					/* We don't want it encrypted... 	*/
		       PRIVATEKEYBLOB, 	/* We want the whole thing		*/
					/*    (public/private key pair)		*/
		       0,		/* Flags				*/
		       pbKeyBlob,	/* Where to return the key blob 	*/
		       &dwBlobLen))	/* The returned length			*/
    {
	log_printf("win32_getCertAndKey: Contents have been written to the blob. \n");
    }
    else
    {
	log_printf("Error during CryptExportKey.\n");
	goto error;
    }
		
    log_printf("win32_getCertAndKey: We now have the serialized certificate and the Private Key Blob\n");

    /*------------------------------------------------------------------------------*/
    /* Convert the blob returned into an RSA structure				*/
    if (privkeyblob_to_rsa(pbKeyBlob, &pRSA))
    {
	log_printf("Failed converting keyblob into an RSA structure\n");
	goto error;
    }

    /* now convert key from RSA structure to DER to nice b64 format */

    *key_len = i2d_RSAPrivateKey(pRSA, NULL);
    if (!*key_len)
    {
	log_printf("win32_getCertAndKey: error determining length for private key to DER conversion\n");
	log_printf("error determining length for private key to DER conversion\n");
	goto error;
    }

    *key_der = (char *) malloc(sizeof(char) * *key_len);
    if (!*key_der)
    {
	log_printf("win32_getCertAndKey: error allocating storage for private key to DER conversion\n");
	log_printf("error allocating storage for private key to DER conversion\n");
	goto error;
    }
	
    pChar = *key_der;
    if (i2d_RSAPrivateKey(pRSA, &pChar) == 0)
    {
	log_printf("win32_getCertAndKey: error converting private key to DER format\n");
	log_printf("error converting private key to DER format\n");
	goto error;
    }

    if (pRSA)
	RSA_free(pRSA);
    if (pbElement)
	free(pbElement);
    if (pbKeyBlob)
	free(pbKeyBlob);
    if (hXchgKey)
	CryptDestroyKey(hXchgKey);
    if (fCallerFreeProv && hCryptProvider)
	CryptReleaseContext(hCryptProvider, 0);

    log_printf("win32_getCertAndKey: key_len=%0d\n", *key_len);
    return 1;

  error:
    if (pbElement)
	free(pbElement);
    if (pbKeyBlob)
	free(pbKeyBlob);
    if (*key_der) {
	free(*key_der);
	*key_der = NULL;
    }
    if (*cert_der) {
	free(*cert_der);
	*cert_der = NULL;
    }
    if (pRSA)
	RSA_free(pRSA);
    if (hXchgKey)
	CryptDestroyKey(hXchgKey);
    if (fCallerFreeProv && hCryptProvider)
	CryptReleaseContext(hCryptProvider, 0);

    return 0;
}	


int os_getCertAndKey( char			**cert_der,
		      int			*cert_len,
		      char			**key_der,
		      int			*key_len,
		      char			*name,
		      int			namelen
		      )
{
    if (name == NULL)
    {
	log_printf("os_getCertAndKey: name pointer is NULL\n");
	return(0);
    }
    strncpy(name, "fudge", namelen);

    /*----------------------------------------------------------------------*/
    /* Get the KCA-issued certificate, if any.				    */

    if ( (gpCertContext = getKCACertificate()) == NULL)
    {
	HandleError("os_getCertAndKey: Could not find KCA-issued certificate!");
    }

    return win32_getCertAndKeyFromContext(gpCertContext, cert_der, cert_len, 
				key_der, key_len, name, namelen);
}
#else	/* WIN32 */

#if defined(USE_KRB5)

/********************************************************************************
 *
 * os_getCertAndKey for KRB5 (Unix and/or Macintosh)
 *
 ********************************************************************************/

#define KX509_CC_PRINCIPAL  "kx509"
#define KX509_CC_INSTANCE   "certificate"

int os_getCertAndKey(
	char			**cert_der,
	int			*cert_len,
	char			**key_der,
	int			*key_len,
	char			*name,
	int			namelen
)

{
	krb5_context	k5_context;
	krb5_ccache	cc;
	krb5_error_code	k5_rc = 0;
	krb5_creds	match_creds;
	krb5_creds	creds;
	int		retrieve_flags = (KRB5_TC_MATCH_SRV_NAMEONLY);

	X509		*x509 = NULL;
	unsigned char	*data;
	char		subject[BUFSIZ];
	char		*cn;
	struct stat	statbuf;

	memset(&match_creds, '\0', sizeof(match_creds));

	log_printf("Trying to init_context\n");
	
	if ((k5_rc = krb5_init_context(&k5_context)))
	{
		log_printf("os_getCertAndKey: %s initializing K5 context, "
			"check configuration.\n", error_message(k5_rc));
		return 0;
	}

	log_printf("Trying to find default CC\n");
	
	if ((k5_rc = krb5_cc_default(k5_context, &cc)))
	{
		log_printf("os_getCertAndKey: %s resolving default credentials cache.\n",
			error_message(k5_rc));
		return 0;
	}

	log_printf("Trying to get credentials\n");
	
	if ((k5_rc = krb5_cc_get_principal(k5_context, cc, &match_creds.client)))
	{
		log_printf("os_getCertAndKey: %s retreiving primary principal from "
			"credentials cache.\n", error_message(k5_rc));
		return 0;
	}

	if ((k5_rc = krb5_sname_to_principal(k5_context, KX509_CC_INSTANCE,
						KX509_CC_PRINCIPAL, KRB5_NT_UNKNOWN,
						&match_creds.server)))
	{
		log_printf("os_getCertAndKey: %s creating principal structure for "
				"server principal\n", error_message(k5_rc));
		return 0;
	}

	if ((k5_rc = krb5_cc_retrieve_cred(k5_context, cc, retrieve_flags, &match_creds, &creds)))
	{
		log_printf("os_getCertAndKey: %s finding the credentials containing the "
			"private key and certificate in the credentials cache.\n",
			error_message(k5_rc));
		return 0;
	}

	/*
	 * Note, that while 'creds' is local stack storage, the things that it
	 * now points to are not.  So passing these addresses back is not a
	 * problem as long as we don't free that data before returning...
	 */
	strncpy(name, krb5_princ_name(k5_context, creds.client)->data, namelen);

	log_printf("os_getCertAndKey: K5 name has been assigned with '%s'\n", name);
	*key_der = creds.ticket.data;
	*key_len = creds.ticket.length;
	*cert_der = creds.second_ticket.data;
	*cert_len = creds.second_ticket.length;


	/* 
	 * Attempt to get the Common Name from the certificate.
	 * First we try to obtain an X509 structure from the
	 * DER format certificate that we have.
	 * Then we get the Subject Name from the X509 and
	 * parse that to get the Common Name.
	 *
	 * Note that 'name' has already been filled in above
	 * with the uniqname; so if we fail, the uniqname
	 * is returned...
	 */

	data = (unsigned char *)creds.second_ticket.data;

	x509 = d2i_X509(NULL, &data, creds.second_ticket.length);
	if (x509 != NULL)
	{
		X509_NAME_oneline(X509_get_subject_name(x509), subject, BUFSIZ);
		log_printf("os_getCertAndKey: The certificate subject name is '%s' (0x%08x)\n",
	          subject, &subject);
		cn = strtok(subject, "/");
		while (cn && strncmp(cn, "CN=", 3))
		{
			log_printf("os_getCertAndKey: Checking token '%s' (0x%08x)\n", cn, cn);
			cn = strtok(NULL, "/");
		}
		if (cn)
		{
			log_printf("os_getCertAndKey: Found Common Name '%s'\n", cn+3);
			strncpy(name, cn+3, namelen);
		}
		else
		{
			log_printf("os_getCertAndKey: Unable to parse common name from subject name\n");
		}
	}
	else
	{
		log_printf("os_getCertAndKey: d2i_X509 failed!\n");
	}
	X509_free(x509);

	return 1;
}
#else /* !KRB5 && !WIN32 */
#error No implementation for getKCACertificate
#endif /* KRB5 */
#endif /* WIN32 */


struct a_t **getCertAndKey(struct a_t **tattrl, char *name, int namelen)
{
    struct a_t	**attrl=NULL;

    int		cert_length = 0;
    char	*cert_der = NULL;
    char	*cert_enc = NULL;
    int		key_length =0;
    char	*key_der = NULL;
    char	*key_enc = NULL;
    int i;

    log_printf("getCertAndKey: entered\n");

    if (!os_getCertAndKey(&cert_der, &cert_length,
			   &key_der,	&key_length,
			   name, namelen))
    {	
	log_printf("getCertAndKey: os_getCertAndKey failed\n"); 
	goto error;
    }

    cert_enc=(char *)malloc(sizeof(char)*(cert_length+1)*2);
    if (!cert_enc) { 
	log_printf("getCertAndKey: out of memory\n"); 
	goto error;
    }     
    b64_encode(cert_der,cert_length,cert_enc);

    log_printf("getCertAndKey: cert_length=%0d\n", cert_length);
    log_printf("getCertAndKey: cert_enc='%s'\n", cert_enc);

    /* now convert key from internal format to DER to nice b64 format */

    log_printf("getCertAndKey: 4\n");
    key_enc=(char *)malloc(sizeof(char)*(key_length+1)*2);
    if (!key_enc) {
	log_printf("getCertAndKey: out of memory\n");
	goto error;
    }     
    b64_encode(key_der,key_length,key_enc);

    log_printf("getCertAndKey: key_length=%0d\n", key_length);
    log_printf("getCertAndKey: key_enc='%s'\n", key_enc);

    log_printf("getCertAndKey: 5\n");

    /* make an attr list */
    attrl=(struct a_t **)malloc(sizeof(struct a_t *)*3);
   
    log_printf("getCertAndKey: 6\n");
    if (!attrl) 
    	goto error;
    memset(attrl, 0, sizeof(struct a_t *)*3);

    (attrl)[0]=(struct a_t *)malloc(sizeof(struct a_t));
    log_printf("getCertAndKey: 7\n");
    if (! (attrl)[0]) {
    	goto error;
    }
    (attrl)[1]=(struct a_t *)malloc(sizeof(struct a_t));
    log_printf("getCertAndKey: 8\n");
    if (! (attrl)[1]) {
	goto error;
    }
    log_printf("getCertAndKey: 9\n");
    (attrl)[0]->name=_strdup("cert");
    (attrl)[0]->value=cert_enc;
    (attrl)[1]->name=_strdup("key");
    (attrl)[1]->value=key_enc;

    log_printf("getCertAndKey: leaving\n");
    return(attrl);

  error:
    if (attrl) {
	for (i=0;attrl[i];i++) {
	    if (attrl[i])
		free(attrl[i]);
	}
	free(attrl);
    }
    if (key_enc)
	free(key_enc);
    if (cert_enc)
	free(cert_enc);

    return NULL;
}


int doauth(struct a_t ***attrl, struct a_t ***tattrl)
{
    char user[MAXSTRLEN]="";
    int i;

    log_printf("doauth: entered\n");

    *attrl=NULL;
    *tattrl=NULL;

    *tattrl=(struct a_t **)malloc(sizeof(struct a_t *)*3);
    if (!*tattrl) goto error;
    memset(*tattrl, 0, sizeof(struct a_t *)*3);

    *attrl=getCertAndKey(*tattrl, user, sizeof(user)); 
    if (!*attrl) {
	log_printf("doauth: doauth 9, couldn't do cert/key\n");
	goto error;
    }

    log_printf("doauth: user name is '%s'\n", user);

    (*tattrl)[0]=(struct a_t *)malloc(sizeof(struct a_t));
    if (! (*tattrl)[0]) goto error;

    (*tattrl)[1]=(struct a_t *)malloc(sizeof(struct a_t));
    if (! (*tattrl)[1]) goto error;

    (*tattrl)[0]->name=_strdup("user");
    (*tattrl)[0]->value=_strdup(user);
    (*tattrl)[1]->name=_strdup("password");
    (*tattrl)[1]->value=_strdup("");

    log_printf("doauth: success\n");
    return(0);	/* success */

  error:
    if (*attrl) {
	for (i=0;(*attrl)[i];i++) {
	    if ((*attrl)[i]->name)
		free((*attrl)[i]->name);
	    if ((*attrl)[i]->value)
		free((*attrl)[i]->value);
	    free((*attrl)[i]);
	}
	free(*attrl);
	*attrl = NULL;
    }
    if (*tattrl) {
	if ((*tattrl)[1])
	    free((*tattrl)[1]);
	if ((*tattrl)[0])
	    free((*tattrl)[0]);
	free(*tattrl);
	*tattrl = NULL;
    }	
    return(-1);
}

/*
 * checkTokenValidity
 *    return codes:
 *      0  there are no kx509 credentials available
 *     -1  creds are available, but have changed
 *      1  there are creds available
 *
 * Call the correct routine for our situation...
 *
 * Thanks to Simon Wilkinson <simon@sxw.org.uk>
 * for the original version of this code to better
 * handle re-acquiring certificates after one has
 * expired.
 */

int checkTokenValidity()
{
#if defined(_WIN32)
	return checkTokenValidity_W32();
#endif
#if defined(USE_KRB5)
	return checkTokenValidity_KRB5();
#endif
}

#if defined(_WIN32)

int checkTokenValidity_W32()
{
	/*
	 *  1) Get the certificate out of the store (Make it a subroutine???)
	 *  2) Check if it is the same one (if we already have one)
	 */
	PCCERT_CONTEXT		pCertContext = NULL;
	static CERT_INFO	info;
	static int		last_result = 0;

	/*----------------------------------------------------------------------*/
	/* Get the KCA-issued certificate					*/

	if ( (pCertContext = getKCACertificate()) == NULL)
	{
		log_printf("checkTokenValidity_W32: Could not find KCA-issued certificate!\n");
		return (last_result = 0);
	}

	//--------------------------------------------------------------------
	// Compare the pCertInfo members of this certificate with the
	// global version to determine whether they are identical.

	if( gpCertContext && 
	    CertCompareCertificate(
				MY_ENCODING_TYPE,
				pCertContext->pCertInfo,
				gpCertContext->pCertInfo))
	{
	     log_printf("checkTokenValidity_32: The two certificates are identical. \n");
	     return (last_result = 1);
	}
	else
	{
	     log_printf("checkTokenValidity_32: The two certificates are not identical. \n");
	     last_result = 1;
	     return -1;
	}

	return 1;
}

#endif

#if defined(USE_KRB5)

int checkTokenValidity_KRB5()
{
	struct stat	statbuf;
	krb5_context	k5_context;
	krb5_ccache	cc;
	krb5_creds	match_creds, creds;
	krb5_error_code	k5_rc;

	static int	last_result = 0;
	static time_t	cc_modtime;
	static char	*cc_name = NULL;

	log_printf("entering checkTokenValidity_KRB5\n");
	memset(&match_creds, '\0', sizeof(match_creds));

#ifndef DARWIN
	/* KfM doesn't use a file.  drh 20021024 */
	/* If we don't already know the Credentials Cache name, determine it now */
	if (cc_name == NULL) {
		krb5_init_context(&k5_context);
		krb5_cc_default(k5_context, &cc);
		cc_name = (char *)krb5_cc_get_name(k5_context, cc);
		log_printf("checkTokenValidity_KRB5: cc_name is %s\n",cc_name);

		krb5_free_context(k5_context);
	
		if (cc_name == NULL) {
			log_printf("checkTokenValidity_KRB5: krb5_cc_get_name failed\n");
			return 0;
		}
	}
	
	/* Is the Credentials Cache there? */
	log_printf("checkTokenValidity_KRB5: trying stat\n");
	if (stat(cc_name, &statbuf)) {
		log_printf("checkTokenValidity_KRB5: Stat of %s failed\n",cc_name);
		return(last_result = 0);
	}

	/*
	 * Has it been altered since last we checked? If not, we say whatever we
	 * said last time.
	 */
    
	log_printf("File time is %d our time is %d\n", statbuf.st_mtime, cc_modtime);
   
	if (statbuf.st_mtime == cc_modtime) {
		log_printf("checkTokenValidity_KRB5: Nothing's changed since last time\n");
		return(last_result);
	}

	cc_modtime = statbuf.st_mtime;

#endif /* DARWIN */

	/*
	 * The ccache is present, and has been updated since we last
	 * looked. Check to see if there's a kx509 principal in it
	 * (Not much error reporting here - see the doauth code for
	 * some, if you _really_ want)
	 */

	if ((k5_rc = krb5_init_context(&k5_context))) {
		log_printf("checkTokenValidity_KRB5: %s getting krb5_init_context\n",
			error_message(k5_rc));
		return(last_result = 0);
	}

	if ((k5_rc = krb5_cc_default(k5_context, &cc))) {
		log_printf("checkTokenValidity_KRB5: %s getting krb5_cc_default\n",
			error_message(k5_rc));
		return(last_result = 0);
	}

	if ((k5_rc = krb5_cc_get_principal(k5_context, cc, &match_creds.client))) {
		log_printf("checkTokenValidity_KRB5: %s from krb5_cc_get_principal\n",
			error_message(k5_rc));  
		return(last_result = 0);
	}
       
	if ((k5_rc = krb5_sname_to_principal(k5_context, KX509_CC_INSTANCE,
  					 KX509_CC_PRINCIPAL, KRB5_NT_UNKNOWN,
  					 &match_creds.server))) {
		log_printf("checkTokenValidity_KRB5: %s from krb5_sname_to_principal\n",
			error_message(k5_rc));
		return(last_result = 0);
	}

	if ((k5_rc = krb5_cc_retrieve_cred(k5_context, cc, KRB5_TC_MATCH_SRV_NAMEONLY, 
  				    &match_creds, &creds))) {
		/* Not there _sniff_ */
		krb5_free_cred_contents(k5_context, &match_creds);
		log_printf("checkTokenValidity_KRB5: %s from krb5_cc_retrieve_cred\n",
			error_message(k5_rc));
		return(last_result = 0);
	}

#ifdef DARWIN
	/* However, this should work for all platforms. drh 20021024 */

	/*
	 * Has it been altered since last we checked? If not, we say whatever we
	 * said last time.
	 */
    
	log_printf("Creds endtime is %d our time is %d\n", creds.times.endtime, cc_modtime);
   
	if (creds.times.endtime == cc_modtime) {
		log_printf("checkTokenValidity_KRB5: Nothing's changed since last time\n");
		krb5_free_cred_contents(k5_context, &match_creds);
		krb5_free_cred_contents(k5_context, &creds);
		return(last_result);
	}

	cc_modtime = creds.times.endtime;

#endif /* DARWIN */

	krb5_free_cred_contents(k5_context, &match_creds);
	krb5_free_cred_contents(k5_context, &creds);

	/*
	 * This sucks, because the doauth code will just do all the
	 * above again when the session is opened. Ho hum
	 */

	/*
	 * We tell them that the creds are there, but that they have
	 * changed (future calls will just get that they are there
	 */

	last_result = 1;
	log_printf("checkTokenValidity_KRB5: Drop through reached, creds changed\n");
	return -1;
}

#endif

