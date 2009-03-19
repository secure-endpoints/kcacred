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

#include <tchar.h>
#include <stdio.h>

#include <winsock.h>
#include <windows.h>
#include "debug.h" 

#include "credprov.h"
#include "kca_asn.h"

#include <assert.h>

#include <strsafe.h>

PCCERT_CONTEXT
find_matching_cert(HCERTSTORE hStoreHandle,
                   khm_handle cred) {
    CERT_ID certId;
    PCCERT_CONTEXT pCertContext = NULL;
    BYTE    serial[1024];
    BYTE    issuer[1024];
    khm_size cb;

    ZeroMemory(&certId, sizeof(certId));

    cb = sizeof(serial);
    if (KHM_FAILED(kcdb_cred_get_attr(cred,
                                      attr_id_serial_number,
                                      NULL, serial, &cb))) {
        return NULL;
    }

    certId.IssuerSerialNumber.SerialNumber.cbData = (DWORD)cb;
    certId.IssuerSerialNumber.SerialNumber.pbData = serial;

    cb = sizeof(issuer);
    if (KHM_FAILED(kcdb_cred_get_attr(cred,
                                      attr_id_issuer_name,
                                      NULL, issuer, &cb))) {
        return NULL;
    }

    certId.IssuerSerialNumber.Issuer.cbData = (DWORD)cb;
    certId.IssuerSerialNumber.Issuer.pbData = issuer;

    certId.dwIdChoice = CERT_ID_ISSUER_SERIAL_NUMBER;

    pCertContext = CertFindCertificateInStore(hStoreHandle,
                                              X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                              0,
                                              CERT_FIND_CERT_ID,
                                              &certId,
                                              NULL);

    return pCertContext;
}

/* from plugins/krb5/krb5funcs.c */
wchar_t * 
khm_get_realm_from_princ(wchar_t * princ) {
    wchar_t * t;

    if(!princ)
        return NULL;

    for (t = princ; *t; t++) {
        if(*t == L'\\') {       /* escape */
            t++;
            if(! *t)            /* malformed */
                break;
        } else if (*t == L'@')
            break;
    }

    if (*t == '@' && *(t+1) != L'\0')
        return (t+1);
    else
        return NULL;
}


void kca_list_creds(void) {
    HCERTSTORE     hStoreHandle;
    PCCERT_CONTEXT pCertContext = NULL;
    PCCERT_CONTEXT prev_pCertContext = NULL;
    DWORD          dwCertEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    DWORD          dwFindFlags = 0;
    DWORD          dwFindType = CERT_FIND_ANY;
    CERT_INFO      *pCertInfo = NULL;
    PCERT_EXTENSION pCertExt = NULL;
    CRYPT_OBJID_BLOB *p = NULL;
    int            i = 0;
    char           strRealm[256];
    wchar_t        widname[256];
    wchar_t        wemail[256];
    wchar_t        wissuer[256];
    wchar_t        wbuffer[256];
    wchar_t        certstore_name[128];
    wchar_t *      realm;
    khm_handle     cred;
    khm_handle     ident;

    if (!(hStoreHandle = CertOpenSystemStore(0, WIN32MYCERT_STORE))) {
        HandleError("Unable to access the system certificate store");
        return;
    }

    LoadString(hResModule, IDS_LOC_MYSTORE,
               certstore_name, ARRAYLENGTH(certstore_name));

    log_printf("Listing KCA certs ----");

    kcdb_credset_flush(g_credset);

    while ((pCertContext = CertFindCertificateInStore(hStoreHandle,
                                                      dwCertEncodingType,
                                                      dwFindFlags,
                                                      dwFindType,
                                                      NULL,
                                                      prev_pCertContext
                                                      ))) {

        /* debug stuff */
        CertGetNameString(pCertContext,
                          CERT_NAME_EMAIL_TYPE,
                          0, NULL, widname, ARRAYLENGTH(widname));

        CertGetNameString(pCertContext,
                          CERT_NAME_SIMPLE_DISPLAY_TYPE,
                          CERT_NAME_ISSUER_FLAG,
                          NULL,
                          wissuer,
                          ARRAYLENGTH(wissuer));

        log_printf("Found certificate...");
        log_printf("     E : %S", widname);
        log_printf("     I : %S", wissuer);

        if (pCertInfo = pCertContext->pCertInfo) {
	    BOOL bGotRealm = FALSE, bGotIdentity = FALSE;

	    ident = NULL;
	    cred = NULL;

	    for (i = pCertInfo->cExtension; i; i--) {
                pCertExt = &pCertInfo->rgExtension[i-1];
		p = &pCertExt->Value;
		if (!strcmp(pCertExt->pszObjId, szOID_KCA_AUTHREALM)) {
		    log_printf("Found KCA_AUTHREALM Extension");

		    /* Should be able to pass pValue into the OpenSSL ASN.1 routine for
 		     * proper parsing, until we have it implemented ...
		     */
		    if (p->pbData[0] == 4) {
			khm_size len;

			len = (khm_size) p->pbData[1];

			if (len > p->cbData) {
			    log_printf("  Malformed value! len=%d, buffersize=%d", len, p->cbData);
			    goto done_with_cert;
			}

			memcpy(strRealm, &p->pbData[2], len);
			strRealm[len] = '\0';
			bGotRealm = TRUE;

                        log_printf("   value is: '%s'", strRealm);
		    } else {
			log_printf("   Malformed value! type is %d", (int) p->pbData[0]);
			goto done_with_cert;
		    }
		} else if (!strcmp(pCertExt->pszObjId, szOID_ISSUER_ALT_NAME2) && !bGotRealm) {
		    DWORD  cbStructInfo = 0;
		    PCERT_ALT_NAME_INFO pAltNameInfo = NULL;
		    unsigned int j;

		    log_printf("Found ISSUER_ALT_NAME2 Extension");

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

                        log_printf("   value is: '%s'", strRealm);
		    }
		} else if (!strcmp(pCertExt->pszObjId, szOID_SUBJECT_ALT_NAME2)) {
		    DWORD  cbStructInfo = 0;
		    PCERT_ALT_NAME_INFO pAltNameInfo = NULL;
		    unsigned int j;

		    log_printf("Found SUBJECT_ALT_NAME2 Extension");

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

                        log_printf("   value is: '%S'", widname);
		    }
		}
	    }

	    /* If we don't have a realm, then skip the cert */
	    if (!bGotRealm)
		goto done_with_cert;

	    CertGetNameString(pCertContext,
			      CERT_NAME_EMAIL_TYPE,
			      0,
			      NULL,
			      wemail,
			      ARRAYLENGTH(wemail));

	    log_printf("   Email: [%S]", wemail);

	    if ( !bGotIdentity ) {
		/* if we don't have a proper principal name, we
		 * use the email attribute and uppercase the domain. */
		StringCbCopy(widname, sizeof(widname), wemail);

		if (realm = khm_get_realm_from_princ(widname)) {
#if defined(WIN32) && _MSC_VER >= 1400
                    _wcsupr_s(realm, ARRAYLENGTH(widname) - (realm - widname));
#else
                    _wcsupr(realm);
#endif
		}
	    }

	    CertGetNameString(pCertContext,
                              CERT_NAME_SIMPLE_DISPLAY_TYPE,
                              CERT_NAME_ISSUER_FLAG,
                              NULL,
                              wissuer,
                              ARRAYLENGTH(wissuer));

	    log_printf("   Issuer: [%S]", wissuer);

            if (KHM_FAILED
                (kcdb_identity_create(widname, KCDB_IDENT_FLAG_CREATE,
                                      &ident))) {
                log_printf("Can't create identity for certificate");
                goto done_with_cert;
            }

	    if (KHM_FAILED
                (kcdb_cred_create(wissuer, ident, credtype_id, &cred))) {
		log_printf("Can't create credential");
		goto done_with_cert;
	    }

	    AnsiStrToUnicode(wbuffer, sizeof(wbuffer), strRealm);

	    kcdb_cred_set_attr(cred, attr_id_auth_realm,
                               wbuffer, KCDB_CBSIZE_AUTO);

	    CertGetNameString(pCertContext,
                              CERT_NAME_SIMPLE_DISPLAY_TYPE,
                              0,
                              NULL,
                              wbuffer,
                              ARRAYLENGTH(wbuffer));

	    if (wbuffer[0])
		kcdb_cred_set_attr(cred, attr_id_subj_display,
                                   wbuffer, KCDB_CBSIZE_AUTO);

	    kcdb_cred_set_attr(cred, attr_id_issuer_display,
                               wissuer, KCDB_CBSIZE_AUTO);

            /* The SerialNumber and Issuer fields are used later to
               uniquely identify the cert later.  Without them, other
               functions such as deleting certificates will not
               work. */
	    if (pCertInfo->SerialNumber.cbData) {
		kcdb_cred_set_attr(cred, attr_id_serial_number,
                                   pCertInfo->SerialNumber.pbData,
                                   pCertInfo->SerialNumber.cbData);
	    } else {
                log_printf("SerialNumber not found for cert!");
#ifdef DEBUG
                assert(FALSE);
#endif
            }

	    if (pCertInfo->Issuer.cbData) {
		kcdb_cred_set_attr(cred, attr_id_issuer_name,
                                   pCertInfo->Issuer.pbData,
                                   pCertInfo->Issuer.cbData);
	    } else {
                log_printf("Issuer not found for cert!");
#ifdef DEBUG
                assert(FALSE);
#endif
            }

	    kcdb_cred_set_attr(cred, KCDB_ATTR_LOCATION,
                               certstore_name, KCDB_CBSIZE_AUTO);

	    kcdb_cred_set_attr(cred, attr_id_subj_email,
                               wemail, KCDB_CBSIZE_AUTO);

	    /* times */

	    kcdb_cred_set_attr(cred, KCDB_ATTR_ISSUE,
                               &pCertInfo->NotBefore, KCDB_CBSIZE_AUTO);

	    kcdb_cred_set_attr(cred, KCDB_ATTR_EXPIRE,
                               &pCertInfo->NotAfter, KCDB_CBSIZE_AUTO);

	    /* now add the cert to the credset */

	    kcdb_credset_add_cred(g_credset, cred, -1);

	  done_with_cert:
	    if (ident)
		kcdb_identity_release(ident);
	    if (cred)
		kcdb_cred_release(cred);
        } /* if (pCertInfo = pCertContext->pCertInfo) */

        prev_pCertContext = pCertContext;
    }

    log_printf("Done listing KCA certs ----");

    if (pCertContext) {
        CertFreeCertificateContext(pCertContext);
        pCertContext = NULL;
    }

    if (!CertCloseStore(hStoreHandle, CERT_CLOSE_STORE_CHECK_FLAG)) {
        log_printf("The store was closed, but certificates still in use.");
    }

    kcdb_credset_collect(NULL, g_credset, NULL, credtype_id, NULL);
}


