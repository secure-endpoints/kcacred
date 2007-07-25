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

#define NOSTRSAFE
#include <tchar.h>
#include <stdio.h>

#include <winsock.h>         // Must be included before <windows.h> !!! 
#include <windows.h>
#include <openssl/x509v3.h>
#include "b64.h"
#include "debug.h" 

#include "credprov.h"
#include <strsafe.h>

wchar_t * getContainerName(X509 *x509)
{
    char * ptr;
    char * issuer_der =NULL, * serial_der = NULL;
    char * issuer_b64 = NULL, * serial_b64 = NULL;
    char * container = NULL;
    wchar_t * containerW = NULL;
    int issuer_len, serial_len, container_len;
    X509_NAME *issuer;
    ASN1_INTEGER *serial;
    size_t 		len2;

    issuer = X509_get_issuer_name(x509);
    if (issuer == NULL)
	goto error;
    issuer_len = i2d_X509_NAME(issuer, NULL);
    issuer_der = (char *)malloc(issuer_len);
    if (!issuer_der) 
	goto error;
    ptr = issuer_der;
    i2d_X509_NAME(issuer, (unsigned char **)&ptr);
    issuer_b64 = malloc((issuer_len+1)*2);
    if (!issuer_b64)
	goto error;
    b64_encode(issuer_der, issuer_len, issuer_b64);

    serial = X509_get_serialNumber(x509);
    if (serial == NULL)
	goto error;
    serial_len = i2d_ASN1_INTEGER(serial, NULL);
    serial_der = (char *)malloc(serial_len);
    if (!serial_der)
	goto error;

    ptr = serial_der;
    i2d_ASN1_INTEGER(serial, (unsigned char **)&ptr);
    serial_b64 = malloc((serial_len+1)*2);
    if (!serial_b64)
	goto error;
    b64_encode(serial_der, serial_len, serial_b64);

    container_len = strlen(issuer_b64)+strlen(serial_b64)+2;
    container = (char *)malloc(container_len);
    if (!container)
	goto error;

    StringCbPrintfA(container, container_len, "%s:%s",issuer_b64,serial_b64);

    len2 = (strlen(container)+1)*2;
    containerW = (wchar_t *)malloc(len2);
    if (!containerW)
	goto error;
    AnsiStrToUnicode(containerW, len2, container);

  error:
    if (issuer_der)
	free(issuer_der);
    if (serial_der)
	free(serial_der);
    if (issuer_b64)
	free(issuer_b64);
    if (serial_b64)
	free(serial_b64);
    if (container)
	free(container);

    return containerW;
}

int store_cert(BYTE *cert, DWORD len, wchar_t * container) {
    HCERTSTORE          hStoreHandle;
    PCCERT_CONTEXT      pCertContext=NULL;      
    CRYPT_KEY_PROV_INFO NewProvInfo;
    DWORD               dwPropId; 
    DWORD               dwFlags =  CERT_STORE_NO_CRYPT_RELEASE_FLAG;
    DWORD		dwCertEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    DWORD		dwErr;
    DWORD		dwFindFlags = 0;
    DWORD		dwAddDisposition = CERT_STORE_ADD_NEW;
    int			rc = 0;

    //--------------------------------------------------------------------
    // Open a store as the source of the certificates to be deleted and added

    if(!(hStoreHandle = CertOpenSystemStore(0, WIN32MYCERT_STORE))) {
        HandleError("The MY system store did not open.");
        return 0;
    }

    //--------------------------------------------------------------------
    // Add caller-provided certificate to the MY store.

    if (!(rc = CertAddEncodedCertificateToStore(hStoreHandle,
                                                dwCertEncodingType,
                                                cert,
                                                len,
                                                dwAddDisposition,
                                                &pCertContext // returned pointer to CERT_CONTEXT
                                                ))) {
        dwErr = GetLastError();
        if (dwErr == CRYPT_E_EXISTS) {
            log_printf("CertAddEncodedCertificateToStore returned CRYPT_E_EXISTS");
        } else if ((dwErr & CRYPT_E_OSS_ERROR) == CRYPT_E_OSS_ERROR) {
            log_printf("CertAddEncodedCertificateToStore returned CRYPT_E_OSS_ERROR"
                       " with GetLastError() returning 0x%08x -- %s", dwErr, GetLastErrorText());
        } else {
            log_printf("CertAddEncodedCertificateToStore failed with 0x%08x -- ", dwErr, GetLastErrorText());
        }

        return 0;
    }

    //--------------------------------------------------------------------
    // Initialize the CRYPT_KEY_PROV_INFO data structure.
    // Note: pwszContainerName and pwszProvName can be set to NULL 
    // to use the default container and provider.

    NewProvInfo.pwszContainerName = container;
    NewProvInfo.pwszProvName = MS_DEF_PROV_W;
    NewProvInfo.dwProvType = PROV_RSA_FULL;
    NewProvInfo.dwFlags = 0;
    NewProvInfo.cProvParam = 0;
    NewProvInfo.rgProvParam = NULL;
    NewProvInfo.dwKeySpec = AT_KEYEXCHANGE;	//	AT_SIGNATURE; // 

    rc = 1;

    //--------------------------------------------------------------------
    // Set the property.

    dwPropId = CERT_KEY_PROV_INFO_PROP_ID; 
    if(!CertSetCertificateContextProperty
       (pCertContext,        /* A pointer to the certificate where the
                                property will be set. */
        dwPropId,            /* An identifier of the property to be
                                set. In this case,
                                CERT_KEY_PROV_INFO_PROP_ID is to be
                                set to provide a pointer with the
                                certificate to its associated private
                                key container. */
        dwFlags,             /* The flag used in this case is
                                CERT_STORE_NO_CRYPT_RELEASE_FLAG,
                                indicating that the cryptographic
                                context acquired should not be
                                released when the function
                                finishes. */
        &NewProvInfo	     /* A pointer to a data structure that
				holds information on the private key
				container to be associated with this
				certificate. */
        )) {
        HandleError("Set property failed."); 
        rc = 0;
    }

    //--------------------------------------------------------------------
    // Clean up.
    CertFreeCertificateContext(pCertContext);
    if(!CertCloseStore(hStoreHandle,
                       CERT_CLOSE_STORE_CHECK_FLAG)) {
        log_printf("The store was closed, but certificates still in use.");
    }

    return rc; 
}  // End store_cert
