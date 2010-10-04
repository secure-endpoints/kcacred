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

/* get_realm.c -- gather into one file all code related to determining
 *			the realm of the user's (currently active)
 *			Kerberos tickets, irrespective of the client's
 *			architecture or kerberos implementation
 *
 * CHANGE HISTORY:
 *	2000.1213 -- billdo -- created
 *
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <errno.h>
#include <string.h>

# define __WINCRYPT_H__		// PREVENT windows.h from including wincrypt.h
				// since wincrypt.h and openssl namepsaces collide
				//  ex. X509_NAME is #define'd and typedef'd ...
# include <ws2tcpip.h>		// Must be included before <windows.h> !!!
# include <windows.h>
# include <netidmgr.h>
# include <openssl/pem.h>


#include <stdlib.h>
#include <openssl/x509v3.h>

# include <krb5.h>
# include <com_err.h>

#include "kx509.h"
#include "debug.h"

#include<strsafe.h>

/*
 *=========================================================================*
 *
 * get_krb5_realm()
 *
 *=========================================================================*
 */
int get_krb5_realm(krb5_context k5_context, char *realm,
                   size_t cch_realm,
		   char *tkt_cache_name, char **err_msg)
{
    krb5_ccache cc = NULL;
    krb5_principal me = NULL;
    krb5_error_code result;
    int retcode = 0;

    *realm = 0;

    if(tkt_cache_name) {
        if (result = krb5_cc_resolve(k5_context, tkt_cache_name, &cc)) {
	    const char * result_text = krb5_get_error_message(k5_context, result);
	    _report_cs1(KHERR_DEBUG_1, L"get_cert_authent_K5: krb5_cc_resolve: %1!S!",
                        _cptr(result_text));
            _resolve();
	    *err_msg = "Unable to determine default credentials cache.";
	    retcode = KX509_STATUS_CLNT_FIX;
            goto cleanup;
        }
    } else {
        if (result = krb5_cc_default(k5_context, &cc)) {
  	    const char * result_text = krb5_get_error_message(k5_context, result);
            _report_cs1(KHERR_DEBUG_1, L"get_krb5_realm: krb5_cc_default: %1!S!", 
                        _cptr(result_text));
            _resolve();
	    *err_msg = "Unable to determine default credentials cache.";
	    retcode = KX509_STATUS_CLNT_FIX;
            goto cleanup;
        }
    }

    if (result = krb5_cc_get_principal(k5_context, cc, &me)) {
        const char * result_text = krb5_get_error_message(k5_context, result);
        _report_cs1(KHERR_DEBUG_1, L"get_krb5_realm: krb5_cc_get_principal: %1!S!",
                    _cptr(result_text));
        _resolve();
        *err_msg = "Unable to determine principal from credentials cache.";
        retcode = KX509_STATUS_CLNT_FIX;
        goto cleanup;
    }

    if (strlen(krb5_principal_get_realm(k5_context, me)) >= cch_realm) {
        _report_cs0(KHERR_DEBUG_1, L"get_krb5_realm: realm name too long!");
        _resolve();
        *err_msg = "Realm name too long.";
        retcode = KX509_STATUS_CLNT_BAD;
        goto cleanup;
    }

    strcpy_s(realm, cch_realm, krb5_principal_get_realm(k5_context, me));

 cleanup:
    if (cc)
        krb5_cc_close(k5_context, cc);
    if (me)
        krb5_free_principal(k5_context, me);

    return retcode;
}

