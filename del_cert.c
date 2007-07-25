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

/* $Id$ */

#include "credprov.h"
#include "debug.h"

struct destroy_cred_rock {
    HCERTSTORE   hStoreHandle;
    khm_int32 rv;
};

khm_int32 KHMAPI
destroy_cred_func(khm_handle cred, void * rock) {
    khm_int32 ctype;
    struct destroy_cred_rock * r;
    PCCERT_CONTEXT pCertContext;

    if (KHM_FAILED(kcdb_cred_get_type(cred, &ctype)) ||
        ctype != credtype_id)
        return KHM_ERROR_SUCCESS; /* skip to the next */

    r = (struct destroy_cred_rock *) rock;

    pCertContext = find_matching_cert(r->hStoreHandle, cred);
    if (pCertContext) {
        if (!CertDeleteCertificateFromStore(pCertContext)) {

            /* this can happen if the credset is out of sync from the
               cert store. */

            r->rv = KHM_ERROR_NOT_FOUND;
        }

        /* CertDeleteCertificateFromStore() frees the cert context. */
    }

    return KHM_ERROR_SUCCESS;
}


khm_int32
kca_del_matching_creds(khm_handle credset) {
    struct destroy_cred_rock r;

    if (credset == NULL)
        return KHM_ERROR_SUCCESS; /* nothing to do */

    ZeroMemory(&r, sizeof(r));

    r.rv = KHM_ERROR_SUCCESS;
    r.hStoreHandle = CertOpenSystemStore(0, WIN32MYCERT_STORE);
    if (r.hStoreHandle == NULL) {
        log_printf("Can't open the system certificate store");
        return KHM_ERROR_UNKNOWN;
    }

    kcdb_credset_apply(credset, destroy_cred_func, &r);

    CertCloseStore(r.hStoreHandle, 0);

    return r.rv;
}

/* should only be called from the plug-in thread.  Destroys contents
   of the g_credset */
khm_int32
kca_del_ident_creds(khm_handle ident) {
    khm_int32 rv = KHM_ERROR_SUCCESS;
    khm_size s = 0;

    rv = kcdb_credset_flush(g_credset);
    if (KHM_FAILED(rv))
        return rv;

    rv = kcdb_credset_extract(g_credset, NULL,
                              ident, credtype_id);
    if (KHM_FAILED(rv))
        return rv;

    rv = kcdb_credset_get_size(g_credset, &s);
    if (s == 0)
        return rv;

    rv = kca_del_matching_creds(g_credset);

    return rv;
}
