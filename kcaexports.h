/*
 * Copyright (c) 2008 Secure Endpoints Inc.
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

#pragma once

#include "credprov.h"
#include<openssl/x509v3.h>
#include "kx509.h"
#include "doauth.h"

typedef struct _KCAPluginExports {
    DWORD magic;                /* Always KCAPluginExportsMagic */
    DWORD size;                 /* Size of the structure, in bytes */

    /* IN */
    void (*log)(const char *);

    /* OUT */

    int
    (*getcert)(RSA **, X509 **, char *, int, char *, int, char *, char *);

    void
    (*clean_cert)(RSA *, X509 *);

    RSA *
    (*client_genkey)(int);

    wchar_t *
    (*getContainerName)(X509 *x509);

    int
    (*store_key)(BYTE *p, DWORD cbPk, wchar_t * container);

    int
    (*store_cert)(BYTE *cert, DWORD len, wchar_t * container);

    void
    (*list_creds)(void);
} KCAPluginExports;

#define KCAPluginExportsMagic 0xd341f4a0

#ifdef KCAEXPORTS_C
#define KCAEXP KHMEXP_EXP
#else
#define KCAEXP KHMEXP_IMP
#endif

KCAEXP int KHMAPI
get_plugin_exports(KCAPluginExports * e);
