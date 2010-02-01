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

#include<windows.h>
#include<stdio.h>
#define NOEXPORT
#include<netidmgr.h>

#include "..\kcaexports.h"

/* Internals */
KHMEXP khm_int32 KHMAPI kmq_init(void);
KHMEXP khm_int32 KHMAPI kmq_exit(void);
KHMEXP void KHMAPI khui_init_actions(void);
KHMEXP void KHMAPI khui_exit_actions(void);

KCAPluginExports e;

void
logger(const char * m)
{
    OutputDebugStringA(m);
    fprintf(stderr, "%s\n", m);
}

void
do_tests(void)
{
    (*e.list_creds)();
}

static char g_realm[256]="WINDOWS.SECURE-ENDPOINTS.COM";
static char g_ccname[280]="API:jaltman@WINDOWS.SECURE-ENDPOINTS.COM";
static char g_hostlist[2048]="www.secure-endpoints.com";
static int  g_nattempts=10000;

void parse_args(int argc, char *argv[])
{
    /* nothing to do yet */
    ;
}

void stress_test_kca(void)
{
    RSA         *rsa;
    int         keybits;
    X509        *x509;
    char        msg[1024]="";
    int         i;
    char        subject[2048], issuer[2048], *serial_str;
    ASN1_INTEGER *asn;
    DWORD       rc;
    BYTE * pk;
    DWORD  cbPk;

    for (i=0; i<g_nattempts; i++) {
        rsa = NULL;
        x509 = NULL;
        serial_str = NULL;

        printf("Attempt %d of %d\n", i, g_nattempts);

        rc = (e.getcert)(&rsa, &keybits, &x509, msg, (int)sizeof(msg), 
                        g_realm, (int)sizeof(g_realm),
                        g_ccname, NULL);

        if (rc == 0) 
        {
            X509_NAME_oneline(X509_get_subject_name(x509), subject, sizeof(subject));

            X509_NAME_oneline(X509_get_issuer_name(x509), issuer, sizeof(issuer));

            asn = X509_get_serialNumber(x509);
            serial_str = i2s_ASN1_INTEGER(NULL, asn);
            printf("Got cert (keylength=%d):(serial=%s):\nissuer=%s\nsubject=%s\n",
                   keybits,serial_str,issuer,subject);

            if ((e.rsa_to_keyblob)(keybits, rsa, &pk, &cbPk))
            {
                if (!(e.store_key)(pk, cbPk, L"kcacred-test"))
                    printf("Store key failed\n");

                (e.free)(pk);
            }

            (e.clean_cert)(rsa, x509);

            OPENSSL_free(serial_str);
            printf("\n");
        } else {
            printf("Failure 0x%x\n\n", rc);
        }
    }
}

int main(int argc, char *argv[])
{
    PDESCTHREAD(L"UI",L"App");

    khm_version_init();
    kmq_init();
    khui_init_actions();
    kmm_init();

    kmm_load_module(L"KCAMod", 0, NULL);

    ZeroMemory(&e, sizeof(e));
    e.log = logger;
    e.magic = KCAPluginExportsMagic;
    e.size = sizeof(e);

    if (!get_plugin_exports(&e)) {
        fprintf(stderr, "Can't get exports.\n");
        goto _exit;
    }

    parse_args(argc, argv);

    stress_test_kca();

 _exit:
    kmm_exit();
    khui_exit_actions();
    kmq_exit();

    return 0;
}
