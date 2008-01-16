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

#define KCAEXPORTS_C
#include "kcaexports.h"

extern void (*_log_external)(const char *);

KCAEXP int KHMAPI
get_plugin_exports(KCAPluginExports * e)
{
    if (e->magic != KCAPluginExportsMagic ||
        e->size != sizeof(*e))
        return FALSE;

    e->getcert = getcert;
    e->clean_cert  = clean_cert;
    e->client_genkey = client_genkey;
    e->getContainerName = getContainerName;
    e->store_key = store_key;
    e->store_cert = store_cert;
    e->list_creds = kca_list_creds;

    if (e->log)
        _log_external = e->log;

    return TRUE;
}
