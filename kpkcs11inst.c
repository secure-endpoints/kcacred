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

static khm_boolean
is_plugin_available(void) {
    return FALSE;
}

static khm_boolean
is_plugin_installed(void) {
    return FALSE;
}

static void
install_plugin(void) {
}

void
install_kpkcs11_plugin(void) {

    _begin_task(0);
    _report_cs0(KHERR_INFO, L"Begin installation of PKCS #11 plug-in");

    if (!is_plugin_available()) {
        _report_cs0(KHERR_INFO, L"The plugin DLL was not found. Aborting");
        goto done;
    }

    if (is_plugin_installed()) {
        _report_cs0(KHERR_INFO, L"The plugin already installed. Aorting");
        goto done;
    }

    install_plugin();

 done:
    _end_task();
}
