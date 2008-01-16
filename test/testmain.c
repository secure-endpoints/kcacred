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

KCAPluginExports e;

void
log(const char * m)
{
    OutputDebugStringA(m);
    fprintf(stderr, "%s\n", m);
}

void
do_tests(void)
{
    (*e.list_creds)();
}

int main(int argc, char ** argv)
{
    PDESCTHREAD(L"UI",L"App");

    khm_version_init();
    kmq_init();
    khui_init_actions();
    kmm_init();

    kmm_load_module(L"KCAMod", 0, NULL);

    ZeroMemory(&e, sizeof(e));
    e.log = log;
    e.magic = KCAPluginExportsMagic;
    e.size = sizeof(e);

    if (!get_plugin_exports(&e)) {
        fprintf(stderr, "Can't get exports.\n");
        goto _exit;
    }

    do_tests();

 _exit:
    kmm_exit();
    khui_exit_actions();
    kmq_exit();

    return 0;
}
