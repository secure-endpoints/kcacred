/*
 * Copyright (c) 2006-2007, 2010 Secure Endpoints Inc.
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

kconf_schema
plugin_schema[] = {
    /* goes in <plugins-config> */
    { MYPLUGIN_NAMEW, KC_SPACE, 0, L"Configuration space for our plug-in" },

    /* <plugin-config>\Parameters */
    { L"Parameters", KC_SPACE, 0, L"Parameters" },

    /******* Identity settings ********/

    { L"KCAEnabled", KC_INT32, 1, NULL},
    /* Boolean value.  If non-zero, obtains KCA certificates. */

    { L"KCAHosts", KC_STRING, (khm_ui_8) L"", NULL},
    /* String value.  Space separated list of KCA hosts to use. */

    { L"KCAHostMethod", KC_INT32, 0, NULL},
    /* Method for determining KCA hosts. Currently, 0 means determine
       hosts automatically (in which case 'KCAHosts' value is
       ignored). 1 means use the 'KCAHosts' value, and enables
       specifying host list manually. */

    { L"IssuerDN", KC_STRING, (khm_ui_8) L"", NULL},
    /* Distinguished name of the issuer.  This field is only expected
       to be found in the Realms/<Realm>/ key and is used to associate
       KCA certificates with known realms. */

    { L"Realms", KC_SPACE, 0, L"Per-realm configuration"},

    /* Per-realm settings are the same as identity settings.  Each
       realm has a subspace under this node named after the
       realm. Values specified here shadow those that are specified
       per-identity. */

    { L"Realms", KC_ENDSPACE, 0, NULL},

    { L"Parameters", KC_ENDSPACE, 0, NULL},

    { MYPLUGIN_NAMEW, KC_ENDSPACE, 0, NULL}
};

khm_size n_plugin_schema = ARRAYLENGTH(plugin_schema);
