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
#include <assert.h>

/* Dialog procedures and support functions for handling configuration
   dialogs for per-identity configuration. When the configuration
   dialog is activated, an instance of this dialog will be created for
   each identity that the user touches. */

INT_PTR CALLBACK
config_id_dlgproc(HWND hwnd,
                  UINT uMsg,
                  WPARAM wParam,
                  LPARAM lParam) {

    struct nc_dialog_data * d;

    switch (uMsg) {
    case WM_INITDIALOG:
        {
            wchar_t idname[KCDB_IDENT_MAXCCH_NAME];
            khm_size cb;
            khm_int32 rv;

            d = malloc(sizeof(*d));
            assert(d);
            ZeroMemory(d, sizeof(*d));

            /* for subpanels, lParam is a pointer to a
               khui_config_init_data strucutre that provides the
               instance and context information.  It's not a
               persistent strucutre, so we have to make a copy. */
            d->cfg = *((khui_config_init_data *) lParam);
            d->hwnd = hwnd;

            certset_init(&d->certset);

            cb = sizeof(idname);
            rv = khui_cfg_get_name(d->cfg.ctx_node, idname, &cb);
            assert(KHM_SUCCEEDED(rv));

            rv = kcdb_identity_create(idname, 0, &d->ident);
            assert(KHM_SUCCEEDED(rv));

#pragma warning(push)
#pragma warning(disable: 4244)
            SetWindowLongPtr(hwnd, DWLP_USER, (LONG_PTR) d);
#pragma warning(pop)

            d->loading = TRUE;
            dlg_load_identity_params(d, d->ident);
            dlg_init(d);
            dlg_enable_certs(d, d->enabled, TRUE);
            d->loading = FALSE;
        }
        return FALSE;

    case KHUI_WM_CFG_NOTIFY:
        d = (struct nc_dialog_data *)
            GetWindowLongPtr(hwnd, DWLP_USER);

        if (d == NULL)
            return TRUE;

        if (HIWORD(wParam) == WMCFG_APPLY) {
            if (d->dirty) {
                dlg_save_identity_params(d);

                khui_cfg_set_flags_inst(&d->cfg,
                                        KHUI_CNFLAG_APPLIED,
                                        (KHUI_CNFLAG_APPLIED |
                                         KHUI_CNFLAG_MODIFIED));

                d->dirty = FALSE;
            } else {
                /* do nothing */
            }
            return TRUE;
        }
        break;

    case WM_COMMAND:
        {
            INT_PTR rv;
            khm_boolean old_dirty;

            d = (struct nc_dialog_data *)
                GetWindowLongPtr(hwnd, DWLP_USER);

            if (d == NULL)
                break;

            old_dirty = d->dirty;
            rv = dlg_handle_wm_command(d, wParam, lParam);

            if (d->dirty && !old_dirty) {
                khui_cfg_set_flags_inst(&d->cfg,
                                        KHUI_CNFLAG_MODIFIED,
                                        KHUI_CNFLAG_MODIFIED);
            }
            return rv;
        }
        break;

    case WM_NOTIFY:
        {
            INT_PTR rv;
            khm_boolean old_dirty;

            d = (struct nc_dialog_data *)
                GetWindowLongPtr(hwnd, DWLP_USER);

            if (d == NULL)
                break;

            old_dirty = d->dirty;
            rv = dlg_handle_wm_notify(d, wParam, lParam);

            if (d->dirty && !old_dirty) {
                khui_cfg_set_flags_inst(&d->cfg,
                                        KHUI_CNFLAG_MODIFIED,
                                        KHUI_CNFLAG_MODIFIED);
            }
            return rv;
        }
        break;

    case WM_DESTROY:
        {
            d = (struct nc_dialog_data *)
                GetWindowLongPtr(hwnd, DWLP_USER);

            if (d != NULL) {
                if (d->ident)
                    kcdb_identity_release(d->ident);

                certset_destroy(&d->certset);

                free(d);

#pragma warning(push)
#pragma warning(disable: 4244)
                SetWindowLongPtr(hwnd, DWLP_USER, (LONG_PTR) 0);
#pragma warning(pop)
            }
        }
        break;
    }

    return FALSE;

}
