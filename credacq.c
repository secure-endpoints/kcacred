/*
 * Copyright (c) 2006-2008 Secure Endpoints Inc.
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

#define NOSTRSAFE
#include "credprov.h"
#include "debug.h"
#include <openssl/x509v3.h>
#include "kx509.h"
#include "doauth.h"
#include "help/kcahelp.h"
#include <shlwapi.h>
#include <htmlhelp.h>
#include <commctrl.h>
#include <assert.h>

#include <windowsx.h>

#include <strsafe.h>

#ifndef SIZE_MAX
#ifdef _WIN64
#define SIZE_MAX _UI64_MAX
#else
#define SIZE_MAX UINT_MAX
#endif
#endif

/* This file provides handlers for the credentials acquisition
   messages including handling the user interface for the new
   credentials dialogs. */

/*********************************************************************
 Certificate sets

 These don't contain actual certificates.  They just describe how a
 set of certificates should be obtained by KCA.
*********************************************************************/
#define CERTSET_ALLOC_INCR 4

void
certset_init(struct nc_cert_set * certset) {
    ZeroMemory(certset, sizeof(*certset));
}

void
certset_destroy(struct nc_cert_set * certset) {
    if (certset->certs) {
        PFREE(certset->certs);
    }

    ZeroMemory(certset, sizeof(*certset));
}

void
certset_del_cert(struct nc_cert_set * certset,
                 khm_size idx) {
    if (idx > certset->n_certs) {
        return;
    }

    if (idx < certset->n_certs - 1) {
        MoveMemory(&certset->certs[idx],
                   &certset->certs[idx + 1],
                   sizeof(certset->certs[0]) * (certset->n_certs - (idx + 1))); 
    }

    certset->n_certs--;
}

const wchar_t *
certset_get_eff_realm(enum kca_host_method method,
                      const wchar_t * realm,
                      const wchar_t * def_realm) {
    if (method == KCA_HOST_AUTO ||
        (method == KCA_HOST_MANUAL && !realm[0]))
        return def_realm;
    else if (method == KCA_HOST_REALM ||
             (method == KCA_HOST_MANUAL && realm[0]))
        return realm;
    else {
#ifdef DEBUG
        assert(FALSE);
#endif
        return NULL;
    }
}

enum kca_host_method
certset_get_method(const wchar_t * realm,
                   const wchar_t * hosts) {

    enum kca_host_method method;

    if (hosts && hosts[0])
        method = KCA_HOST_MANUAL;
    else if (realm && realm[0])
        method = KCA_HOST_REALM;
    else
        method = KCA_HOST_AUTO;

    return method;
}

const wchar_t *
certset_get_cert_eff_realm(struct nc_cert_set * certset,
                           khm_size idx) {

    if (idx >= certset->n_certs)
        return NULL;
    else
        return certset_get_eff_realm(certset->certs[idx].kca_host_method,
                                     certset->certs[idx].kca_realm,
                                     certset->identity_realm);
}

khm_size
certset_add_cert(struct nc_cert_set * certset,
                 enum kca_host_method method,
                 const wchar_t * realm,
                 const wchar_t * hosts) {

    struct nc_cert * cert;
    khm_size idx;
    const wchar_t * eff_realm;

    /* first check if we already have the specified realm in the
       set. */

    eff_realm = certset_get_eff_realm(method,
                                      realm,
                                      certset->identity_realm);

    if (eff_realm) {
        for (idx = 0; idx < certset->n_certs; idx ++) {
            const wchar_t * c_eff_realm;

            c_eff_realm = certset_get_cert_eff_realm(certset, idx);

            if (c_eff_realm && !wcscmp(c_eff_realm, eff_realm)) {

                cert = &certset->certs[idx];

                cert->kca_host_method = method;
                StringCbCopy(cert->kca_realm, sizeof(cert->kca_realm), realm);
                StringCbCopy(cert->kca_hosts, sizeof(cert->kca_hosts), hosts);

                return idx;
            }
        }
    }

    /* we need to add a new one */

    if (certset->n_certs + 1 >= certset->nc_certs) {
        certset->nc_certs = UBOUNDSS(certset->n_certs + 1,
                                     CERTSET_ALLOC_INCR,
                                     CERTSET_ALLOC_INCR);

#ifdef DEBUG
        assert(certset->nc_certs > certset->n_certs + 1);
#endif
        certset->certs = PREALLOC(certset->certs,
                                  sizeof(certset->certs[0]) * certset->nc_certs);
#ifdef DEBUG
        assert(certset->certs);
#endif
        if (certset->certs == NULL)
            return SIZE_MAX;

        ZeroMemory(&certset->certs[certset->n_certs],
                   sizeof(certset->certs[0]) * (certset->nc_certs - certset->n_certs));
    }

    idx = certset->n_certs;
    cert = &certset->certs[idx];

    ZeroMemory(cert, sizeof(*cert));

    cert->kca_host_method = method;
    StringCbCopy(cert->kca_realm, sizeof(cert->kca_realm), realm);
    StringCbCopy(cert->kca_hosts, sizeof(cert->kca_hosts), hosts);

    certset->n_certs++;

    return (int) idx;
}

struct nc_cert *
certset_get_cert(struct nc_cert_set * certset, khm_size idx) {

    if (idx >= certset->n_certs)
        return NULL;
    else
        return &certset->certs[idx];
}

void
unparse_cert_string(wchar_t * s,
                    khm_size cb_s,
                    enum kca_host_method method,
                    const wchar_t * realm,
                    const wchar_t * hosts) {

    wchar_t parsebuffer[KCA_MAXCCH_REALM + KCA_MAXCCH_HOST * KCA_MAX_HOSTS + 16];
    wchar_t str[KCA_MAXCCH_HOST * KCA_MAX_HOSTS + 8];
    khm_size cb;

    multi_string_init(parsebuffer, sizeof(parsebuffer));

    StringCbPrintf(str, sizeof(str), L"realm=%s",
                   ((method == KCA_HOST_AUTO || method == KCA_HOST_MANUAL)? L"[Identity]":
                    realm));

    cb = sizeof(parsebuffer);
    multi_string_append(parsebuffer, &cb, str);

    StringCbPrintf(str, sizeof(str), L"hosts=%s",
                   ((method == KCA_HOST_MANUAL)? hosts : L"[Automatic]"));

    cb = sizeof(parsebuffer);
    multi_string_append(parsebuffer, &cb, str);

    cb = cb_s;
    multi_string_to_csv(s, &cb, parsebuffer);
}

void
parse_cert_string(const wchar_t * s,
                  enum kca_host_method * method,
                  wchar_t * realm,
                  khm_size cb_realm,
                  wchar_t * hosts,
                  khm_size cb_hosts) {
    wchar_t parsebuffer[KCA_MAXCCH_REALM + KCA_MAXCCH_HOST * KCA_MAX_HOSTS + 16];
    khm_size cb;
    wchar_t * t;
    wchar_t * prealm = NULL;
    wchar_t * phosts = NULL;

    cb = sizeof(parsebuffer);

    if (KHM_FAILED(csv_to_multi_string(parsebuffer, &cb, s)))
        goto failed_to_parse;

    for (t = parsebuffer; t && *t; t = multi_string_next(t)) {
        if (!wcsncmp(t, L"realm=", 6)) {
#ifdef DEBUG
            assert(prealm == NULL);
#endif
            prealm = t + 6;
        } else if (!wcsncmp(t, L"hosts=", 6)) {
#ifdef DEBUG
            assert(phosts == NULL);
#endif
            phosts = t + 6;
        } else {
#ifdef DEBUG
            assert(FALSE);
#endif
        }
    }

    if (prealm && !wcscmp(prealm, L"[Identity]"))
        prealm = NULL;

    if (phosts && !wcscmp(phosts, L"[Automatic]"))
        phosts = NULL;

    if (prealm)
        StringCbCopy(realm, cb_realm, prealm);
    else
        StringCbCopy(realm, cb_realm, L"");

    if (phosts)
        StringCbCopy(hosts, cb_hosts, phosts);
    else
        StringCbCopy(hosts, cb_hosts, L"");

    if (prealm == NULL && phosts == NULL) {

        *method = KCA_HOST_AUTO;

    } else if (prealm != NULL) {

        *method = KCA_HOST_REALM;

    } else {

        *method = KCA_HOST_MANUAL;

    }

    return;

 failed_to_parse:

    /* use defaults */

    *method = KCA_HOST_AUTO;

    StringCbCopy(realm, cb_realm, L"");
    StringCbCopy(hosts, cb_hosts, L"");
}

/*********************************************************************

  Compatibility with Win2000

  The dialog code uses XP specific (actually comctl32.dll version 6.0+
  specific) funcitonality to make better use of screen real-estate and
  for generally better user experience.  Since this is incompatible
  with Win2k, we use subclassed controls to emulate some of the
  features on Win2k.

 ********************************************************************/

LONG UI_compat_initialized = 0;
BOOL UI_compat_emulate = FALSE;

static void
UI_compat_init(void) {

    khm_ui_4 comctl_version;

    if (InterlockedIncrement(&UI_compat_initialized) > 1) {
        /* already done */
        InterlockedDecrement(&UI_compat_initialized);
        return;

        /* the compatibility functions are only supposed to be called
           from the UI thread.  So we don't do anything more than this
           to ensure thread safety. */
    }

    comctl_version = khm_get_commctl_version(NULL);

    if (comctl_version >= 0x00060000) {
        /* Windows XP or higher */
        UI_compat_emulate = FALSE;
    } else {
        /* Not Win XP */
        UI_compat_emulate = TRUE;
    }
}

#define MAXCCH_CUEBANNER 256
#define UI_EDIT_PROP L"KCAEditEmu"

struct UI_Edit_Subclass_data {
    DWORD magic;
#define UI_EDIT_MAGIC 0xe670021c

    WNDPROC old_wnd_proc;
    wchar_t cue_banner[MAXCCH_CUEBANNER];

    BOOL focus;
};

/* From CommCtrl.h */
#ifndef EM_SETCUEBANNER
#ifndef ECM_FIRST
#define ECM_FIRST 0x1500
#endif
#define EM_SETCUEBANNER (ECM_FIRST + 1)
#endif

#ifndef Edit_SetCueBannerText
#define Edit_SetCueBannerText(hw,cue) (SendMessage((hw), EM_SETCUEBANNER, 0, (LPARAM) (cue)))
#endif

/* Subclassed window procedure.  This will be used to subclass the
   EDIT window controls to provide cue banners. */
LRESULT CALLBACK
UI_Edit_Proc (HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {

    HLOCAL hl_data = GetProp(hwnd, UI_EDIT_PROP);
    struct UI_Edit_Subclass_data * p_data;
    WNDPROC wndproc = NULL;
    BOOL passthrough = TRUE;
    LRESULT lr = FALSE;

#ifdef DEBUG
    assert(hl_data != INVALID_HANDLE_VALUE);
#endif

    if (hl_data == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    p_data = LocalLock(hl_data);
#ifdef DEBUG
    assert(p_data);
    assert(p_data->magic == UI_EDIT_MAGIC);
    assert(p_data->old_wnd_proc);
#endif

    if (p_data == NULL || p_data->magic != UI_EDIT_MAGIC) {
        if (p_data)
            LocalUnlock(hl_data);
        return FALSE;
    }

    wndproc = p_data->old_wnd_proc;

    switch (uMsg) {

    case WM_DESTROY:
        LocalUnlock(hl_data);
        SetWindowLongPtr(hwnd, GWLP_WNDPROC, (LONG_PTR) wndproc);
        RemoveProp(hwnd, UI_EDIT_PROP);
        LocalFree(hl_data);

        return CallWindowProc(wndproc, hwnd, uMsg, wParam, lParam);

    case EM_SETCUEBANNER:
        lr = SUCCEEDED(StringCbCopy(p_data->cue_banner, sizeof(p_data->cue_banner),
                                    (const wchar_t *) lParam));
        InvalidateRect(hwnd, NULL, TRUE);
        passthrough = FALSE;
        break;

    case WM_SETFOCUS:
        p_data->focus = TRUE;
        InvalidateRect(hwnd, NULL, TRUE);
        break;

    case WM_KILLFOCUS:
        p_data->focus = FALSE;
        InvalidateRect(hwnd, NULL, TRUE);
        break;

    case WM_PAINT:
        lr = CallWindowProc(wndproc, hwnd, uMsg, wParam, lParam);
        passthrough = FALSE;

        /* do our own drawing, if necessary */
        if (!p_data->focus) {
            wchar_t wtext[32];

            wtext[0] = L'\0';

            CallWindowProc(wndproc, hwnd, WM_GETTEXT, ARRAYLENGTH(wtext),
                           (LPARAM) wtext);

            if (wtext[0] == L'\0' && p_data->cue_banner[0] != L'\0') {
                /* we have to show the cue banner */
                HFONT hf = NULL;
                HFONT hf_old = NULL;
                HDC hdc;
                RECT r;
                size_t len = 0;

                StringCchLength(p_data->cue_banner, ARRAYLENGTH(p_data->cue_banner),
                                &len);

                hf = (HFONT) CallWindowProc(wndproc, hwnd, WM_GETFONT, 0, 0);

                hdc = GetWindowDC(hwnd);

                if (hf)
                    hf_old = SelectFont(hdc, hf);

                SetTextColor(hdc, GetSysColor(COLOR_GRAYTEXT));
                SetBkMode(hdc, TRANSPARENT);

                GetClientRect(hwnd, &r);

                DrawText(hdc, p_data->cue_banner, (int)len, &r,
                         DT_SINGLELINE | DT_VCENTER);

                if (hf)
                    SelectFont(hdc, hf_old);

                ReleaseDC(hwnd, hdc);
            }
        }
 
        break;
    }

    LocalUnlock(hl_data);

    if (passthrough && wndproc)
        return CallWindowProc(wndproc, hwnd, uMsg, wParam, lParam);
    else
        return lr;
}

static BOOL
UI_Edit_SetCompat(HWND hw_edit) {
    HLOCAL hl_data = INVALID_HANDLE_VALUE;
    struct UI_Edit_Subclass_data * p_data = NULL;
    WNDPROC old_wp = NULL;

    UI_compat_init();

    if (!UI_compat_emulate)
        return TRUE;            /* nothing to do */

    old_wp = (WNDPROC) GetWindowLongPtr(hw_edit, GWLP_WNDPROC);

    if (old_wp == UI_Edit_Proc) {
        /* uh oh.  we tried to subclass a control that was already
           subclassed by us. This can actually happen when controls
           reuse child EDIT controls for various reasons and our code
           can't tell whether it's a new EDIT control or a re-used old
           one. */

        /* Nothing to do. */
        return TRUE;
    }

    hl_data = LocalAlloc(LHND, sizeof(struct UI_Edit_Subclass_data));
#ifdef DEBUG
    assert(hl_data != INVALID_HANDLE_VALUE);
#endif
    if (hl_data == INVALID_HANDLE_VALUE)
        return FALSE;

    p_data = (struct UI_Edit_Subclass_data *) LocalLock(hl_data);
    if (p_data == NULL)
        goto error_exit;

    p_data->magic = UI_EDIT_MAGIC;
    p_data->cue_banner[0] = L'\0';
    p_data->old_wnd_proc = NULL;

    SetProp(hw_edit, UI_EDIT_PROP, hl_data);

    p_data->old_wnd_proc = old_wp;
    SetWindowLongPtr(hw_edit, GWLP_WNDPROC, (LONG_PTR) UI_Edit_Proc);

    return TRUE;

 error_exit:
    if (p_data != NULL && hl_data != INVALID_HANDLE_VALUE)
        LocalUnlock(hl_data);
    LocalFree(hl_data);

    return FALSE;
}

/*********************************************************************

These are stubs for the Window message for the dialog panel.  This
dialog panel is the one that is added to the new credentials window
for obtaining new credentials.

Note that all the UI callbacks run under the UI thread.

 *********************************************************************/

static void
dlg_certlist_add_item(struct nc_dialog_data * d,
                      HWND hw_list,
                      struct nc_cert * cert,
                      khm_size cert_idx,
                      int idx) {
    wchar_t str_idrealm[KHUI_MAXCCH_SHORT_DESC];
    wchar_t str_autohost[KHUI_MAXCCH_SHORT_DESC];
    wchar_t buf[128];
    LVITEM lvi;
    wchar_t * txt_realm;
    wchar_t * txt_hosts;

    LoadString(hResModule, IDS_NC_CL_IDREALM, buf, ARRAYLENGTH(buf));
    StringCbPrintf(str_idrealm, sizeof(str_idrealm), buf, d->certset.identity_realm);
    LoadString(hResModule, IDS_NC_CL_AUTOHOST, str_autohost, ARRAYLENGTH(str_autohost));

    if (cert->kca_host_method == KCA_HOST_AUTO) {

        txt_realm = str_idrealm;
        txt_hosts = str_autohost;

    } else if (cert->kca_host_method == KCA_HOST_REALM) {

        txt_realm = cert->kca_realm;
        txt_hosts = str_autohost;

    } else {
#ifdef DEBUG
        assert(cert->kca_host_method == KCA_HOST_MANUAL);
#endif

        txt_realm = (cert->kca_realm[0]? cert->kca_realm : str_idrealm);
        txt_hosts = cert->kca_hosts;
    }

    ZeroMemory(&lvi, sizeof(lvi));

    if (idx >= 0) {

        lvi.mask = LVIF_TEXT | LVIF_IMAGE;
        lvi.iItem = idx;
        lvi.iSubItem = 1;
        lvi.pszText = txt_hosts;
        lvi.iImage = 0;

        ListView_SetItem(hw_list, &lvi);

        lvi.mask = LVIF_TEXT;
        lvi.iSubItem = 0;
        lvi.pszText = txt_realm;

        ListView_SetItem(hw_list, &lvi);

    } else {

        lvi.mask = LVIF_PARAM | LVIF_TEXT | LVIF_IMAGE;
        lvi.iItem = (int) cert_idx;
        lvi.iSubItem = 0;

        lvi.pszText = txt_realm;
        lvi.lParam = (LPARAM) cert_idx;
        lvi.iImage = 0;

        idx = ListView_InsertItem(hw_list, &lvi);
#ifdef DEBUG
        assert(idx >= 0);
#endif
        lvi.mask = LVIF_TEXT;
        lvi.iItem = idx;
        lvi.iSubItem = 1;
        lvi.pszText = txt_hosts;

        ListView_SetItem(hw_list, &lvi);
    }
}

void
dlg_init(struct nc_dialog_data * d) {

    HWND hw_list;
    HWND hw_realm;
    HWND hw_hosts;

    hw_list =  GetDlgItem(d->hwnd, IDC_NC_CERTLIST);
    hw_realm = GetDlgItem(d->hwnd, IDC_NC_REALM);
    hw_hosts = GetDlgItem(d->hwnd, IDC_NC_HOSTS);

#ifdef DEBUG
    assert(hw_list);
    assert(hw_realm);
    assert(hw_hosts);
#endif

    if (!d->certlist_initialized) {
        LVCOLUMN lvc;
        RECT r;
        wchar_t coltext[KHUI_MAXCCH_SHORT_DESC];
        HIMAGELIST ilist;
        HICON icon;

        GetClientRect(hw_list, &r);

        ZeroMemory(&lvc, sizeof(lvc));
        lvc.mask = LVCF_TEXT | LVCF_WIDTH;
        lvc.pszText = coltext;
        LoadString(hResModule, IDS_NC_CL_REALM, coltext, ARRAYLENGTH(coltext));
        lvc.cx = (r.right - r.left) * 2 / 3;

        ListView_InsertColumn(hw_list, 0, &lvc);

        lvc.mask |= LVCF_SUBITEM;
        lvc.cx = (r.right - r.left) - lvc.cx;
        lvc.iSubItem = 1;
        LoadString(hResModule, IDS_NC_CL_HOSTS, coltext, ARRAYLENGTH(coltext));

        ListView_InsertColumn(hw_list, 1, &lvc);

        ilist = ImageList_Create(GetSystemMetrics(SM_CXSMICON),
                                 GetSystemMetrics(SM_CYSMICON),
                                 ILC_COLORDDB | ILC_MASK,
                                 4, 4);

        icon = (HICON) LoadImage(hResModule, MAKEINTRESOURCE(IDI_CERT),
                                 IMAGE_ICON,
                                 GetSystemMetrics(SM_CXSMICON),
                                 GetSystemMetrics(SM_CYSMICON),
                                 LR_DEFAULTCOLOR);

        ImageList_AddIcon(ilist, icon);

        DestroyIcon(icon);

        ListView_SetImageList(hw_list, ilist, LVSIL_SMALL);
        /* We don't need to keep track of the image list from now on.
           The list view will destroy it when the control is
           destroyed. */

        UI_Edit_SetCompat(hw_realm);
        UI_Edit_SetCompat(hw_hosts);

        d->certlist_initialized = TRUE;
    }

    SetWindowText(hw_realm, L"");
    SetWindowText(hw_hosts, L"");

    SendMessage(hw_realm, EM_SETLIMITTEXT, KCA_MAXCCH_REALM - 1, 0);
    SendMessage(hw_hosts, EM_SETLIMITTEXT, KCA_MAXCCH_HOST * KCA_MAX_HOSTS - 2, 0);

    {
        wchar_t cuebanner[KHUI_MAXCCH_SHORT_DESC];
        wchar_t fmt[128];

        LoadString(hResModule, IDS_NC_CUE_REALM_F, fmt, ARRAYLENGTH(fmt));
        StringCbPrintf(cuebanner, sizeof(cuebanner), fmt, d->certset.identity_realm);

        Edit_SetCueBannerText(hw_realm, cuebanner);

        LoadString(hResModule, IDS_NC_CUE_HOSTS, cuebanner, ARRAYLENGTH(cuebanner));

        Edit_SetCueBannerText(hw_hosts, cuebanner);
    }

    {
        khm_size i;

        ListView_DeleteAllItems(hw_list);

        for (i=0; i < d->certset.n_certs; i++) {
            struct nc_cert * cert;

            cert = certset_get_cert(&d->certset, i);
            if (cert == NULL) {
#ifdef DEBUG
                assert(FALSE);
#endif
                continue;
            }

            dlg_certlist_add_item(d, hw_list, cert, i, -1);
        }
    }
}

static void
safe_enable_window(HWND dlg, int ctl_id, BOOL enable) {
    HWND ctl;

    ctl = GetDlgItem(dlg, ctl_id);

    if (ctl == NULL)
        return;

    if (enable)
        EnableWindow(ctl, TRUE);
    else {
        HWND hwfocus = GetFocus();

        if (hwfocus == ctl) {
            int count = 0;

            hwfocus = NULL;
            do {
                hwfocus = GetNextDlgTabItem(dlg, hwfocus, FALSE);
                count ++;
            } while(hwfocus == ctl && count < 2);

            SendMessage(dlg, WM_NEXTDLGCTL, (WPARAM) hwfocus, MAKELPARAM(TRUE, 0));
        }

        EnableWindow(ctl, FALSE);
    }
}

void
dlg_enable_certs(struct nc_dialog_data * d, BOOL enable, BOOL update_control) {

    if (!!d->enabled != !!enable) {
        d->enabled = !!enable;
        d->dirty = TRUE;
    }

    safe_enable_window(d->hwnd, IDC_NC_CERTLIST, enable);
    safe_enable_window(d->hwnd, IDC_NC_REALM, enable);
    safe_enable_window(d->hwnd, IDC_NC_HOSTS, enable);
    safe_enable_window(d->hwnd, IDC_NC_ADDREALM, enable);
    safe_enable_window(d->hwnd, IDC_NC_DELREALM, enable);

    if (update_control) {
        CheckDlgButton(d->hwnd, IDC_NC_ENABLE, (enable ? BST_CHECKED : BST_UNCHECKED));
    }

#if KH_VERSION_API < 12
    if (d->nc) {
        PostMessage(d->nc->hwnd, KHUI_WM_NC_NOTIFY,
                    MAKEWPARAM(0, WMNC_UPDATE_CREDTEXT),
                    (LPARAM) d->nc);
    }
#endif
}

void
dlg_add_cert(struct nc_dialog_data * d) {

    enum kca_host_method method = KCA_HOST_AUTO;
    struct nc_cert * cert;
    wchar_t realm[KCA_MAXCCH_REALM];
    wchar_t hosts[KCA_MAXCCH_HOST * KCA_MAX_HOSTS];
    khm_size n_certs = 0;
    khm_size cert_idx = 0;
    HWND hw_list;
    int idx = -1;

    realm[0] = L'\0';
    GetDlgItemText(d->hwnd, IDC_NC_REALM, realm, ARRAYLENGTH(realm));
    hosts[0] = L'\0';
    GetDlgItemText(d->hwnd, IDC_NC_HOSTS, hosts, ARRAYLENGTH(hosts));

    method = certset_get_method(realm, hosts);

    n_certs = d->certset.n_certs;

    cert_idx = certset_add_cert(&d->certset, method, realm, hosts);
    cert = certset_get_cert(&d->certset, cert_idx);

    hw_list = GetDlgItem(d->hwnd, IDC_NC_CERTLIST);

    if (cert_idx < n_certs) {
        /* we updated an existing certificate. */
        LVFINDINFO lvfi;

        ZeroMemory(&lvfi, sizeof(lvfi));

        lvfi.flags = LVFI_PARAM;
        lvfi.lParam = (LPARAM) cert_idx;

        idx = ListView_FindItem(hw_list, -1, &lvfi);
#ifdef DEBUG
        assert(idx >= 0);
#endif
    }

    dlg_certlist_add_item(d, hw_list, cert, cert_idx, idx);

    d->dirty = TRUE;
    d->certset_changed = TRUE;
}

void
dlg_del_cert(struct nc_dialog_data * d) {

    wchar_t txt_realm[KCA_MAXCCH_REALM];
    wchar_t txt_hosts[KCA_MAXCCH_HOST * KCA_MAX_HOSTS];
    const wchar_t * eff_realm = NULL;
    enum kca_host_method method;
    khm_size i;

    txt_realm[0] = L'\0';
    GetDlgItemText(d->hwnd, IDC_NC_REALM, txt_realm, ARRAYLENGTH(txt_realm));
    txt_hosts[0] = L'\0';
    GetDlgItemText(d->hwnd, IDC_NC_HOSTS, txt_hosts, ARRAYLENGTH(txt_hosts));

    method = certset_get_method(txt_realm, txt_hosts);
    eff_realm = certset_get_eff_realm(method, txt_realm, d->certset.identity_realm);

#ifdef DEBUG
    assert(eff_realm != NULL);
#endif

    if (eff_realm == NULL)
        return;

    for (i=0; i < d->certset.n_certs; i++) {
        const wchar_t * cert_realm;

        cert_realm = certset_get_cert_eff_realm(&d->certset, i);
#ifdef DEBUG
        assert(cert_realm != NULL);
#endif
        if (!wcscmp(cert_realm, eff_realm))
            break;
    }

    if (i >= d->certset.n_certs)
        return;                 /* a matching certificate was not found */

    certset_del_cert(&d->certset, i);

    {
        HWND hw_list;
        LVFINDINFO lvfi;
        LVITEM lvi;
        int idx;

        hw_list = GetDlgItem(d->hwnd, IDC_NC_CERTLIST);
#ifdef DEBUG
        assert(hw_list != NULL);
#endif
        if (hw_list == NULL)
            return;

        ZeroMemory(&lvfi, sizeof(lvfi));
        ZeroMemory(&lvi, sizeof(lvi));

        lvfi.flags = LVFI_PARAM;
        lvfi.lParam = (LPARAM) i;

        idx = ListView_FindItem(hw_list, -1, &lvfi);
#ifdef DEBUG
        assert(idx >= 0);
#endif
        if (idx < 0)
            return;

        ListView_DeleteItem(hw_list, idx);

        for (; i < d->certset.n_certs; i++) {
            lvfi.lParam = (LPARAM) i + 1;
            idx = ListView_FindItem(hw_list, -1, &lvfi);
#ifdef DEBUG
            assert(idx >= 0);
#endif
            if (idx < 0)
                continue;

            lvi.mask = LVIF_PARAM;
            lvi.iItem = idx;
            lvi.iSubItem = 0;
            lvi.lParam = (LPARAM) i;

            ListView_SetItem(hw_list, &lvi);
        }
    }

    d->dirty = TRUE;
    d->certset_changed = TRUE;
}

BOOL
dlg_open_ident_handle(khm_handle ident,
                      khm_int32 flags,
                      struct dlg_ident_handle * h,
                      wchar_t * realm,
                      khm_size cb_realm) {

    khm_handle csp_realms = NULL;
    khm_handle csp_ident = NULL;
    wchar_t idname[KCDB_IDENT_MAXCCH_NAME];
    wchar_t * prealm = NULL;
    khm_size cb;

    cb = sizeof(idname);

    ZeroMemory(h, sizeof(*h));

    if (ident) {
        wchar_t * atsign;

        if (KHM_SUCCEEDED(kcdb_identity_get_name(ident, idname, &cb)) &&
            (atsign = wcsrchr(idname, L'@')) != NULL) {

            prealm = atsign + 1;

            if (realm && *prealm) {
                StringCbCopy(realm, cb_realm, prealm);
            }
        }
    }

    h->csp_all = csp_params;

    if (prealm && *prealm &&
        KHM_SUCCEEDED(khc_open_space(csp_params, L"Realms", 0,
                                     &csp_realms)) &&
        KHM_SUCCEEDED(khc_open_space(csp_realms, prealm, 0,
                                     &h->csp_realm))) {
        khc_shadow_space(h->csp_realm, h->csp_all);
        h->csp_all = h->csp_realm;
    }

    if (ident &&
        KHM_SUCCEEDED(kcdb_identity_get_config(ident, flags, &csp_ident)) &&
        KHM_SUCCEEDED(khc_open_space(csp_ident, MYCREDTYPE_NAMEW, flags,
                                     &h->csp_idkca))) {
        khc_shadow_space(h->csp_idkca, h->csp_all);
        h->csp_all = h->csp_idkca;
    }

    if (csp_realms)
        khc_close_space(csp_realms);

    if (csp_ident)
        khc_close_space(csp_ident);

    return (h->csp_all != NULL);
}

void
dlg_close_ident_handle(struct dlg_ident_handle * h) {
    if (h->csp_idkca)
        khc_close_space(h->csp_idkca);

    if (h->csp_realm)
        khc_close_space(h->csp_realm);

    ZeroMemory(h, sizeof(*h));
}

static int
add_certs_from_csp(struct nc_cert_set * certset,
                   khm_handle csp) {
    enum kca_host_method method;
    wchar_t hosts[KCA_MAXCCH_HOST * KCA_MAX_HOSTS];
    wchar_t realm[KCA_MAXCCH_REALM];

    wchar_t valuename[12];
    wchar_t value[ARRAYLENGTH(hosts) + ARRAYLENGTH(realm) + 16];
    khm_size cb;

    int i;
    khm_int32 count;

    if (KHM_FAILED(khc_read_int32(csp, L"NCerts", &count)))
        return 0;

    for (i = 0; i < count; i++) {
        if (FAILED(StringCbPrintf(valuename, sizeof(valuename), L"Cert_%d", i)))
            break;

        cb = sizeof(value);
        if (KHM_FAILED(khc_read_string(csp, valuename, value, &cb)))
            continue;

        parse_cert_string(value,
                          &method,
                          realm, sizeof(realm),
                          hosts, sizeof(hosts));

        certset_add_cert(certset, method, realm, hosts);
    }

    return 1;
}

void
dlg_load_identity_params(struct nc_dialog_data * d,
                         khm_handle ident) {

    struct dlg_ident_handle h;
    khm_int32 t;
    khm_size cb;
    khm_handle tident = NULL;

    h.csp_all = NULL;

    certset_destroy(&d->certset);
    certset_init(&d->certset);

    /* look up the values from csp_parms */
    StringCbCopy(d->certset.identity_realm, sizeof(d->certset.identity_realm), L"");

    /* this can be called with ident == NULL, in which case we try to
       use the identity specified as the primary identity in d->nc. */
    if ((ident == NULL ||
         !dlg_open_ident_handle(ident, 0, &h,
                                d->certset.identity_realm,
                                sizeof(d->certset.identity_realm))) &&
        (d->nc == NULL ||
	 KHM_FAILED(khui_cw_get_primary_id(d->nc, &tident)) ||
         !dlg_open_ident_handle(tident, 0, &h,
                                d->certset.identity_realm,
                                sizeof(d->certset.identity_realm)))) {

        if (!dlg_open_ident_handle(NULL, 0, &h, NULL, 0)) {
            h.csp_all = NULL;
        }
    }

    if (tident != NULL) {
	kcdb_identity_release(tident);
	tident = NULL;
    }

    if (h.csp_all == NULL) {
        d->enabled = FALSE;

        certset_add_cert(&d->certset, KCA_HOST_AUTO, NULL, NULL);
    } else {
        int found_certs = 0;

        if (KHM_SUCCEEDED(khc_read_int32(h.csp_all, L"KCAEnabled", &t))) {
            d->enabled = !!t;
        } else {
            d->enabled = TRUE;
        }

        found_certs = add_certs_from_csp(&d->certset, h.csp_all);

        /* import legacy data, only if we couldn't find the new
           keys. */

        if (!found_certs) {
            enum kca_host_method method;
            wchar_t hosts[KCA_MAXCCH_HOST * KCA_MAX_HOSTS];
            wchar_t realm[KCA_MAXCCH_REALM];

            if (KHM_SUCCEEDED(khc_read_int32(h.csp_all, L"KCAHostMethod", &t)) &&
                (t == KCA_HOST_AUTO || t == KCA_HOST_MANUAL || t == KCA_HOST_REALM)) {
                method = t;

                if (method == KCA_HOST_MANUAL) {
                    cb = sizeof(hosts);
                    if (KHM_FAILED(khc_read_string(h.csp_all, L"KCAHosts",
                                                   hosts, &cb))) {
                        hosts[0] = L'\0';
                    }
                } else {
                    hosts[0] = L'\0';
                }

                if (method == KCA_HOST_REALM) {
                    cb = sizeof(realm);
                    if (KHM_FAILED(khc_read_string(h.csp_all, L"KCARealm",
                                                   realm, &cb)))
                        realm[0] = L'\0';
                } else {
                    realm[0] = L'\0';
                }

                certset_add_cert(&d->certset, method, realm, hosts);
            }
        }

        dlg_close_ident_handle(&h);
    }

    d->dirty = FALSE;
    d->certset_changed = FALSE;
}

void
dlg_save_identity_params(struct nc_dialog_data * d) {
    struct dlg_ident_handle h;
    khm_size i;
    khm_handle ident = NULL;

    if (!d->dirty)
        return;

    if ((d->ident == NULL ||
         !dlg_open_ident_handle(d->ident,
                                KHM_FLAG_CREATE | KCONF_FLAG_WRITEIFMOD,
                                &h, NULL, 0))

        &&

        (d->nc == NULL ||
	 KHM_FAILED(khui_cw_get_primary_id(d->nc, &ident)) ||
         !dlg_open_ident_handle(ident,
                                KHM_FLAG_CREATE | KCONF_FLAG_WRITEIFMOD,
                                &h, NULL, 0))

        &&

        !dlg_open_ident_handle(NULL, KHM_FLAG_CREATE | KCONF_FLAG_WRITEIFMOD,
                               &h, NULL, 0)) {

	if (ident != NULL)
	    kcdb_identity_release(ident);
        return;
    }

    if (ident != NULL) {
	kcdb_identity_release(ident);
	ident = NULL;
    }

    khc_write_int32(h.csp_all, L"KCAEnabled", d->enabled);

    khc_write_int32(h.csp_all, L"NCerts", (khm_int32)d->certset.n_certs);

    for (i=0; i < d->certset.n_certs; i++) {
        struct nc_cert * cert;
        wchar_t buffer[KCA_MAXCCH_REALM + KCA_MAXCCH_HOST * KCA_MAX_HOSTS + 16];
        wchar_t valuename[12];

        cert = certset_get_cert(&d->certset, i);
        if (cert == NULL)
            continue;

        unparse_cert_string(buffer, sizeof(buffer),
                            cert->kca_host_method,
                            cert->kca_realm,
                            cert->kca_hosts);

        if (FAILED(StringCbPrintf(valuename, sizeof(valuename), L"Cert_%d", (int) i)))
            break;

        khc_write_string(h.csp_all, valuename, buffer);
    }

    dlg_close_ident_handle(&h);

    d->dirty = FALSE;
    d->certset_changed = FALSE;
}

INT_PTR
dlg_handle_wm_notify(struct nc_dialog_data * d, WPARAM wParam, LPARAM lParam) {
    LPNMHDR pnmh;

    pnmh = (LPNMHDR) lParam;

    switch(pnmh->code) {
    case LVN_BEGINLABELEDIT:
        {
            NMLVDISPINFO * pdi;
            LVITEM lvi;
            HWND hw_list;
            HWND hw_edit;
            khm_size idx_cert;
            struct nc_cert * cert;
            const wchar_t * realm;

            pdi = (NMLVDISPINFO *) pnmh;

            hw_list = GetDlgItem(d->hwnd, IDC_NC_CERTLIST);
#ifdef DEBUG
            assert(hw_list);
#endif
            if (!hw_list)
                goto disallow_labeledit;

            ZeroMemory(&lvi, sizeof(lvi));
            lvi.iItem = pdi->item.iItem;
            lvi.mask = LVIF_PARAM;

            if (!ListView_GetItem(hw_list, &lvi))
                goto disallow_labeledit;

            idx_cert = (khm_size) lvi.lParam;

            cert = certset_get_cert(&d->certset, idx_cert);
#ifdef DEBUG
            assert(cert);
#endif
            if (cert == NULL)
                goto disallow_labeledit;

            realm = certset_get_cert_eff_realm(&d->certset, idx_cert);
            if (realm == NULL)
                realm = L"";

            hw_edit = ListView_GetEditControl(hw_list);
#ifdef DEBUG
            assert(hw_edit);
#endif
            if (hw_edit == NULL)
                goto disallow_labeledit;

            SetWindowText(hw_edit, realm);
            SendMessage(hw_edit, EM_SETLIMITTEXT, KCA_MAXCCH_REALM, 0);

            SetWindowLongPtr(d->hwnd, DWLP_MSGRESULT, FALSE);
            return TRUE;

        disallow_labeledit:
            SetWindowLongPtr(d->hwnd, DWLP_MSGRESULT, TRUE);
        }
        break;

    case LVN_ENDLABELEDIT:
        {
            NMLVDISPINFO * pdi;
            LVITEM lvi;
            khm_size idx_cert;
            khm_size i;
            struct nc_cert * cert;
            HWND hw_list;
            const wchar_t * new_realm;
            enum kca_host_method new_method;

            pdi = (NMLVDISPINFO *) pnmh;

            /* if the user cancelled the operation, then pszText would
               be NULL and we have nothing to do. */
            if (pdi->item.pszText == NULL)
                break;

            hw_list = GetDlgItem(d->hwnd, IDC_NC_CERTLIST);
#ifdef DEBUG
            assert(hw_list);
#endif
            if (!hw_list)
                goto disallow_newlabel;

            ZeroMemory(&lvi, sizeof(lvi));
            lvi.iItem = pdi->item.iItem;
            lvi.mask = LVIF_PARAM;

            if (!ListView_GetItem(hw_list, &lvi))
                goto disallow_newlabel;

            idx_cert = (khm_size) lvi.lParam;
            cert = certset_get_cert(&d->certset, idx_cert);
#ifdef DEBUG
            assert(cert);
#endif
            if (cert == NULL)
                goto disallow_newlabel;

            if (!wcscmp(cert->kca_realm, pdi->item.pszText))
                /* we aren't really disallowing this operation, but
                   rather, the operation is a no-op. */
                goto disallow_newlabel;

            new_method = certset_get_method(pdi->item.pszText, cert->kca_hosts);
            new_realm = certset_get_eff_realm(new_method,
                                              pdi->item.pszText,
                                              d->certset.identity_realm);

            for (i=0; i < d->certset.n_certs; i++) {
                const wchar_t * eff_realm;

                eff_realm = certset_get_cert_eff_realm(&d->certset, i);
                if (eff_realm == NULL)
                    continue;

                if (!wcscmp(eff_realm, new_realm)) {
                    break;
                }
            }

            if (i < d->certset.n_certs) {
                /* a certifcate for the realm already exists. we only
                   allow one certificate per-realm. */

                wchar_t message[KHUI_MAXCCH_MESSAGE];
                wchar_t msg_fmt[KHUI_MAXCCH_TITLE];
                wchar_t title[KHUI_MAXCCH_TITLE];

                LoadString(hResModule, IDS_NC_MSGTITLE, title, ARRAYLENGTH(title));
                LoadString(hResModule, IDS_NC_CANTRENAME, msg_fmt, ARRAYLENGTH(msg_fmt));
                StringCbPrintf(message, sizeof(message), msg_fmt, new_realm);

                MessageBox(d->hwnd, message, title, MB_OK);

                goto disallow_newlabel;
            }

            cert->kca_host_method = new_method;
            StringCbCopy(cert->kca_realm, sizeof(cert->kca_realm), pdi->item.pszText);

            dlg_certlist_add_item(d, hw_list, cert, idx_cert, pdi->item.iItem);

            /* we return FALSE to the LISTVIEW control because we
               already set the certficate text above.  We don't allow
               the LISTVIEW to set it because the actual text we want
               to be displayed may not be what's contained in
               pszText. */
            SetWindowLongPtr(d->hwnd, DWLP_MSGRESULT, FALSE);
            break;

        disallow_newlabel:
            SetWindowLongPtr(d->hwnd, DWLP_MSGRESULT, FALSE);
        }
        break;

    case LVN_ITEMCHANGED:
        {
            HWND hw_list;
            int selcount;

            hw_list = GetDlgItem(d->hwnd, IDC_NC_CERTLIST);

            selcount = ListView_GetSelectedCount(hw_list);

            if (selcount == 1) {
                int idx_sel;
                LVITEM lvi;
                khm_size idx_cert;
                struct nc_cert * cert;

                idx_sel = ListView_GetNextItem(hw_list, -1, LVNI_SELECTED);
#ifdef DEBUG
                assert(idx_sel >= 0);
#endif
                if (idx_sel < 0)
                    goto done_with_item_activate;

                ZeroMemory(&lvi, sizeof(lvi));

                lvi.mask = LVIF_PARAM;
                lvi.iItem = idx_sel;
                lvi.iSubItem = 0;

                if (!ListView_GetItem(hw_list, &lvi))
                    goto done_with_item_activate;

                idx_cert = (khm_size) lvi.lParam;

                cert = certset_get_cert(&d->certset, idx_cert);

#ifdef DEBUG
                assert(cert);
#endif
                if (cert == NULL)
                    goto done_with_item_activate;

                if (cert->kca_host_method == KCA_HOST_AUTO) {

                    SetDlgItemText(d->hwnd, IDC_NC_REALM, L"");
                    SetDlgItemText(d->hwnd, IDC_NC_HOSTS, L"");

                } else if (cert->kca_host_method == KCA_HOST_REALM) {

                    SetDlgItemText(d->hwnd, IDC_NC_REALM, cert->kca_realm);
                    SetDlgItemText(d->hwnd, IDC_NC_HOSTS, L"");

                } else {

                    SetDlgItemText(d->hwnd, IDC_NC_REALM, cert->kca_realm);
                    SetDlgItemText(d->hwnd, IDC_NC_HOSTS, cert->kca_hosts);

                }
            }

        done_with_item_activate:

            SetWindowLongPtr(d->hwnd, DWLP_MSGRESULT, 0);
        }
        break;
    }

    return TRUE;
}

INT_PTR
dlg_handle_wm_command(struct nc_dialog_data * d, WPARAM wParam, LPARAM lParam) {
    switch(wParam) {
    case MAKEWPARAM(IDC_NC_ADDREALM, BN_CLICKED):
        dlg_add_cert(d);
        break;

    case MAKEWPARAM(IDC_NC_DELREALM, BN_CLICKED):
        dlg_del_cert(d);
        break;

    case MAKEWPARAM(IDC_NC_ENABLE, BN_CLICKED):
        {
            BOOL enable;

            enable = (IsDlgButtonChecked(d->hwnd, IDC_NC_ENABLE) == BST_CHECKED);

            dlg_enable_certs(d, enable, FALSE);
        }
        break;
    }

    return TRUE;
}

/* Note: This callback runs under the UI thread */
INT_PTR
handle_wm_initdialog(HWND hwnd, WPARAM wParam, LPARAM lParam) {
    khui_new_creds * nc = NULL;
    khui_new_creds_by_type * nct = NULL;
    struct nc_dialog_data * d = NULL;

    nc = (khui_new_creds *) lParam;
    khui_cw_find_type(nc, credtype_id, &nct);

    assert(nct);

    d = malloc(sizeof(*d));
    ZeroMemory(d, sizeof(*d));

    d->nc = nc;
    d->nct = nct;

    d->hwnd = hwnd;

#pragma warning(push)
#pragma warning(disable: 4244)
    SetWindowLongPtr(hwnd, DWLP_USER, (LPARAM) d);
#pragma warning(pop)

    nct->aux = (LPARAM) d;      /* we can use the auxiliary field to
                                   hold a pointer to d */

    d->enabled = FALSE;         /* don't enable until we get an identity */

    certset_init(&d->certset);

    dlg_init(d);

    return FALSE;
}

/* Note: This callback runs under the UI thread */
static
INT_PTR
handle_khui_wm_nc_notify(HWND hwnd, WPARAM wParam, LPARAM lParam) {

    struct nc_dialog_data * d;

    /* Refer to the khui_wm_nc_notifications enumeration in the
       NetIDMgr SDK for the full list of notification messages that
       can be sent. */

    d = (struct nc_dialog_data *) GetWindowLongPtr(hwnd, DWLP_USER);

    if (!d)
        return TRUE;

    /* these should be set by now */
    assert(d->nc);
    assert(d->nct);

    switch (HIWORD(wParam)) {
#if KH_VERSION_API < 12
    case WMNC_UPDATE_CREDTEXT:
        {
            wchar_t tpl_fmt[KHUI_MAXCCH_SHORT_DESC];
            wchar_t msg_fmt[KHUI_MAXCCH_SHORT_DESC];
            wchar_t msg[KHUI_MAXCCH_SHORT_DESC];
            khm_int32 flags = 0;
	    khm_handle ident = NULL;

            assert(d->nct->credtext);

            /* do not add a custom credential text string if there is
               no valid identity selected. */
            if (!d->nc ||
		KHM_FAILED(khui_cw_get_primary_id(d->nc, &ident)) ||
                KHM_FAILED(kcdb_identity_get_flags(ident,
                                                   &flags)) ||
                !(flags & KCDB_IDENT_FLAG_VALID)) {

		if (ident)
		    kcdb_identity_release(ident);

                StringCbCopy(d->nct->credtext, KHUI_MAXCB_LONG_DESC,
                             L"");
                break;

            }

	    if (ident) {
		kcdb_identity_release(ident);
		ident = NULL;
	    }

            /* we are being requested to update the credentials
               text. We already allocated a buffer when we created the
               nct structure.  So we can just set the text here.*/

            LoadString(hResModule, IDS_NC_CT_TEMPLATE,
                       tpl_fmt, ARRAYLENGTH(tpl_fmt));

            if (d->enabled) {

                if (d->certset.n_certs == 0) {
                    LoadString(hResModule, IDS_NC_CT_CERT_0,
                               msg, ARRAYLENGTH(msg));
                } else if (d->certset.n_certs == 1) {
                    LoadString(hResModule, IDS_NC_CT_CERT_1,
                               msg_fmt, ARRAYLENGTH(msg_fmt));
                    StringCbPrintf(msg, sizeof(msg), msg_fmt,
                                   certset_get_cert_eff_realm(&d->certset, 0));
                } else {
                    wchar_t realmlist[128];
                    khm_size i;

                    realmlist[0] = L'\0';
                    for (i=0; i < d->certset.n_certs; i++) {
                        if (i)
                            StringCbCat(realmlist, sizeof(realmlist), L",");
                        if (FAILED(StringCbCat(realmlist, sizeof(realmlist),
                                               certset_get_cert_eff_realm(&d->certset, i))))
                            break;
                    }

                    LoadString(hResModule, IDS_NC_CT_CERT_N,
                               msg_fmt, ARRAYLENGTH(msg_fmt));
                    StringCbPrintf(msg, sizeof(msg), msg_fmt, realmlist);
                }
            } else {
                LoadString(hResModule, IDS_NC_CT_DISABLED,
                           msg, ARRAYLENGTH(msg));
            }

            StringCbPrintf(d->nct->credtext, KHUI_MAXCB_LONG_DESC,
                           tpl_fmt, msg);
        }
        break;

    case WMNC_CREDTEXT_LINK:
        {
            khui_htwnd_link * l = (khui_htwnd_link *) lParam;

#define ENABLELINK MYCREDTYPE_NAMEW L":Enable"

            if (l == NULL)
                break;

            if (!wcsncmp(l->id, ENABLELINK, ARRAYLENGTH(ENABLELINK) - 1)) {
                dlg_enable_certs(d, TRUE, TRUE);
            }

#undef  ENABLELINK

        }
        break;
#endif  /* KH_VERSION_API < 12 */

    case WMNC_IDENTITY_CHANGE:
        {
	    khm_handle ident = NULL;

	    khui_cw_get_primary_id(d->nc, &ident);

            dlg_load_identity_params(d, ident);
            dlg_enable_certs(d, d->enabled, TRUE);
            dlg_init(d);

	    if (ident)
		kcdb_identity_release(ident);
        }
        break;

    case WMNC_DIALOG_PREPROCESS:
        {
            /* nothing to do */
        }
        break;
    }

    return TRUE;
}

/* Note: This callback runs under the UI thread */
static
INT_PTR
handle_wm_notify(HWND hwnd, WPARAM wParam, LPARAM lParam) {
    struct nc_dialog_data * d;

    d = (struct nc_dialog_data *) GetWindowLongPtr(hwnd, DWLP_USER);

    if (d == NULL)
        return 0;

    return dlg_handle_wm_notify(d, wParam, lParam);
}

/* Note: This callback runs under the UI thread */
static
INT_PTR
handle_wm_command(HWND hwnd, WPARAM wParam, LPARAM lParam) {

    struct nc_dialog_data * d;
    INT_PTR rv;

    d = (struct nc_dialog_data *) GetWindowLongPtr(hwnd, DWLP_USER);

    if (d == NULL)
        return 0;

    rv = dlg_handle_wm_command(d, wParam, lParam);

    if (d->certset_changed) {
#if KH_VERSION_API < 12
        PostMessage(d->nc->hwnd, KHUI_WM_NC_NOTIFY,
                    MAKEWPARAM(0, WMNC_UPDATE_CREDTEXT),
                    (LPARAM) d->nc);
#endif
        d->certset_changed = FALSE;
    }

    return rv;
}

/* Note: This callback runs under the UI thread */
static
INT_PTR
handle_wm_destroy(HWND hwnd, WPARAM wParam, LPARAM lParam) {

    struct nc_dialog_data * d;

    d = (struct nc_dialog_data *) GetWindowLongPtr(hwnd, DWLP_USER);

    if (d) {
        d->nc = NULL;
        d->nct = NULL;

        certset_destroy(&d->certset);

        free(d);

        SetWindowLongPtr(hwnd, DWLP_USER, 0);
    }

    return FALSE;
}

DWORD popup_map[] = {
    IDC_NC_ENABLE, IDH_NC_ENABLE,
    IDC_NC_CERTLIST, IDH_NC_CERTLIST,
    IDC_NC_REALM, IDH_NC_REALM,
    IDC_NC_HOSTS, IDH_NC_HOSTS,
    IDC_NC_USEIDREALM, IDH_NC_USEIDREALM,
    IDC_NC_ADDREALM, IDH_NC_ADDREALM,
    IDC_NC_DELREALM, IDH_NC_DELREALM,

    0, 0
};

void
get_help_file(wchar_t * path, khm_size cbpath) {

    assert(cbpath >= MAX_PATH * sizeof(wchar_t));

    StringCbCopy(path, cbpath, module_path);
    PathAppend(path, HELPFILE_NAME);
}

/* Note: This callback runs under the UI thread */
INT_PTR
handle_wm_help(HWND hwnd, WPARAM wParam, LPARAM lParam) {
    HELPINFO * hlp;
    HWND hw_help = NULL;
    HWND hw_ctrl = NULL;
    wchar_t helploc[MAX_PATH + MAX_PATH];

    hlp = (HELPINFO *) lParam;

    if (hlp->hItemHandle != NULL &&
        hlp->hItemHandle != hwnd) {
        DWORD id;
        int i;

        hw_ctrl = hlp->hItemHandle;

        id = GetWindowLong(hw_ctrl, GWL_ID);
        for (i=0; popup_map[i] != 0; i += 2) {
            if (popup_map[i] == id)
                break;
        }

        if (popup_map[i] != 0) {

            get_help_file(helploc, sizeof(helploc));

            StringCbCat(helploc, sizeof(helploc), L"::ncpopups.txt");

            hw_help = HtmlHelp(hw_ctrl, helploc, HH_TP_HELP_WM_HELP,
                               (DWORD_PTR) popup_map);
        }
    }

    if (hw_help == NULL) {
        get_help_file(helploc, sizeof(helploc));

        HtmlHelp(hwnd, helploc, HH_HELP_CONTEXT, IDH_NC_CTX);
    }

    return TRUE;
}

/* Dialog procedure for the new credentials panel for our credentials
   type.  We just dispatch messages here to other functions here.

   Note that this procedure runs under the UI thread.
 */
INT_PTR CALLBACK
nc_dlg_proc(HWND hwnd,
            UINT uMsg,
            WPARAM wParam,
            LPARAM lParam) {

    switch (uMsg) {
    case WM_INITDIALOG:
        return handle_wm_initdialog(hwnd, wParam, lParam);

    case WM_COMMAND:
        return handle_wm_command(hwnd, wParam, lParam);

    case WM_HELP:
        return handle_wm_help(hwnd, wParam, lParam);

    case WM_NOTIFY:
        return handle_wm_notify(hwnd, wParam, lParam);

    case KHUI_WM_NC_NOTIFY:
        return handle_khui_wm_nc_notify(hwnd, wParam, lParam);

    case WM_DESTROY:
        return handle_wm_destroy(hwnd, wParam, lParam);

        /* TODO: add code for handling other windows messages here. */
    }

    return FALSE;
}

/*******************************************************************

The following section contains function stubs for each of the
credentials messages that a credentials provider is likely to want to
handle.  It doesn't include a few messages, but they should be easy to
add.  Please see the documentation for each of the KMSG_CRED_*
messages for documentation on how to handle each of the messages.

********************************************************************/


/* Handler for KMSG_CRED_NEW_CREDS */
khm_int32
handle_kmsg_cred_new_creds(khui_new_creds * nc) {

    wchar_t wshortdesc[KHUI_MAXCCH_SHORT_DESC];
    size_t cb = 0;
    khui_new_creds_by_type * nct = NULL;
    khm_int32 k5_credtype = KCDB_CREDTYPE_INVALID;

    /* This is a minimal handler that just adds a dialog pane to the
       new credentials window to handle new credentials acquisition
       for this credentials type. */

    /* TODO: add additional initialization etc. as needed */

    nct = malloc(sizeof(*nct));
    ZeroMemory(nct, sizeof(*nct));

    nct->type = credtype_id;
    nct->ordinal = SIZE_MAX;

    LoadString(hResModule, IDS_CT_SHORT_DESC,
               wshortdesc, ARRAYLENGTH(wshortdesc));
    StringCbLength(wshortdesc, sizeof(wshortdesc), &cb);
#ifdef DEBUG
    assert(cb > 0);
#endif
    cb += sizeof(wchar_t);

    nct->name = malloc(cb);
    StringCbCopy(nct->name, cb, wshortdesc);

    /* while we are at it, we should also allocate space for the
       credential text. */
    nct->credtext = malloc(KHUI_MAXCB_LONG_DESC);
    ZeroMemory(nct->credtext, KHUI_MAXCB_LONG_DESC);

    nct->h_module = hResModule;
    nct->dlg_proc = nc_dlg_proc;
    nct->dlg_template = MAKEINTRESOURCE(IDD_NEW_CREDS);

    /* we depend on Krb5 */

    if (KHM_SUCCEEDED(kcdb_credtype_get_id(L"Krb5Cred", &k5_credtype))) {

        nct->n_type_deps = 1;
        nct->type_deps[0] = k5_credtype;

    } else {

        /* Actually we can't proceed if we can't look up the Krb5
           credentials provider. */

#ifdef DEBUG
        assert(FALSE);
#endif

        if (nct->credtext)
            free(nct->credtext);
        if (nct->name)
            free(nct->name);

        free(nct);

        return KHM_ERROR_SUCCESS;
    }

    khui_cw_add_type(nc, nct);

    return KHM_ERROR_SUCCESS;
}

/* Handler for KMSG_CRED_RENEW_CREDS */
khm_int32
handle_kmsg_cred_renew_creds(khui_new_creds * nc) {

    khui_new_creds_by_type * nct;
    khm_int32 k5_credtype;

    /* This is a minimal handler that just adds this credential type
       to the list of credential types that are participating in this
       renewal operation. */

    /* TODO: add additional initialization etc. as needed */

    nct = malloc(sizeof(*nct));
    ZeroMemory(nct, sizeof(*nct));

    nct->type = credtype_id;

    if (KHM_SUCCEEDED(kcdb_credtype_get_id(L"Krb5Cred", &k5_credtype))) {

        nct->n_type_deps = 1;
        nct->type_deps[0] = k5_credtype;

    } else {
        /* we can't proceed without the Krb5 credentials provider. */
#ifdef DEBUG
        assert(FALSE);
#endif

        free(nct);
        return KHM_ERROR_SUCCESS;

    }

    khui_cw_add_type(nc, nct);

    return KHM_ERROR_SUCCESS;
}

/* Handler for KMSG_CRED_DIALOG_PRESTART */
khm_int32
handle_kmsg_cred_dialog_prestart(khui_new_creds * nc) {
    /* TODO: Handle this message */

    /* The message is sent after the dialog has been created.  The
       window handle for the created dialog can be accessed through
       the hwnd_panel member of the khui_new_creds_by_type structure
       that was added for this credentials type. */
    return KHM_ERROR_SUCCESS;
}

/* Handler for KMSG_CRED_DIALOG_NEW_IDENTITY */
/* Not a message sent out by NetIDMgr.  See documentation of
   KMSG_CRED_DIALOG_NEW_IDENTITY  */
khm_int32
handle_kmsg_cred_dialog_new_identity(khm_ui_4 uparam,
                                     void *   vparam) {
    /* TODO: Handle this message */
    return KHM_ERROR_SUCCESS;
}

/* Handler for KMSG_CRED_DIALOG_NEW_OPTIONS */
/* Not a message sent out by NetIDMgr.  See documentation of
   KMSG_CRED_DIALOG_NEW_OPTIONS */
khm_int32
handle_kmsg_cred_dialog_new_options(khm_ui_4 uparam,
                                    void *   vparam) {
    /* TODO: Handle this message */
    return KHM_ERROR_SUCCESS;
}

/* Handler for KMSG_CRED_PROCESS */
khm_int32
handle_kmsg_cred_process(khui_new_creds * nc) {

    khui_new_creds_by_type * nct = NULL;
    khm_int32 k5_credtype = KCDB_CREDTYPE_INVALID;
    wchar_t   wccname[260];
    char      ccname[260];
    khm_size  cb;

    RSA       *rsa = NULL;
    int        keybits = DEFBITS;
    X509      *cert = NULL;

    BYTE      *privKey = NULL;
    DWORD     cbPrivKey = 0;
    char      realm[260];

    char      err_buf[256];

    /*  */
    int       xerr = 0;
    char      der_buf[4096];
    char      *pder_buf = der_buf;
    int       cb_der;
    khm_handle ident = NULL;

    struct nc_dialog_data tmp_data;
    struct nc_dialog_data * d;
    struct nc_cert * nc_cert;
    khm_size i;

    char      hostlist[ARRAYLENGTH(nc_cert->kca_hosts)];

    wchar_t * container = NULL;

    int n_failed = 0;
    int certs_cleaned = 0;

    /* This is where the credentials acquisition should be performed
       as determined by the UI.  Note that this message is sent even
       when the user clicks 'cancel'.  The value of nc->result should
       be checked before performing any credentials acquisition.  If
       the value is KHUI_NC_RESULT_CANCEL, then no credentials should
       be acquired.  Otherwise, the value would be
       KHUI_NC_RESULT_PROCESS. */

    khui_cw_find_type(nc, credtype_id, &nct);

    /* mmkay */
    if (!nct)
        return KHM_ERROR_SUCCESS;

    d = (struct nc_dialog_data *) nct->aux;
    ZeroMemory(&tmp_data, sizeof(tmp_data));
    certset_init(&tmp_data.certset);

    if (khui_cw_get_result(nc) == KHUI_NC_RESULT_CANCEL) {
        khui_cw_set_response(nc, credtype_id,
                             KHUI_NC_RESPONSE_SUCCESS |
                             KHUI_NC_RESPONSE_EXIT);
        return KHM_ERROR_SUCCESS;
    }

    if (khui_cw_get_result(nc) != KHUI_NC_RESULT_PROCESS) {
        return KHM_ERROR_UNKNOWN;
    }

    /* if this is a renewal, make sure we are supposed to renew a
       cert. */

    if (khui_cw_get_subtype(nc) == KMSG_CRED_RENEW_CREDS) {

        khui_action_context * ctx;

        _begin_task(0);
        _report_cs0(KHERR_DEBUG_1, L"Renewing KCA Cert");
        _describe();

        ctx = khui_cw_get_ctx(nc);

        if (ctx != NULL &&
            (ctx->scope == KHUI_SCOPE_IDENT ||
             (ctx->scope == KHUI_SCOPE_CREDTYPE &&
              ctx->cred_type == credtype_id) ||
             (ctx->scope == KHUI_SCOPE_CRED &&
              ctx->cred_type == credtype_id))) {

            ident = ctx->identity;

            d = &tmp_data;

            if (ident) {
                kcdb_identity_hold(ident);
                dlg_load_identity_params(d, ident);
            }

        } else {

            log_printf("Renewal operation scope does not include KCA");
            _end_task();

            certset_destroy(&tmp_data.certset);
            return KHM_ERROR_SUCCESS;

        }

    } else if (khui_cw_get_subtype(nc) == KMSG_CRED_NEW_CREDS) {

        _begin_task(0);
        _report_cs0(KHERR_DEBUG_1, L"Obtaining new KCA Cert");
        _describe();

        khui_cw_get_primary_id(nc, &ident);

    } else {
        log_printf("Not a new credentials request or a renewal.  Skipping KCA");
        certset_destroy(&tmp_data.certset);
        return KHM_ERROR_SUCCESS;
    }

    assert(d);

    if (!d->enabled || d->certset.n_certs == 0) {
        /* too bad.  we aren't getting any creds here.  But save the
           options if we are getting new creds. */
        if (khui_cw_get_subtype(nc) == KMSG_CRED_NEW_CREDS)
            dlg_save_identity_params(d);

        if (!d->enabled)
            log_printf("KCA certs disabled for this identity.  Skipping KCA");
        else
            log_printf("No KCA certs were specified for this identity.  Skipping KCA");

        khui_cw_set_response(nc, credtype_id,
                             KHUI_NC_RESPONSE_SUCCESS |
                             KHUI_NC_RESPONSE_EXIT);

        _end_task();

        certset_destroy(&tmp_data.certset);
        if (ident)
            kcdb_identity_release(ident);
        return KHM_ERROR_SUCCESS;
    }

    /* processing */
    if (KHM_FAILED(kcdb_credtype_get_id(L"Krb5Cred", &k5_credtype))) {
        log_printf("Can't lookup credtype ID for Krb5Cred");
        _end_task();

        certset_destroy(&tmp_data.certset);
        if (ident)
            kcdb_identity_release(ident);
        return KHM_ERROR_UNKNOWN;
    }

    if (!khui_cw_type_succeeded(nc, k5_credtype)) {
        log_printf("Krb5Cred failed.  Not getting KCA cert");
        goto err_exit;
    }

    if (ident == NULL) {

        log_printf("No identity found.  Not getting KCA cert");
        goto err_exit;

    }

    cb = sizeof(wccname);
    if (KHM_FAILED(kcdb_identity_get_attrib(ident,
                                            L"Krb5CCName",
                                            NULL,
                                            wccname,
                                            &cb))) {
        log_printf("Can't determine CC name for identity.  Not getting KCA cert");
        goto err_exit;
    }

    log_printf("Found CC name: [%S]", wccname);

    UnicodeStrToAnsi(ccname, sizeof(ccname), wccname);

    for (i=0; i < d->certset.n_certs; i++) {

        nc_cert = certset_get_cert(&d->certset, i);
#ifdef DEBUG
        assert(nc_cert != NULL);
#endif

        if (nc_cert == NULL)
            continue;

        if (nc_cert->kca_host_method == KCA_HOST_MANUAL) {
            UnicodeStrToAnsi(hostlist, sizeof(hostlist), nc_cert->kca_hosts);
        } else {
            hostlist[0] = '\0';
        }

        if (nc_cert->kca_host_method == KCA_HOST_REALM ||
            nc_cert->kca_host_method == KCA_HOST_MANUAL) {
            UnicodeStrToAnsi(realm, sizeof(realm), nc_cert->kca_realm);
        } else {
            realm[0] = '\0';
        }

        /* get a certificate from the KCA */
        xerr = getcert(&rsa, &keybits, &cert, err_buf, sizeof(err_buf),
                       realm, sizeof(realm),
                       ccname,
                       (hostlist[0]?hostlist:NULL));

        if (xerr) {
            log_printf("Error %d from getcert : %s", xerr, err_buf);
            _report_cs1(xerr == KX509_STATUS_CLNT_IGN ? KHERR_DEBUG_1 : KHERR_ERROR,
                        L"Can't obtain KCA certificate: %1!S!", _cptr(err_buf));
            _resolve();
            n_failed++;
            goto cert_err_exit;
        }

        cb_der = i2d_X509(cert, (unsigned char **)&pder_buf);

        if (cb_der < 0) {
            log_printf("Error %d from i2d_X509", cb_der);
            _report_cs1(KHERR_ERROR, L"Error %1!d! while decoding KCA certificate",
                        _int32(cb_der));
            n_failed++;
            goto cert_err_exit;
        }

        /* did we cause a buffer overrun? */
        assert(cb_der < sizeof(der_buf));

        if (!rsa_to_keyblob(keybits, rsa, &privKey, &cbPrivKey)) {
            log_printf("rsa_to_keyblob failed.");
            _report_cs0(KHERR_ERROR,
                        L"Can't decode KCA certificate.  rsa_to_keyblob failed.");
            n_failed++;
            goto cert_err_exit;
        }

        /* clean out old certs before storing new ones.  we wait until
           now because we don't want to destroy all the existing
           certificates unless we have something to store. */
        if (!certs_cleaned) {
            kca_del_ident_creds(ident);
            certs_cleaned = 1;
        }

        /* obtain the container name into which the key shall be stored */
        container = getContainerName(cert);
        if (!container) {
            log_printf("Unable to obtain container name from cert");
            _report_cs0(KHERR_ERROR, L"Unable to obtain container name from cert");
            n_failed++;
            goto cert_err_exit;
        }

        /* store the private key in the registry */
        if (!store_key(privKey, cbPrivKey, container)) {
            log_printf("Unable to store private key in registry");
            _report_cs0(KHERR_ERROR, L"Can't store KCA private key in registry");
            n_failed++;
            goto cert_err_exit;
        }

        /* and the cert */
        store_cert((BYTE *) &der_buf[0], cb_der, container);

    cert_err_exit:

        if (container)
            free(container);
        container = NULL;

        if (privKey) {
            free(privKey);
            privKey = NULL;
        }
        clean_cert(rsa, cert);
        rsa = NULL;
        cert = NULL;
    }

    certset_destroy(&tmp_data.certset);

    khui_cw_set_response(nc, credtype_id,
                         KHUI_NC_RESPONSE_EXIT |
                         ((n_failed == 0)? KHUI_NC_RESPONSE_SUCCESS :
                          KHUI_NC_RESPONSE_FAILED));

    if (khui_cw_get_subtype(nc) == KMSG_CRED_NEW_CREDS)
        dlg_save_identity_params(d);

    _end_task();

    if (ident)
        kcdb_identity_release(ident);
    return KHM_ERROR_SUCCESS;

 err_exit:

    if (container)
        free(container);

    clean_cert(rsa, cert);

    certset_destroy(&tmp_data.certset);

    khui_cw_set_response(nc, credtype_id,
                         KHUI_NC_RESPONSE_FAILED |
                         KHUI_NC_RESPONSE_EXIT);

    _end_task();

    if (ident)
        kcdb_identity_release(ident);
    return KHM_ERROR_SUCCESS;
}

/* Handler for KMSG_CRED_END */
khm_int32
handle_kmsg_cred_end(khui_new_creds * nc) {

    khui_new_creds_by_type * nct = NULL;

    /* TODO: Perform any additional uninitialization as needed. */

    khui_cw_find_type(nc, credtype_id, &nct);

    if (nct) {

        khui_cw_del_type(nc, credtype_id);

        if (nct->name)
            free(nct->name);
        if (nct->credtext)
            free(nct->credtext);

        free(nct);

    }

    return KHM_ERROR_SUCCESS;
}

/* Handler for KMSG_CRED_IMPORT */
khm_int32
handle_kmsg_cred_import(void) {

    /* TODO: Handle this message */

    return KHM_ERROR_SUCCESS;
}


/******************************************************
 Dispatch each message to individual handlers above.
 */
khm_int32 KHMAPI
handle_cred_acq_msg(khm_int32 msg_type,
                    khm_int32 msg_subtype,
                    khm_ui_4  uparam,
                    void *    vparam) {

    khm_int32 rv = KHM_ERROR_SUCCESS;

    switch(msg_subtype) {
    case KMSG_CRED_NEW_CREDS:
        return handle_kmsg_cred_new_creds((khui_new_creds *) vparam);

    case KMSG_CRED_RENEW_CREDS:
        return handle_kmsg_cred_renew_creds((khui_new_creds *) vparam);

    case KMSG_CRED_DIALOG_PRESTART:
        return handle_kmsg_cred_dialog_prestart((khui_new_creds *) vparam);

    case KMSG_CRED_PROCESS:
        return handle_kmsg_cred_process((khui_new_creds *) vparam);

    case KMSG_CRED_DIALOG_NEW_IDENTITY:
        return handle_kmsg_cred_dialog_new_identity(uparam, vparam);

    case KMSG_CRED_DIALOG_NEW_OPTIONS:
        return handle_kmsg_cred_dialog_new_options(uparam, vparam);

    case KMSG_CRED_END:
        return handle_kmsg_cred_end((khui_new_creds *) vparam);

    case KMSG_CRED_IMPORT:
        return handle_kmsg_cred_import();
    }

    return rv;
}
