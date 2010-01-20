/*
 * Copyright (c) 2009 Secure Endpoints Inc.
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


#define NOSTRSAFE
#include "credprov.h"
#include <tchar.h>
#include <shellapi.h>
#include <htmlhelp.h>
#include <strsafe.h>
#include <assert.h>

static ATOM message_window_class = 0;
static HWND notifier_window = NULL;
static volatile BOOL notification_icon_added = FALSE;

#define TOKEN_ICON_ID 1
#define TOKEN_MESSAGE_ID WM_USER

static khm_int32
get_default_notifier_action(void)
{
    khm_int32 cmd = KHUI_ACTION_OPEN_APP;

    khc_read_int32(NULL, L"CredWindow\\NotificationAction", &cmd);

    return cmd;
}

static void
prepare_context_menu(HMENU hmenu)
{
    khm_int32 cmd;
    wchar_t caption[128];

    cmd = get_default_notifier_action();

    if (cmd == KHUI_ACTION_NEW_CRED)
        LoadString(hResModule, IDS_ACT_NEW, caption, ARRAYLENGTH(caption));
    else
        LoadString(hResModule, IDS_ACT_OPEN, caption, ARRAYLENGTH(caption));

    ModifyMenu(hmenu, ID_DEFAULT, MF_STRING|MF_BYCOMMAND, ID_DEFAULT, caption);
    SetMenuDefaultItem(hmenu, ID_DEFAULT, FALSE);
}

static void
handle_context_menu(void)
{
    POINT pt;
    HMENU hMenu;
    HMENU hMenuBar;

    GetCursorPos(&pt);

    hMenuBar = LoadMenu(hResModule, MAKEINTRESOURCE(IDR_CTXMENU));
    hMenu = GetSubMenu(hMenuBar, 0);

    if (hMenu) {
        prepare_context_menu(hMenu);
        TrackPopupMenu(hMenu, TPM_NONOTIFY, pt.x, pt.y, 0, notifier_window, NULL);
    }

    {
        NOTIFYICONDATA idata;
        ZeroMemory(&idata, sizeof(idata));
        Shell_NotifyIcon(NIM_SETFOCUS, &idata);
    }
}

static LRESULT CALLBACK
notifier_wnd_proc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    if (uMsg == TOKEN_MESSAGE_ID) {
        switch (lParam) {
        case NIN_SELECT:
        case NIN_KEYSELECT:

            {
                NOTIFYICONDATA idata;
                khm_int32 cmd = KHUI_ACTION_OPEN_APP;

                khc_read_int32(NULL, L"CredWindow\\NotificationAction", &cmd);

                khui_action_trigger(cmd, NULL);

                ZeroMemory(&idata, sizeof(idata));

                Shell_NotifyIcon(NIM_SETFOCUS, &idata);
            }
            return 0;

        case WM_CONTEXTMENU:
            handle_context_menu();
            return TRUE;

        default:
            return 0;
        }
    }
    else if (uMsg == WM_COMMAND) {
        switch (LOWORD(wParam)) {
        case ID_DEFAULT:
            {
                khm_int32 cmd;

                cmd = get_default_notifier_action();

                khui_action_trigger(cmd, NULL);
            }
            return TRUE;

        case ID_SHOWHELP:
            {
                wchar_t helploc[MAX_PATH + MAX_PATH];

                get_help_file(helploc, sizeof(helploc));

                StringCbCat(helploc, sizeof(helploc), L"::index.html");

                HtmlHelp(notifier_window, helploc, HH_DISPLAY_TOPIC, 0);
            }
            return TRUE;
        }
    }

    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

static void
initialize_if_necessary(void)
{
    if (message_window_class == 0) {
        WNDCLASSEX c = {
            sizeof(WNDCLASSEX), /* cbSize */
            0,                  /* style */
            notifier_wnd_proc,  /* lpfnWndProc */
            0,                  /* cbClsExtra */
            0,                  /* cbWndExtra */
            hInstance,          /* hinstance */
            NULL,               /* hIcon */
            NULL,               /* hCursor */
            NULL,               /* hbrBackground */
            NULL,               /* lpszMenuName */
            L"KCACredStateIconNotifier", /* lpszClassName */
            NULL,                        /* hIconSm */
        };

        message_window_class = RegisterClassEx(&c);
    }

    if (notifier_window == NULL && message_window_class != 0) {
        notifier_window = CreateWindow(MAKEINTATOM(message_window_class),
                                       L"KCACredStateIconNotifierWindow",
                                       0, 0, 0, 0, 0,
                                       HWND_MESSAGE,
                                       NULL,
                                       hInstance,
                                       NULL);
    }

    assert(notifier_window != NULL);

    if (!notification_icon_added && notifier_window != NULL) {
        NOTIFYICONDATA idata;

        ZeroMemory(&idata, sizeof(idata));

        idata.cbSize = sizeof(idata);
        idata.hWnd = notifier_window;
        idata.uID = TOKEN_ICON_ID;
        idata.uFlags = NIF_ICON | NIF_MESSAGE;
        idata.uCallbackMessage = TOKEN_MESSAGE_ID;
        idata.hIcon = (HICON) LoadImage(hResModule, MAKEINTRESOURCE(IDI_CRED_NONE),
                                        IMAGE_ICON, 0, 0,
                                        LR_DEFAULTSIZE | LR_DEFAULTCOLOR | LR_SHARED);
        notification_icon_added = Shell_NotifyIcon(NIM_ADD, &idata);

        idata.cbSize = sizeof(idata);
        idata.uVersion = NOTIFYICON_VERSION;

        Shell_NotifyIcon(NIM_SETVERSION, &idata);

        assert(notification_icon_added);
    }
}

void
kca_remove_icon(void)
{
    NOTIFYICONDATA idata;

    ZeroMemory(&idata, sizeof(idata));

    idata.cbSize = sizeof(idata);
    idata.hWnd = notifier_window;
    idata.uID = TOKEN_ICON_ID;
    Shell_NotifyIcon(NIM_DELETE, &idata);
    notification_icon_added = FALSE;
}

static void
set_tooltip_and_icon(UINT tooltip_text, const wchar_t * postfix, UINT icon_id)
{
    NOTIFYICONDATA idata;
    wchar_t buf[ARRAYLENGTH(idata.szTip)];

    ZeroMemory(&idata, sizeof(idata));

    idata.cbSize = sizeof(idata);
    idata.hWnd = notifier_window;
    idata.uID = TOKEN_ICON_ID;
    idata.uFlags = NIF_ICON | NIF_TIP;
    idata.hIcon = (HICON) LoadImage(hResModule, MAKEINTRESOURCE(icon_id),
                                    IMAGE_ICON, 0, 0,
                                    LR_DEFAULTCOLOR | LR_DEFAULTSIZE | LR_SHARED);
    if (tooltip_text != 0) {
        LoadString(hResModule, tooltip_text, buf, ARRAYLENGTH(buf));
    }
    StringCbPrintf(idata.szTip, sizeof(idata.szTip),
                   L"%s%s",
                   (tooltip_text != 0)? buf : L"",
                   (postfix != NULL)? postfix : L"");

    Shell_NotifyIcon(NIM_MODIFY, &idata);
}

struct state_data {
    khm_handle credset;
};

#define COLLECT_STR_LEN 256

static khm_int32 KHMAPI
collect_kca_cert_names(khm_handle cred, void * rock)
{
    wchar_t *str = (wchar_t *) rock;
    wchar_t realm[KCDB_MAXCCH_NAME] = L"";
    FILETIME ft_now;
    FILETIME ft_expire;
    khm_size cb;

    cb = sizeof(ft_expire);
    if (KHM_FAILED(kcdb_cred_get_attr(cred, KCDB_ATTR_EXPIRE, NULL, &ft_expire, &cb)))
        return KHM_ERROR_SUCCESS;

    GetSystemTimeAsFileTime(&ft_now);
    if (CompareFileTime(&ft_now, &ft_expire) >= 0)
        return KHM_ERROR_SUCCESS;

    cb = sizeof(realm);

    if (KHM_SUCCEEDED(kcdb_cred_get_attr(cred, attr_id_auth_realm, NULL, realm, &cb)) &&
        realm[0]) {
        StringCchCat(str, COLLECT_STR_LEN, realm);
        StringCchCat(str, COLLECT_STR_LEN, L"\n");
    }

    return KHM_ERROR_SUCCESS;
}

static khm_int32 KHMAPI
set_state_from_ui_thread(HWND hwnd_main, void * stuff)
{
    struct state_data * d = (struct state_data *) stuff;
    wchar_t certs[COLLECT_STR_LEN] = L"";

    initialize_if_necessary();

    if (d->credset)
        kcdb_credset_apply(d->credset, collect_kca_cert_names, certs);

    if (certs[0] == L'\0') {
        set_tooltip_and_icon(IDS_CRED_TT_NONE, NULL, IDI_CRED_NONE);
        return KHM_ERROR_SUCCESS;
    }

    set_tooltip_and_icon(IDS_CRED_TT_GOOD, certs, IDI_CRED_GOOD);

    return KHM_ERROR_SUCCESS;
}

void
kca_icon_set_state(khm_handle credset_with_tokens)
{
    struct state_data d;

#if KH_VERSION_API < 7
    if (pkhui_request_UI_callback == NULL)
        return;
#endif

    d.credset = credset_with_tokens;

    if (notification_icon_added) {
        set_state_from_ui_thread(NULL, &d);
    } else {
        khui_request_UI_callback(set_state_from_ui_thread, &d);
    }
}
