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
#include <cryptuiapi.h>

/* Dialog procedure and support code for displaying property sheets
   for credentials of type MyCred. */

/* Dialog procedure for the property sheet.  This will run under the
   UI thread when a property sheet is being displayed for one of our
   credentials.. */
INT_PTR CALLBACK
pp_cred_dlg_proc(HWND hwnd,
                 UINT uMsg,
                 WPARAM wParam,
                 LPARAM lParam) {

    khui_property_sheet * ps;

    switch (uMsg) {
    case WM_INITDIALOG:
        {
            PROPSHEETPAGE * p;
            wchar_t notavailable[128];

            p = (PROPSHEETPAGE *) lParam;
            ps = (khui_property_sheet *) p->lParam;

#pragma warning(push)
#pragma warning(disable: 4244)
            SetWindowLongPtr(hwnd, DWLP_USER, (LONG_PTR) ps);
#pragma warning(pop)

            if (ps->cred) {
                wchar_t tbuf[512];
                khm_size cb;
                khm_handle ident = NULL;

                LoadString(hResModule, IDS_NOTAVAILABLE,
                           notavailable, ARRAYLENGTH(notavailable));

                cb = sizeof(tbuf);
                if (KHM_SUCCEEDED(kcdb_cred_get_attr_string(ps->cred,
                                                            attr_id_subj_email,
                                                            tbuf,
                                                            &cb,
                                                            KCDB_TS_LONG))) {
                    SetDlgItemText(hwnd, IDC_PP_SUBJ_E, tbuf);
                } else {
                    SetDlgItemText(hwnd, IDC_PP_SUBJ_E, notavailable);
                }

                cb = sizeof(tbuf);
                if (KHM_SUCCEEDED(kcdb_cred_get_attr_string(ps->cred,
                                                            attr_id_subj_display,
                                                            tbuf,
                                                            &cb,
                                                            KCDB_TS_LONG))) {
                    SetDlgItemText(hwnd, IDC_PP_SUBJ_D, tbuf);
                } else {
                    SetDlgItemText(hwnd, IDC_PP_SUBJ_D, notavailable);
                }

                cb = sizeof(tbuf);
                if (KHM_SUCCEEDED(kcdb_cred_get_attr_string(ps->cred,
                                                            attr_id_auth_realm,
                                                            tbuf,
                                                            &cb,
                                                            KCDB_TS_LONG))) {
                    SetDlgItemText(hwnd, IDC_PP_REALM, tbuf);
                } else {
                    SetDlgItemText(hwnd, IDC_PP_REALM, notavailable);
                }

                cb = sizeof(tbuf);
                if (KHM_SUCCEEDED(kcdb_cred_get_attr_string(ps->cred,
                                                            attr_id_issuer_display,
                                                            tbuf,
                                                            &cb,
                                                            KCDB_TS_LONG))) {
                    SetDlgItemText(hwnd, IDC_PP_ISSUER, tbuf);
                } else {
                    SetDlgItemText(hwnd, IDC_PP_ISSUER, notavailable);
                }

                cb = sizeof(tbuf);
                if (KHM_SUCCEEDED(kcdb_cred_get_attr_string(ps->cred,
                                                            KCDB_ATTR_ISSUE,
                                                            tbuf,
                                                            &cb,
                                                            KCDB_TS_LONG))) {
                    SetDlgItemText(hwnd, IDC_PP_NOTBEFORE, tbuf);
                } else {
                    SetDlgItemText(hwnd, IDC_PP_NOTBEFORE, notavailable);
                }

                cb = sizeof(tbuf);
                if (KHM_SUCCEEDED(kcdb_cred_get_attr_string(ps->cred,
                                                            KCDB_ATTR_EXPIRE,
                                                            tbuf,
                                                            &cb,
                                                            KCDB_TS_LONG))) {
                    SetDlgItemText(hwnd, IDC_PP_NOTAFTER, tbuf);
                } else {
                    SetDlgItemText(hwnd, IDC_PP_NOTAFTER, notavailable);
                }

            } else {
#ifdef DEBUG
                /* we really shouldn't get here */
                DebugBreak();
#endif
            }
        }
        return FALSE;

    case WM_COMMAND:
        {
            HCERTSTORE     hStoreHandle = NULL;
            PCCERT_CONTEXT pCertContext = NULL;
            CERT_ID        certId;
            BYTE           sn_buf[1024];
            BYTE           issuer_buf[1024];
            CRYPTUI_VIEWCERTIFICATE_STRUCT vcs;
            wchar_t title_fmt[128];
            wchar_t realm[128];
            wchar_t title[256];
            BOOL b;

            khm_size       cb;

            if (wParam != MAKEWPARAM(IDC_PP_DETAILS, BN_CLICKED))
                break;

            ps = (khui_property_sheet *) GetWindowLongPtr(hwnd, DWLP_USER);

            if (ps == NULL || ps->cred == NULL) {
#ifdef DEBUG
                DebugBreak();
#endif
                break;
            }

            /* we need to display the standard UI for this certificate */

            ZeroMemory(&certId, sizeof(certId));

            cb = sizeof(sn_buf);
            if (KHM_FAILED(kcdb_cred_get_attr(ps->cred, attr_id_serial_number,
                                              NULL, sn_buf, &cb))) {
                break;
            }

            certId.IssuerSerialNumber.SerialNumber.cbData = cb;
            certId.IssuerSerialNumber.SerialNumber.pbData = sn_buf;

            cb = sizeof(issuer_buf);
            if (KHM_FAILED(kcdb_cred_get_attr(ps->cred, attr_id_issuer_name,
                                              NULL, issuer_buf, &cb))) {
                break;
            }

            certId.IssuerSerialNumber.Issuer.cbData = cb;
            certId.IssuerSerialNumber.Issuer.pbData = issuer_buf;

            certId.dwIdChoice = CERT_ID_ISSUER_SERIAL_NUMBER;

            if (!(hStoreHandle = CertOpenSystemStore(0, WIN32MYCERT_STORE))) {
                log_printf("Unable to access the system store");
                return TRUE;
            }

            pCertContext = CertFindCertificateInStore(hStoreHandle,
                                                      X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                                      0,
                                                      CERT_FIND_CERT_ID,
                                                      &certId,
                                                      NULL);

            if (!pCertContext) {
                /* the certificate was not found */
                EnableWindow(GetDlgItem(hwnd, IDC_PP_DETAILS), FALSE);
                goto _clean_dt;
            }

            ZeroMemory(&vcs, sizeof(vcs));

            vcs.dwSize = sizeof(vcs);
            vcs.hwndParent = hwnd;
            vcs.dwFlags = 0;

            LoadString(hResModule, IDS_PP_TITLE,
                       title_fmt, ARRAYLENGTH(title_fmt));
            cb = sizeof(realm);
            kcdb_cred_get_attr(ps->cred, attr_id_auth_realm,
                               NULL, realm, &cb);
            StringCbPrintf(title, sizeof(title), title_fmt, realm);

            vcs.szTitle = title;

            vcs.pCertContext = pCertContext;

            CryptUIDlgViewCertificate(&vcs, &b);


        _clean_dt:

            if (pCertContext) {
                CertFreeCertificateContext(pCertContext);
                pCertContext = NULL;
            }

            if (hStoreHandle) {
                CertCloseStore(hStoreHandle, 0);
                hStoreHandle = NULL;
            }

            return TRUE;
        }
        break;
    }

    return FALSE;
}

