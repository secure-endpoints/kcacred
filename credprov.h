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

/* only include this header file once */
#pragma once

#ifndef _UNICODE
#ifndef RC_INVOKED
/* This template relies on _UNICODE being defined to call the correct
   APIs. */
#error  This template needs to be compiled with _UNICODE
#endif
#endif

/* Pull in configuration macros from the Makefile */
#include "credacq_config.h"

/* declare a few macros about our plugin */

/* The following macro will be used throughout the template to refer
   to the name of the plugin.  The macro is actually defined the
   Makefile generated configuration header file.  Modify the
   PLUGINNAME Makefile macro.*/
#ifndef MYPLUGIN_NAME
#error  MYPLUGIN_NAME not defined
#endif

/* Also define the unicde equivalent of the name.  In general strings
   in NetIDMgr are unicode. */
#define MYPLUGIN_NAMEW _T(MYPLUGIN_NAME)

/* The name of the module.  This is distinct from the name of the
   plugin for several reasons.  One of which is that a single module
   can provide multiple plugins.  Also, having a module name distinct
   from a plugin name allows multiple vendors to provide the same
   plugin.  For example, the module name for the MIT Kerberos 5 plugin
   is MITKrb5 while the plugin name is Krb5Cred.  The macro is
   actually defined in the Makefile generated configuration header
   file.  Modify the MODULENAME Makefile macro.*/
#ifndef MYMODULE_NAME
#error  MYMODULE_NAME not defined
#endif

#define MYMODULE_NAMEW _T(MYMODULE_NAME)

/* When logging events from our plugin, the event logging API can
   optionally take a facility name to provide a friendly label to
   identify where each event came from.  We will default to the plugin
   name, although it can be anything. */
#define MYPLUGIN_FACILITYW MYPLUGIN_NAMEW

/* Base name of the DLL that will be providing the plugin.  We use it
   to construct names of the DLLs that will contain localized
   resources.  This is defined in the Makefile and fed in to the build
   through there.  The macro to change in the Makefile is
   DLLBASENAME. */
#ifndef MYPLUGIN_DLLBASE
#error   MYPLUGIN_DLLBASE Not defined!
#endif

#define MYPLUGIN_DLLBASEW _T(MYPLUGIN_DLLBASE)

/* Name of the credentials type that will be registered by the plugin.
   This macro is actually defined in the Makefile generated
   configuration header file.  Change the CREDTYPENAME macro in the
   Makefile. */
#ifndef MYCREDTYPE_NAME
#error  MYCREDTYPE_NAME not defined
#endif

#define MYCREDTYPE_NAMEW _T(MYCREDTYPE_NAME)

/* Configuration node names.  We just concatenate a few strings
   together, although you should feel free to completely define your
   own. */

#define CONFIGNODE_MAIN   MYCREDTYPE_NAMEW L"Config"
#define CONFIGNODE_ALL_ID MYCREDTYPE_NAMEW L"AllIdents"
#define CONFIGNODE_PER_ID MYCREDTYPE_NAMEW L"PerIdent"

#define HELPFILE_NAME     L"kcaplugin.chm"

#include<windows.h>
/* include the standard NetIDMgr header files */
#include<netidmgr.h>
#include<netidmgr_version.h>
#include<tchar.h>

/* declarations for language resources */
#include "langres.h"

#ifndef NOSTRSAFE
#include<strsafe.h>
#endif

/***************************************************
 KCA specific declarations
 **************************************************/

#define	WIN32MYCERT_STORE     _T("My")

#define MYCERT_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)

#define	szOID_KCA_AUTHREALM              "1.3.6.1.4.1.250.42.1"
#define szOID_PKINIT_PRINCIPAL_NAME      "1.3.6.1.5.2.2"

#define KCA_MAXCCH_REALM      256
#define KCA_MAXCCH_HOST       256
#define KCA_MAX_HOSTS         8

/***************************************************
 Externals
***************************************************/

extern kmm_module h_khModule;
extern HINSTANCE  hInstance;
extern HMODULE    hResModule;

extern const wchar_t * my_facility;

extern khm_int32 credtype_id;

/* global credentials set used only by the plug-in thread */
extern khm_handle g_credset;

/* configuration handle for parameters */
extern khm_handle csp_params;

/* path to the module */
extern wchar_t module_path[];

/* Attributes */

#define ATTRNAME_KCA_AUTHREALM   L"KCAAuthRealm"
extern khm_int32 attr_id_auth_realm;

#define ATTRNAME_SUBJECT_EMAIL   L"X509SubjEmail"
extern khm_int32 attr_id_subj_email;

#define ATTRNAME_SUBJECT_DISPLAY L"X509SubjDisplay"
extern khm_int32 attr_id_subj_display;

#define ATTRNAME_ISSUER_DISPLAY  L"X509IssuerDisplay"
extern khm_int32 attr_id_issuer_display;

/* encoded issuer name */
#define ATTRNAME_ISSUER_NAME     L"X509IssuerName"
extern khm_int32 attr_id_issuer_name;

/* serial number blob */
#define ATTRNAME_SERIAL          L"X509SerialNumber"
extern khm_int32 attr_id_serial_number;

/* configuration */
extern kconf_schema plugin_schema[];
extern khm_size n_plugin_schema;

/* Function declarations */

/* in plugin.c */
khm_int32 KHMAPI
plugin_msg_proc(khm_int32 msg_type,
                khm_int32 msg_subtype,
                khm_ui_4  uparam,
                void * vparam);

/* in credtype.c */
khm_int32 KHMAPI
cred_is_equal(khm_handle cred1,
              khm_handle cred2,
              void * rock);

/* in credacq.c */
khm_int32 KHMAPI
handle_cred_acq_msg(khm_int32 msg_type,
                    khm_int32 msg_subtype,
                    khm_ui_4  uparam,
                    void *    vparam);

void
get_help_file(wchar_t * path,
              khm_size cbpath);

/* in proppage.c */
INT_PTR CALLBACK
pp_cred_dlg_proc(HWND hwnd,
                 UINT uMsg,
                 WPARAM wParam,
                 LPARAM lParam);

/* in config_id.c */
INT_PTR CALLBACK
config_id_dlgproc(HWND hwndDlg,
                  UINT uMsg,
                  WPARAM wParam,
                  LPARAM lParam);

/* in config_ids.c */
INT_PTR CALLBACK
config_ids_dlgproc(HWND hwndDlg,
                   UINT uMsg,
                   WPARAM wParam,
                   LPARAM lParam);

/* in config_main.c */
INT_PTR CALLBACK
config_dlgproc(HWND hwndDlg,
               UINT uMsg,
               WPARAM wParam,
               LPARAM lParam);

/* in list_cert.c */
void
kca_list_creds(void);

/* in list_cert.c */
PCCERT_CONTEXT
find_matching_cert(HCERTSTORE hStoreHandle,
                   khm_handle cred);

/* in del_cert.c */
khm_int32
kca_del_matching_creds(khm_handle credset);

/* in del_cert.c */
khm_int32
kca_del_ident_creds(khm_handle ident);

/* New credentials and configuration related declarations */

enum kca_host_method {
    KCA_HOST_AUTO,              /* determine hosts for realm
                                   automatically based on the identity
                                   realm. */
    KCA_HOST_MANUAL,            /* use a given host list */
    KCA_HOST_REALM              /* determine hosts automatically based
                                   on the specified realm */
};

/* Information about a certificate that should be obtained on behalf
   of a user. */
struct nc_cert {
    enum kca_host_method kca_host_method;
                                /* Method for obtaining the
                                   certificate. */

    wchar_t kca_realm[KCA_MAXCCH_REALM];
                                /* Realm of the certificate.  Only
                                   valid if kca_host_method is
                                   KCA_HOST_REALM. */

    wchar_t kca_hosts[KCA_MAXCCH_HOST * KCA_MAX_HOSTS];
                                /* Space separated list of hosts.
                                   Only valid if kca_host_method is
                                   KCA_HOST_MANUAL. */
};

/* Information about a set of certificates that should be obtained on
   behalf of a user. */
struct nc_cert_set {

    wchar_t identity_realm[KCA_MAXCCH_REALM];
                                /* The realm of the identity. */

    khm_size n_certs;           /* number of certificates in the certs
                                   array. */

    khm_size nc_certs;          /* number of certificates that the
                                   certs array can hold */

    struct nc_cert * certs;
};

/* This structure will hold all the state information we will need to
   access from the new credentials panel for our credentials type. */
struct nc_dialog_data {
    HWND hwnd;                  /* */

    khui_new_creds * nc;        /* only for new creds */
    khui_new_creds_by_type * nct; /* only for new creds */

    khui_config_init_data cfg;  /* only for config */
    khm_handle ident;           /* only for config */

    khm_boolean dirty;          /* only for config */
    khm_boolean loading;        /* only for config */

    khm_boolean certlist_initialized;

    khm_boolean enabled;
    khm_boolean certset_changed;

    struct nc_cert_set certset;
};

struct dlg_ident_handle {
    khm_handle csp_all;
    khm_handle csp_idkca;
    khm_handle csp_realm;
};

void
dlg_init(struct nc_dialog_data * d);

BOOL
dlg_open_ident_handle(khm_handle ident,
                      khm_int32 flags,
                      struct dlg_ident_handle * h,
                      wchar_t * realm,
                      khm_size cb_realm);

void
dlg_close_ident_handle(struct dlg_ident_handle * h);

void
dlg_load_identity_params(struct nc_dialog_data * d,
                         khm_handle ident);

void
dlg_save_identity_params(struct nc_dialog_data * d);

INT_PTR
dlg_handle_wm_notify(struct nc_dialog_data * d, WPARAM wParam, LPARAM lParam);

INT_PTR
dlg_handle_wm_command(struct nc_dialog_data * d, WPARAM wParam, LPARAM lParam);

void
dlg_enable_certs(struct nc_dialog_data * d,
                 BOOL enable, BOOL update_control);

void
certset_init(struct nc_cert_set * certset);

void
certset_destroy(struct nc_cert_set * certset);



/* kpkcs11inst.c */
void
install_kpkcs11_plugin(void);


/* kcaicon.c */
void
kca_icon_set_state(khm_handle credset_with_tokens);

void
kca_remove_icon(void);

/* Compatibility */

#if KH_VERSION_API < 12

typedef int khui_nc_subtype;

#ifdef _WIN64
#define NIMDLLNAME                  L"nidmgr64.dll"
#define API_khui_cw_get_primary_id  "khui_cw_get_primary_id"
#define API_khui_cw_get_result      "khui_cw_get_result"
#define API_khui_cw_get_subtype     "khui_cw_get_subtype"
#define API_khui_cw_get_ctx         "khui_cw_get_ctx"
#define API_kcdb_get_resource       "kcdb_get_resource"
#else
#define NIMDLLNAME                  L"nidmgr32.dll"
#define API_khui_cw_get_primary_id  "_khui_cw_get_primary_id@8"
#define API_khui_cw_get_result      "_khui_cw_get_result@4"
#define API_khui_cw_get_subtype     "_khui_cw_get_subtype@4"
#define API_khui_cw_get_ctx         "_khui_cw_get_ctx@4"
#define API_kcdb_get_resource       "_kcdb_get_resource@28"
#endif

extern khm_int32
(KHMAPI * pkhui_cw_get_primary_id)(khui_new_creds * nc, khm_handle *p_ident);

extern khm_int32
(KHMAPI * pkhui_cw_get_result)(khui_new_creds * c);

extern khui_nc_subtype
(KHMAPI * pkhui_cw_get_subtype)(khui_new_creds * c);

extern khui_action_context *
(KHMAPI * pkhui_cw_get_ctx)(khui_new_creds * c);

#define khui_cw_get_primary_id  (*pkhui_cw_get_primary_id)
#define khui_cw_get_result      (*pkhui_cw_get_result)
#define khui_cw_get_subtype     (*pkhui_cw_get_subtype)
#define khui_cw_get_ctx         (*pkhui_cw_get_ctx)
#define kcdb_get_resource       (*pkcdb_get_resource)

#define KHUI_CNFLAG_INSTANCE    KHUI_CNFLAG_PLURAL

/*! \brief KCDB Resource IDs */
typedef enum tag_kcdb_resource_id {
    KCDB_RES_T_NONE = 0,

    KCDB_RES_T_BEGINSTRING,     /* Internal marker*/

    KCDB_RES_DISPLAYNAME,       /*!< Localized display name */
    KCDB_RES_DESCRIPTION,       /*!< Localized description */
    KCDB_RES_TOOLTIP,           /*!< A tooltip */

    KCDB_RES_INSTANCE,          /*!< Name of an instance of objects
                                  belonging to this class */

    KCDB_RES_T_ENDSTRING,       /* Internal marker */

    KCDB_RES_T_BEGINICON = 1024, /* Internal marker */

    KCDB_RES_ICON_NORMAL,       /*!< Icon (normal) */
    KCDB_RES_ICON_DISABLED,     /*!< Icon (disabled) */

    KCDB_RES_T_ENDICON,         /* Internal marker */
} kcdb_resource_id;

#endif

#if KH_VERSION_API < 7

#ifdef _WIN64
#define API_khui_action_lock        "khui_action_lock"
#define API_khui_action_unlock      "khui_action_unlock"
#define API_khui_refresh_actions    "khui_refresh_actions"
#define API_khui_request_UI_callback "khui_request_UI_callback"
#else
#define API_khui_action_lock        "_khui_action_lock@0"
#define API_khui_action_unlock      "_khui_action_unlock@0"
#define API_khui_refresh_actions    "_khui_refresh_actions@0"
#define API_khui_request_UI_callback "_khui_request_UI_callback@8"
#endif

extern void
(KHMAPI * pkhui_action_lock)(void);

extern void
(KHMAPI * pkhui_action_unlock)(void);

extern void
(KHMAPI * pkhui_refresh_actions)(void);

typedef khm_int32
(KHMAPI * khm_ui_callback)(HWND hwnd_main_wnd, void * rock);

extern khm_int32
(KHMAPI * pkhui_request_UI_callback)(khm_ui_callback cb,
                                     void * rock);

#define khui_action_lock         (*pkhui_action_lock)
#define khui_action_unlock       (*pkhui_action_unlock)
#define khui_refresh_actions     (*pkhui_refresh_actions)
#define khui_request_UI_callback (*pkhui_request_UI_callback)

#endif

