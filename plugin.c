/*
 * Copyright (c) 2006-2010 Secure Endpoints Inc.
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
#include "netidmgr_version.h"
#include<htmlhelp.h>
#include<assert.h>

/* This file provides the message processing function and the support
   routines for implementing our plugin.  Note that some of the
   message processing routines have been moved to other source files
   based on their use.
*/

khm_int32 attr_id_auth_realm     = KCDB_ATTR_INVALID;
khm_int32 attr_id_subj_email     = KCDB_ATTR_INVALID;
khm_int32 attr_id_subj_display   = KCDB_ATTR_INVALID;
khm_int32 attr_id_issuer_display = KCDB_ATTR_INVALID;
khm_int32 attr_id_issuer_name    = KCDB_ATTR_INVALID;
khm_int32 attr_id_serial_number  = KCDB_ATTR_INVALID;

khm_int32 action_id_kca_help = 0;

khm_int32 credtype_id = KCDB_CREDTYPE_INVALID;
khm_handle g_credset  = NULL;

/* configuration space for parameters */
khm_handle csp_params = NULL;

/* some of the functions we will be calling are only available on API
   version 7 and above of Network Identity Manager.  Since these
   aren't critical, we allow building using API version 5 or above,
   but conditionally use the newer functionality if the plug-in is
   loaded by a newer version of Network Identity Manager. */

#if KH_VERSION_API < 12

HMODULE hm_netidmgr;

#if KH_VERSION_API < 7

/* declarations from version 7 of the API */
void
(KHMAPI * pkhui_action_lock)(void);

void
(KHMAPI * pkhui_action_unlock)(void);

void
(KHMAPI * pkhui_refresh_actions)(void);

typedef khm_int32
(KHMAPI * khm_ui_callback)(HWND hwnd_main_wnd, void * rock);

khm_int32
(KHMAPI * pkhui_request_UI_callback)(khm_ui_callback cb,
                                     void * rock);
#endif

khm_int32
(KHMAPI * pkhui_cw_get_primary_id)(khui_new_creds *, khm_handle *);

khm_int32
(KHMAPI * pkhui_cw_get_result)(khui_new_creds * c);

khui_nc_subtype
(KHMAPI * pkhui_cw_get_subtype)(khui_new_creds * c);

khui_action_context *
(KHMAPI * pkhui_cw_get_ctx)(khui_new_creds * c);

khm_int32
(KHMAPI * pkcdb_get_resource)(khm_handle h,
                              kcdb_resource_id r_id,
                              khm_int32 flags,
                              khm_int32 *prflags,
                              void * vparam,
                              void * buf,
                              khm_size * pcb_buf);

khm_int32 KHMAPI
int_khui_cw_get_primary_id(khui_new_creds * nc, khm_handle * h)
{
    if (nc->n_identities > 0 && nc->identities[0] != NULL) {
        *h = nc->identities[0];
        kcdb_identity_hold(*h);
        return KHM_ERROR_SUCCESS;
    }
    *h = NULL;
    return KHM_ERROR_NOT_FOUND;
}

khm_int32 KHMAPI
int_khui_cw_get_result(khui_new_creds * nc)
{
    return nc->result;
}

khui_nc_subtype KHMAPI
int_khui_cw_get_subtype(khui_new_creds * nc)
{
    return nc->subtype;
}

khui_action_context * KHMAPI
int_khui_cw_get_ctx(khui_new_creds * nc)
{
    return &nc->ctx;
}

/* This is obviously a very stripped down implementation that only
   attempts to implement the bare minimum functionality needed by this
   plug-in. */
khm_int32 KHMAPI
int_kcdb_get_resource(khm_handle h,
                      kcdb_resource_id r_id,
                      khm_int32 flags,
                      khm_int32 *prflags,
                      void * vparam,
                      void * buf,
                      khm_size * pcb_buf)
{
    if (r_id == KCDB_RES_DISPLAYNAME) {
        return kcdb_buf_get_attr_string(h, KCDB_ATTR_NAME, buf, pcb_buf, 0);
    }
    return KHM_ERROR_NOT_FOUND;
}

#endif

/* Handler for system messages.  The only two we handle are
   KMSG_SYSTEM_INIT and KMSG_SYSTEM_EXIT. */
khm_int32 KHMAPI
handle_kmsg_system(khm_int32 msg_type,
                   khm_int32 msg_subtype,
                   khm_ui_4  uparam,
                   void *    vparam) {
    khm_int32 rv = KHM_ERROR_SUCCESS;

    switch (msg_subtype) {

        /* This is the first message that will be received by a
           plugin.  We use it to perform initialization operations
           such as registering any credential types, data types and
           attributes. */
    case KMSG_SYSTEM_INIT:
        {
            kcdb_credtype ct;
            wchar_t short_desc[KCDB_MAXCCH_SHORT_DESC];
            wchar_t long_desc[KCDB_MAXCCH_LONG_DESC];
            khui_config_node cnode;
            khui_config_node_reg creg;
            kcdb_attrib attr;
            khm_handle csp_plugin = NULL;
            khm_handle csp_plugins = NULL;

#if KH_VERSION_API < 12

            do {
                khm_version libver;
                khm_ui_4 apiver;

                khm_get_lib_version(&libver, &apiver);

                if (apiver < 7)
                    break;

                hm_netidmgr = LoadLibrary(NIMDLLNAME);

                if (hm_netidmgr == NULL)
                    break;

#if KH_VERSION_API < 7
                pkhui_action_lock = (void (KHMAPI *)(void))
                    GetProcAddress(hm_netidmgr, API_khui_action_lock);
                pkhui_action_unlock = (void (KHMAPI *)(void))
                    GetProcAddress(hm_netidmgr, API_khui_action_unlock);
                pkhui_refresh_actions = (void (KHMAPI *)(void))
                    GetProcAddress(hm_netidmgr, API_khui_refresh_actions);
                pkhui_request_UI_callback = (khm_int32 (KHMAPI *)(khm_ui_callback, void *))
                    GetProcAddress(hm_netidmgr, API_khui_request_UI_callback);
#endif
                pkhui_cw_get_primary_id = (khm_int32 (KHMAPI *)(khui_new_creds *, khm_handle *))
                    GetProcAddress(hm_netidmgr, API_khui_cw_get_primary_id);
                pkhui_cw_get_result = (khm_int32 (KHMAPI *)(khui_new_creds *))
                    GetProcAddress(hm_netidmgr, API_khui_cw_get_result);
                pkhui_cw_get_subtype = (khui_nc_subtype (KHMAPI *)(khui_new_creds *))
                    GetProcAddress(hm_netidmgr, API_khui_cw_get_subtype);
                pkhui_cw_get_ctx = (khui_action_context * (KHMAPI *)(khui_new_creds *))
                    GetProcAddress(hm_netidmgr, API_khui_cw_get_ctx);
                pkcdb_get_resource = (khm_int32 (KHMAPI *)(khm_handle, kcdb_resource_id,
                                                           khm_int32, khm_int32 *,
                                                           void *, void *, khm_size *))
                    GetProcAddress(hm_netidmgr, API_kcdb_get_resource);
            } while (FALSE);

            if (pkhui_cw_get_primary_id == NULL)
              pkhui_cw_get_primary_id = int_khui_cw_get_primary_id;

            if (pkhui_cw_get_result == NULL)
                pkhui_cw_get_result = int_khui_cw_get_result;

            if (pkhui_cw_get_subtype == NULL)
                pkhui_cw_get_subtype = int_khui_cw_get_subtype;

            if (pkhui_cw_get_ctx == NULL)
                pkhui_cw_get_ctx = int_khui_cw_get_ctx;

            if (pkcdb_get_resource == NULL)
                pkcdb_get_resource = int_kcdb_get_resource;
#endif

            /* Add the icon now.  On NIM v2.x, doing so after tokens
               were reported may result in a deadlock as we try to
               switch to the UI thread and the UI thread is blocked on
               a resource request to this plug-in. */
            kca_icon_set_state(NULL);

            /* First and foremost, we need to register a credential
               type. */
            ZeroMemory(&ct, sizeof(ct));
            ct.id = KCDB_CREDTYPE_AUTO;
            ct.name = MYCREDTYPE_NAMEW;
            ct.short_desc = short_desc;
            ct.long_desc = long_desc;

            short_desc[0] = L'\0';
            LoadString(hResModule, IDS_CT_SHORT_DESC,
                       short_desc, ARRAYLENGTH(short_desc));

            long_desc[0] = L'\0';
            LoadString(hResModule, IDS_CT_LONG_DESC,
                       long_desc, ARRAYLENGTH(long_desc));

            ct.icon = NULL;     /* We skip the icon for now, but you
                                   can assign a handle to an icon
                                   here.  The icon will be used to
                                   represent the credentials type.*/

            kmq_create_subscription(plugin_msg_proc, &ct.sub);

            ct.is_equal = cred_is_equal;

            rv = kcdb_credtype_register(&ct, &credtype_id);

            /* We create a global credential set that we use in the
               plug-in thread.  This alleviates the need to create one
               everytime we need one. Keep in mind that this should
               only be used in the plug-in thread and should not be
               touched from the UI thread or any other thread. */
            kcdb_credset_create(&g_credset);

            /* TODO: Perform additional initialization operations. */

            /* Register our attributes */

            ZeroMemory(&attr, sizeof(attr));

            attr.name = ATTRNAME_KCA_AUTHREALM;
            attr.id = KCDB_ATTR_INVALID;
            attr.alt_id = KCDB_ATTR_INVALID;
            attr.flags = 0;
            attr.type = KCDB_TYPE_STRING;
            attr.short_desc = short_desc;
            attr.long_desc = long_desc;
            attr.compute_cb = NULL;
            attr.compute_min_cbsize = 0;
            attr.compute_max_cbsize = 0;

            LoadString(hResModule, IDS_ATTR_REALM_SHORT_DESC,
                       short_desc, ARRAYLENGTH(short_desc));
            LoadString(hResModule, IDS_ATTR_REALM_LONG_DESC,
                       long_desc, ARRAYLENGTH(long_desc));

            rv = kcdb_attrib_register(&attr, &attr_id_auth_realm);
            if (KHM_FAILED(rv))
                break;

            attr.name = ATTRNAME_SUBJECT_EMAIL;

            LoadString(hResModule, IDS_ATTR_SUBJECT_EMAIL_SHORT_DESC,
                       short_desc, ARRAYLENGTH(short_desc));
            LoadString(hResModule, IDS_ATTR_SUBJECT_EMAIL_LONG_DESC,
                       long_desc, ARRAYLENGTH(long_desc));

            rv = kcdb_attrib_register(&attr, &attr_id_subj_email);
            if (KHM_FAILED(rv))
                break;

            attr.name = ATTRNAME_SUBJECT_DISPLAY;

            LoadString(hResModule, IDS_ATTR_SUBJECT_SHORT_DESC,
                       short_desc, ARRAYLENGTH(short_desc));
            LoadString(hResModule, IDS_ATTR_SUBJECT_LONG_DESC,
                       long_desc, ARRAYLENGTH(long_desc));

            rv = kcdb_attrib_register(&attr, &attr_id_subj_display);
            if (KHM_FAILED(rv))
                break;

            attr.name = ATTRNAME_ISSUER_DISPLAY;

            LoadString(hResModule, IDS_ATTR_ISSUER_SHORT_DESC,
                       short_desc, ARRAYLENGTH(short_desc));
            LoadString(hResModule, IDS_ATTR_ISSUER_LONG_DESC,
                       long_desc, ARRAYLENGTH(long_desc));

            rv = kcdb_attrib_register(&attr, &attr_id_issuer_display);
            if (KHM_FAILED(rv))
                break;

            attr.name = ATTRNAME_ISSUER_NAME;
            attr.flags = KCDB_ATTR_FLAG_HIDDEN;
            attr.type = KCDB_TYPE_DATA;
            attr.short_desc = NULL;
            attr.long_desc = NULL;

            rv = kcdb_attrib_register(&attr, &attr_id_issuer_name);
            if (KHM_FAILED(rv))
                break;

            attr.name = ATTRNAME_SERIAL;

            rv = kcdb_attrib_register(&attr, &attr_id_serial_number);
            if (KHM_FAILED(rv))
                break;

            /* List the credentials that are already here */
            kca_list_creds();

            /* Now we register our configuration panels. */

#ifdef GENERAL_CONFIG_PANEL
            /* This configuration panel is the one that controls
               general options.  We leave the identity specific and
               identity defaults for other configuration panels. */

            ZeroMemory(&creg, sizeof(creg));

            short_desc[0] = L'\0';

            LoadString(hResModule, IDS_CFG_SHORT_DESC,
                       short_desc, ARRAYLENGTH(short_desc));

            long_desc[0] = L'\0';

            LoadString(hResModule, IDS_CFG_LONG_DESC,
                       long_desc, ARRAYLENGTH(long_desc));

            creg.name = CONFIGNODE_MAIN;
            creg.short_desc = short_desc;
            creg.long_desc = long_desc;
            creg.h_module = hResModule;
            creg.dlg_template = MAKEINTRESOURCE(IDD_CONFIG);
            creg.dlg_proc = config_dlgproc;
            creg.flags = 0;

            khui_cfg_register(NULL, &creg);
#endif

            /* Now we do the identity specific and identity default
               configuration panels. "KhmIdentities" is a predefined
               configuration node under which all the identity spcific
               configuration is managed. */

            if (KHM_FAILED(khui_cfg_open(NULL, L"KhmIdentities", &cnode))) {
                /* this should always work */
                assert(FALSE);
                rv = KHM_ERROR_NOT_FOUND;
                break;
            }

            /* First the tab panel for defaults for all identities */

            ZeroMemory(&creg, sizeof(creg));

            short_desc[0] = L'\0';
            LoadString(hResModule, IDS_CFG_IDS_SHORT_DESC,
                       short_desc, ARRAYLENGTH(short_desc));
            long_desc[0] = L'\0';
            LoadString(hResModule, IDS_CFG_IDS_LONG_DESC,
                       long_desc, ARRAYLENGTH(long_desc));

            creg.name = CONFIGNODE_ALL_ID;
            creg.short_desc = short_desc;
            creg.long_desc = long_desc;
            creg.h_module = hResModule;
            creg.dlg_template = MAKEINTRESOURCE(IDD_CONFIG_IDS);
            creg.dlg_proc = config_ids_dlgproc;
            creg.flags = KHUI_CNFLAG_SUBPANEL;

            khui_cfg_register(cnode, &creg);

            /* Now the panel for per identity configuration */

            ZeroMemory(&creg, sizeof(creg));

            short_desc[0] = L'\0';
            LoadString(hResModule, IDS_CFG_ID_SHORT_DESC,
                       short_desc, ARRAYLENGTH(short_desc));
            long_desc[0] = L'\0';
            LoadString(hResModule, IDS_CFG_ID_LONG_DESC,
                       long_desc, ARRAYLENGTH(long_desc));

            creg.name = CONFIGNODE_PER_ID;
            creg.short_desc = short_desc;
            creg.long_desc = long_desc;
            creg.h_module = hResModule;
            creg.dlg_template = MAKEINTRESOURCE(IDD_CONFIG_ID);
            creg.dlg_proc = config_id_dlgproc;
            creg.flags = KHUI_CNFLAG_SUBPANEL | KHUI_CNFLAG_INSTANCE;

            khui_cfg_register(cnode, &creg);

            khui_cfg_release(cnode);

            /* load the schema */
            if (KHM_SUCCEEDED(kmm_get_plugins_config(0, &csp_plugins))) {
                khc_load_schema(csp_plugins, plugin_schema);
                khc_close_space(csp_plugins);
            }

            /* open the plug-in and parameter configuration spaces */
            if (KHM_SUCCEEDED(kmm_get_plugin_config(MYPLUGIN_NAMEW,
                                                    KHM_FLAG_CREATE,
                                                    &csp_plugin))) {
                khc_open_space(csp_plugin, L"Parameters", KHM_FLAG_CREATE,
                               &csp_params);

                khc_close_space(csp_plugin);
            }

            /* try to install the kpkcs11 plugin now */
            install_kpkcs11_plugin();

            /* register the "KCA Help" menu item, so that we can add
               the plug-in menu item to the Help menu. */
            {
                khm_handle h_sub = NULL;

#if KH_VERSION_API < 7

                if (pkhui_action_lock == NULL ||
                    pkhui_action_unlock == NULL ||
                    pkhui_refresh_actions == NULL ||
                    pkhui_request_UI_callback == NULL)

                    goto no_custom_help;

#endif

                kmq_create_subscription(plugin_msg_proc, &h_sub);

                LoadString(hResModule, IDS_ACTION_KCA_HELP,
                           short_desc, ARRAYLENGTH(short_desc));
                LoadString(hResModule, IDS_ACTION_KCA_HELP_TT,
                           long_desc, ARRAYLENGTH(long_desc));

                action_id_kca_help = khui_action_create(NULL,
                                                        short_desc,
                                                        long_desc,
                                                        NULL,
                                                        KHUI_ACTIONTYPE_TRIGGER,
                                                        h_sub);

                if (action_id_kca_help != 0) {
                    khm_size s;
                    khm_size i;
                    khui_menu_def * help_menu;
                    khm_boolean refresh = FALSE;

                    khui_action_lock();

                    help_menu = khui_find_menu(KHUI_MENU_HELP);
                    if (help_menu) {
                        s = khui_menu_get_size(help_menu);

                        for (i=0; i < s; i++) {
                            khui_action_ref * aref;

                            aref = khui_menu_get_action(help_menu, i);

                            if (aref && !(aref->flags & KHUI_ACTIONREF_PACTION) &&
                                aref->action == KHUI_ACTION_HELP_INDEX) {

                                khui_menu_insert_action(help_menu,
                                                        i + 1,
                                                        action_id_kca_help,
                                                        0);
                                refresh = TRUE;
                                break;
                            }
                        }
                    }

                    khui_action_unlock();

                    if (refresh)
                        khui_refresh_actions();
                }

#if KH_VERSION_API < 7
            no_custom_help:
                ;
#endif
            }
        }
        break;

        /* This is the last message that will be received by the
           plugin. */
    case KMSG_SYSTEM_EXIT:
        {
            khui_config_node cnode;
            khui_config_node cn_idents;
            khm_int32 attr_id;

            kca_remove_icon();

            /* It should not be assumed that initialization of the
               plugin went well at this point since we receive a
               KMSG_SYSTEM_EXIT even if the initialization failed. */

            /* Try to remove the KCA plug-in action from Help menu if
               it was successfully registered.  Also, delete the
               action. */
            if (action_id_kca_help != 0) {

                khui_menu_def * help_menu;
                khm_boolean menu_changed = FALSE;

                khui_action_lock();

                help_menu = khui_find_menu(KHUI_MENU_HELP);
                if (help_menu) {
                    khm_size s;
                    khm_size i;

                    s = khui_menu_get_size(help_menu);
                    for (i=0; i < s; i++) {
                        khui_action_ref * aref = khui_menu_get_action(help_menu, i);

                        if (aref && !(aref->flags & KHUI_ACTIONREF_PACTION) &&
                            aref->action == action_id_kca_help) {

                            khui_menu_remove_action(help_menu, i);
                            menu_changed = TRUE;
                            break;

                        }
                    }
                }

                khui_action_delete(action_id_kca_help);

                khui_action_unlock();

                if (menu_changed)
                    khui_refresh_actions();

                action_id_kca_help = 0;
            }

            if (credtype_id != KCDB_CREDTYPE_INVALID) {
                kcdb_credtype_unregister(credtype_id);
                credtype_id = KCDB_CREDTYPE_INVALID;
            }

            if (g_credset) {
                kcdb_credset_delete(g_credset);
                g_credset = NULL;
            }

            /* Now unregister any configuration nodes we registered. */

            if (KHM_SUCCEEDED(khui_cfg_open(NULL, CONFIGNODE_MAIN, &cnode))) {
                khui_cfg_remove(cnode);
                khui_cfg_release(cnode);
            }

            if (KHM_SUCCEEDED(khui_cfg_open(NULL, L"KhmIdentities", &cn_idents))) {
                if (KHM_SUCCEEDED(khui_cfg_open(cn_idents,
                                                CONFIGNODE_ALL_ID,
                                                &cnode))) {
                    khui_cfg_remove(cnode);
                    khui_cfg_release(cnode);
                }

                if (KHM_SUCCEEDED(khui_cfg_open(cn_idents,
                                                CONFIGNODE_PER_ID,
                                                &cnode))) {
                    khui_cfg_remove(cnode);
                    khui_cfg_release(cnode);
                }

                khui_cfg_release(cn_idents);
            }

            if (KHM_SUCCEEDED(kcdb_attrib_get_id(ATTRNAME_KCA_AUTHREALM,
                                                 &attr_id)))
                kcdb_attrib_unregister(attr_id);

            if (KHM_SUCCEEDED(kcdb_attrib_get_id(ATTRNAME_SUBJECT_EMAIL,
                                                 &attr_id)))
                kcdb_attrib_unregister(attr_id);

            if (KHM_SUCCEEDED(kcdb_attrib_get_id(ATTRNAME_SUBJECT_DISPLAY,
                                                 &attr_id)))
                kcdb_attrib_unregister(attr_id);

            if (KHM_SUCCEEDED(kcdb_attrib_get_id(ATTRNAME_ISSUER_DISPLAY,
                                                 &attr_id)))
                kcdb_attrib_unregister(attr_id);

            if (KHM_SUCCEEDED(kcdb_attrib_get_id(ATTRNAME_ISSUER_NAME,
                                                 &attr_id)))
                kcdb_attrib_unregister(attr_id);

            if (KHM_SUCCEEDED(kcdb_attrib_get_id(ATTRNAME_SERIAL,
                                                 &attr_id)))
                kcdb_attrib_unregister(attr_id);

            if (csp_params) {
                khc_close_space(csp_params);
                csp_params = NULL;
            }

#if KH_VERSION_API < 12
            if (hm_netidmgr)
                FreeLibrary(hm_netidmgr);

            pkhui_cw_get_primary_id = NULL;
#endif

#if KH_VERSION_API < 7
            pkhui_action_lock = NULL;
            pkhui_action_unlock = NULL;
            pkhui_refresh_actions = NULL;
            pkhui_request_UI_callback = NULL;
#endif

            /* TODO: Perform additional uninitialization
               operations. */
        }
        break;
    }

    return rv;
}

/* Handler for credentials the refresh message. */
khm_int32
handle_kmsg_cred_refresh(void) {
    kca_list_creds();
    return KHM_ERROR_SUCCESS;
}

/* Handler for destroying credentials */
khm_int32
handle_kmsg_cred_destroy_creds(khui_action_context * ctx) {
    return kca_del_matching_creds(ctx->credset);
}

/* Begin a property sheet */
khm_int32
handle_kmsg_cred_pp_begin(khui_property_sheet * ps) {

    /* TODO: Provide the information necessary to show a property
       page for a credentials belonging to our credential type. */

    PROPSHEETPAGE *p;

    if (ps->credtype == credtype_id &&
        ps->cred) {
        /* We have been requested to show a property sheet for one of
           our credentials. */
        p = malloc(sizeof(*p));
        ZeroMemory(p, sizeof(*p));

        p->dwSize = sizeof(*p);
        p->dwFlags = 0;
        p->hInstance = hResModule;
        p->pszTemplate = MAKEINTRESOURCE(IDD_PP_CRED);
        p->pfnDlgProc = pp_cred_dlg_proc;
        p->lParam = (LPARAM) ps;
        khui_ps_add_page(ps, credtype_id, 0, p, NULL);
    }

    return KHM_ERROR_SUCCESS;
}

/* End a property sheet */
khm_int32
handle_kmsg_cred_pp_end(khui_property_sheet * ps) {
    /* TODO: Handle the end of a property sheet. */

    khui_property_page * p = NULL;

    khui_ps_find_page(ps, credtype_id, &p);
    if (p) {
        if (p->p_page)
            free(p->p_page);
        p->p_page = NULL;
    }

    return KHM_ERROR_SUCCESS;
}

/* IP address change notification */
khm_int32
handle_kmsg_cred_addr_change(void) {
    /* TODO: Handle this message. */

    return KHM_ERROR_SUCCESS;
}

/* Message dispatcher for credentials messages. */
khm_int32 KHMAPI
handle_kmsg_cred(khm_int32 msg_type,
                 khm_int32 msg_subtype,
                 khm_ui_4  uparam,
                 void *    vparam) {
    khm_int32 rv = KHM_ERROR_SUCCESS;

    switch(msg_subtype) {
    case KMSG_CRED_REFRESH:
        return handle_kmsg_cred_refresh();

    case KMSG_CRED_DESTROY_CREDS:
        return handle_kmsg_cred_destroy_creds((khui_action_context *) vparam);

    case KMSG_CRED_PP_BEGIN:
        return handle_kmsg_cred_pp_begin((khui_property_sheet *) vparam);

    case KMSG_CRED_PP_END:
        return handle_kmsg_cred_pp_end((khui_property_sheet *) vparam);

    case KMSG_CRED_ADDR_CHANGE:
        return handle_kmsg_cred_addr_change();

    default:
        /* Credentials acquisition messages are all handled in a
           different source file. */
        if (IS_CRED_ACQ_MSG(msg_subtype))
            return handle_cred_acq_msg(msg_type, msg_subtype,
                                       uparam, vparam);
    }

    return rv;
}

khm_int32 KHMAPI
help_launcher(HWND hwnd_main, void * rock) {
    wchar_t helploc[MAX_PATH + MAX_PATH];

    get_help_file(helploc, sizeof(helploc));

    HtmlHelp(hwnd_main, helploc, HH_DISPLAY_TOC, 0);

    return KHM_ERROR_SUCCESS;
}

khm_int32 KHMAPI
handle_kmsg_act(khm_int32 msg_type,
               khm_int32 msg_subtype,
               khm_ui_4  uparam,
               void *    vparam) {

    khm_int32 rv = KHM_ERROR_SUCCESS;

    if (msg_subtype == KMSG_ACT_ACTIVATE) {
        khui_request_UI_callback(help_launcher, NULL);
    }

    return rv;
}


/* This is the main message handler for our plugin.  All the plugin
   messages end up here where we either handle it directly or dispatch
   it to other handlers. */
khm_int32 KHMAPI plugin_msg_proc(khm_int32 msg_type,
                                 khm_int32 msg_subtype,
                                 khm_ui_4  uparam,
                                 void * vparam) {

    switch(msg_type) {
    case KMSG_SYSTEM:
        return handle_kmsg_system(msg_type, msg_subtype, uparam, vparam);

    case KMSG_CRED:
        return handle_kmsg_cred(msg_type, msg_subtype, uparam, vparam);

    case KMSG_ACT:
        return handle_kmsg_act(msg_type, msg_subtype, uparam, vparam);
    }

    return KHM_ERROR_SUCCESS;
}
