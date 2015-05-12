/*
 * Latch plugin for OpenLDAP 2.4
 * Copyright (C) 2014 Eleven Paths
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License, version 2.1 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include "portable.h"

#ifdef SLAPD_OVER_LATCH

#include "slap.h"
#include "config.h"

#include "latch-overlay.h"

#include "json/json.h"

static char*
latch_overlay_get_account_id(latch_overlay_config_data *cfg, char *id) {

    LDAP *ld;
    int ldap_result;
    struct berval credentials;
    int version = LDAP_VERSION3;
    int tls_new_ctx = 0;
    int ldap_search_scope = LDAP_SCOPE_BASE;
    char *search_base_dn = NULL;
    char *search_filter = NULL;
    char *search_attributes[] = { cfg->ldap_attribute, NULL };
    LDAPMessage *result = NULL;
    LDAPMessage *entry = NULL;
    char *attr = NULL;
    BerElement *ber = NULL;
    struct berval **bvals = NULL;
    char *rv = NULL;

    Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, ">>> %s\n", __func__);

    search_base_dn = replace_str(cfg->ldap_search_base_dn, "@@@USER@@@", id);
    search_filter = replace_str(cfg->ldap_search_filter, "@@@USER@@@", id);

    if (cfg->ldap_search_scope != NULL) {
        if (strcmp("onelevel", cfg->ldap_search_scope) == 0) {
            ldap_search_scope = LDAP_SCOPE_ONELEVEL;
        }
        else if (strcmp("subtree", cfg->ldap_search_scope) == 0) {
            ldap_search_scope = LDAP_SCOPE_SUBTREE;
        }
    }

    /* Initialize connection to LDAP server */

    ldap_result = ldap_initialize(&ld, cfg->ldap_uri);

    if (LDAP_SUCCESS != ldap_result) {
        Log2(LDAP_DEBUG_ANY, LDAP_LEVEL_ERR, "    %s: Failed to initialize LDAP connection. Error: %s\n", __func__, ldap_err2string(ldap_result));
    }
    else {

        /* Set LDAP version. */

        ldap_result = ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);

        if (LDAP_OPT_SUCCESS != ldap_result) {
            Log3(LDAP_DEBUG_ANY, LDAP_LEVEL_ERR, "    %s: Unable to set LDAP protocol version to %d. Error: %s\n", __func__, version, ldap_err2string(ldap_result));
        }
        else {

            /* If LDAPS set the CA certificates file */

            if (strncasecmp(cfg->ldap_uri, "ldaps://", strlen("ldaps://")) == 0) {

                ldap_result = ldap_set_option(ld, LDAP_OPT_X_TLS_CACERTFILE, cfg->ldap_tls_ca_file);

                if (LDAP_OPT_SUCCESS != ldap_result) {
                    Log3(LDAP_DEBUG_ANY, LDAP_LEVEL_ERR, "    %s: Unable to set the TLS CA file to %s. Error: %s\n", __func__, cfg->ldap_tls_ca_file, ldap_err2string(ldap_result));
                }

                ldap_result = ldap_set_option(ld, LDAP_OPT_X_TLS_NEWCTX, &tls_new_ctx);

                if (LDAP_OPT_SUCCESS != ldap_result) {
                    Log3(LDAP_DEBUG_ANY, LDAP_LEVEL_ERR, "    %s: Unable to set the TLS NEWCTX option to %d. Error: %s\n", __func__, tls_new_ctx, ldap_err2string(ldap_result));
                }

            }

            if (cfg->ldap_bind_dn != NULL && cfg->ldap_bind_password != NULL) {

                /* We try to bind with provided credentials */

                credentials.bv_val = cfg->ldap_bind_password;
                credentials.bv_len = strlen(cfg->ldap_bind_password);

                ldap_result = ldap_sasl_bind_s(ld, cfg->ldap_bind_dn, LDAP_SASL_SIMPLE, &credentials, NULL, NULL, NULL);

            }
            else {

                /* Anonymous bind */

                credentials.bv_val = NULL;
                credentials.bv_len = 0;

                ldap_result = ldap_sasl_bind_s(ld, NULL, LDAP_SASL_SIMPLE, &credentials, NULL, NULL, NULL);

            }

            if (LDAP_SUCCESS != ldap_result) {
                Log2(LDAP_DEBUG_ANY, LDAP_LEVEL_ERR, "    %s: Failed to bind to LDAP server. Error: %s\n", __func__, ldap_err2string(ldap_result));
            }
            else {

                /* Search the LDAP for the user entry */

                ldap_result = ldap_search_ext_s(ld, search_base_dn, ldap_search_scope, search_filter, search_attributes, 0, NULL, NULL, NULL, LDAP_NO_LIMIT, &result );

                if (LDAP_SUCCESS != ldap_result) {
                    Log2(LDAP_DEBUG_ANY, LDAP_LEVEL_ERR, "    %s: Failed to search the LDAP server. Error: %s\n", __func__, ldap_err2string(ldap_result));
                }
                else {

                    if ((entry = ldap_first_entry(ld, result)) == NULL) {
                        Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: No entries found.\n", __func__);
                    }
                    else {

                        for (attr = ldap_first_attribute(ld, entry, &ber) ; attr != NULL ; attr = ldap_next_attribute(ld, entry, ber)) {

                            Log2(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: Processing attribute %s\n", __func__, attr);

                            if (strcmp(cfg->ldap_attribute, attr) == 0) {

                                if ((bvals = ldap_get_values_len(ld, entry, attr)) != NULL) {

                                    if (bvals[0] != NULL) {

                                        rv = malloc((bvals[0]->bv_len + 1) * sizeof(char));

                                        memcpy(rv, bvals[0]->bv_val, bvals[0]->bv_len);
                                        rv[bvals[0]->bv_len] = '\0';

                                        Log2(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: Returning attribute value %s\n", __func__, rv);

                                    }

                                    ldap_value_free_len(bvals);

                                }

                            }

                            ldap_memfree(attr);

                        }

                        if (ber != NULL) {
                            ber_free(ber, 0);
                        }

                    }

                    ldap_msgfree(result);

                }

            }

        }

        ldap_unbind_ext( ld, NULL, NULL );

    }

    free(search_base_dn);
    free(search_filter);

    Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "<<< %s\n", __func__);

    return rv;

}

int latch_overlay_check_latch(latch_overlay_config_data *cfg, char *id) {

    int rc = LATCH_STATUS_UNLOCKED;
    char *account_id = NULL;
    char *response = NULL;
    json_object *json_response = NULL;
    json_object *json_data = NULL;
    json_object *json_operations = NULL;
    json_object *json_application = NULL;
    json_bool json_application_rc = FALSE;
    json_object *json_status = NULL;

    Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, ">>> %s\n", __func__);

    if ((account_id = latch_overlay_get_account_id(cfg, id)) != NULL) {

        Log2(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: account_id %s\n", __func__, account_id);

        if (cfg->operation_id == NULL) {
            response = status(account_id);
        } else {
            response = operationStatus(account_id, cfg->operation_id);
        }

        if (response != NULL) {

            Log2(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: response %s\n", __func__, response);

            json_response = json_tokener_parse(response);

            if (json_response != NULL) {

                if ((json_object_object_get_ex(json_response, "data", &json_data) == TRUE) && (json_data != NULL)) {

                    if ((json_object_object_get_ex(json_data, "operations", &json_operations) == TRUE) && (json_operations != NULL)) {

                        if (cfg->operation_id == NULL) {
                            json_application_rc = json_object_object_get_ex(json_operations, cfg->application_id, &json_application);
                        } else {
                            json_application_rc = json_object_object_get_ex(json_operations, cfg->operation_id, &json_application);
                        }

                        if ((json_application_rc) == TRUE && (json_application != NULL)) {
                            if ((json_object_object_get_ex(json_application, "status", &json_status) == TRUE) && (json_status != NULL)) {
                                if (json_object_get_string(json_status) != NULL && strcmp("off", json_object_get_string(json_status)) == 0) {
                                    rc = LATCH_STATUS_LOCKED;
                                }
                            }
                        }

                    }

                }

                json_object_put(json_response);

            }

            free(response);

        }
        else {

            Log1(LDAP_DEBUG_ANY, LDAP_LEVEL_ERR, "    %s: There has been an error communicating with the backend\n", __func__);

        }

        free(account_id);

    }

    Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "<<< %s\n", __func__);

    return rc;

}

#endif /* SLAPD_OVER_LATCH */
