/*
 * Latch plugin for OpenLDAP 2.4
 * Copyright (C) 2014, 2015 Eleven Paths
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

int
latch_overlay_get_entry_attribute(
        char  *uri,
        char  *bind_dn,
        char  *bind_password,
        char  *search_base_dn,
        char  *search_filter,
         int   search_scope,
        char  *attribute_name,
        char  *tls_ca_file,
        char **attribute_value)
{

    LDAP *ld;
    int ldap_result;
    struct berval credentials;
    int version = LDAP_VERSION3;
    int tls_new_ctx = 0;
    char *search_attributes[] = { attribute_name, NULL };
    LDAPMessage *result = NULL;
    LDAPMessage *entry = NULL;
    char *attr = NULL;
    BerElement *ber = NULL;
    struct berval **bvals = NULL;
    int rv = ERROR;

    Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, ">>> %s\n", __func__);

    /* Initialize connection to LDAP server */

    ldap_result = ldap_initialize(&ld, uri);

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

            if (strncasecmp(uri, "ldaps://", strlen("ldaps://")) == 0) {

                ldap_result = ldap_set_option(ld, LDAP_OPT_X_TLS_CACERTFILE, tls_ca_file);

                if (LDAP_OPT_SUCCESS != ldap_result) {
                    Log3(LDAP_DEBUG_ANY, LDAP_LEVEL_ERR, "    %s: Unable to set the TLS CA file to %s. Error: %s\n", __func__, tls_ca_file, ldap_err2string(ldap_result));
                }

                ldap_result = ldap_set_option(ld, LDAP_OPT_X_TLS_NEWCTX, &tls_new_ctx);

                if (LDAP_OPT_SUCCESS != ldap_result) {
                    Log3(LDAP_DEBUG_ANY, LDAP_LEVEL_ERR, "    %s: Unable to set the TLS NEWCTX option to %d. Error: %s\n", __func__, tls_new_ctx, ldap_err2string(ldap_result));
                }

            }

            if (bind_dn != NULL && bind_password != NULL) {

                /* We try to bind with provided credentials */

                credentials.bv_val = bind_password;
                credentials.bv_len = strlen(bind_password);

                ldap_result = ldap_sasl_bind_s(ld, bind_dn, LDAP_SASL_SIMPLE, &credentials, NULL, NULL, NULL);

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

                ldap_result = ldap_search_ext_s(ld, search_base_dn, search_scope, search_filter, search_attributes, 0, NULL, NULL, NULL, LDAP_NO_LIMIT, &result );

                if (LDAP_SUCCESS != ldap_result) {
                    Log2(LDAP_DEBUG_ANY, LDAP_LEVEL_ERR, "    %s: Failed to search the LDAP server. Error: %s\n", __func__, ldap_err2string(ldap_result));
                }
                else {

                    rv = OK;

                    if ((entry = ldap_first_entry(ld, result)) == NULL) {
                        Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: No entries found.\n", __func__);
                    }
                    else {

                        for (attr = ldap_first_attribute(ld, entry, &ber) ; attr != NULL ; attr = ldap_next_attribute(ld, entry, ber)) {

                            Log2(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: Processing attribute %s\n", __func__, attr);

                            if (strcmp(attribute_name, attr) == 0) {

                                if ((bvals = ldap_get_values_len(ld, entry, attr)) != NULL) {

                                    if (bvals[0] != NULL) {

                                        *attribute_value = malloc((bvals[0]->bv_len + 1) * sizeof(char));

                                        memcpy(*attribute_value, bvals[0]->bv_val, bvals[0]->bv_len);

                                        (*attribute_value)[bvals[0]->bv_len] = '\0';

                                        Log2(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: Returning attribute value %s\n", __func__, *attribute_value);

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

    Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "<<< %s\n", __func__);

    return rv;

}

#endif /* SLAPD_OVER_LATCH */
