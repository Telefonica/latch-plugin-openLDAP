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

enum {
    LATCH_OVERLAY_EXCLUDE = 1,
    LATCH_OVERLAY_PATTERN,
    LATCH_OVERLAY_LAST
};

static ConfigDriver latch_overlay_config_gen;

ConfigTable latch_overlay_config[] = {
        { "latch-application-id", "string", 2, 2, 0,
          ARG_STRING | ARG_OFFSET,
          (void *) offsetof(latch_overlay_config_data, application_id),
          "( OLcfgOvAt:99.1 "
          "NAME 'olcLatchApplicationId' "
          "DESC 'Latch Application Id' "
          "SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
        { "latch-secret", "string", 2, 2, 0,
          ARG_STRING | ARG_OFFSET,
          (void *) offsetof(latch_overlay_config_data, secret),
          "( OLcfgOvAt:99.2 "
          "NAME 'olcLatchSecret' "
          "DESC 'Latch Secret' "
          "SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
        { "latch-operation-id", "string", 2, 2, 0,
          ARG_STRING | ARG_OFFSET,
          (void *) offsetof(latch_overlay_config_data, operation_id),
          "( OLcfgOvAt:99.3 "
          "NAME 'olcLatchOperationId' "
          "DESC 'Latch Operation Id' "
          "SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
        { "latch-sdk-host", "string", 2, 2, 0,
          ARG_STRING | ARG_OFFSET,
          (void *) offsetof(latch_overlay_config_data, sdk_host),
          "( OLcfgOvAt:99.4 "
          "NAME 'olcLatchSDKHost' "
          "DESC 'Latch SDK Host' "
          "SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
        { "latch-sdk-proxy", "string", 2, 2, 0,
          ARG_STRING | ARG_OFFSET,
          (void *) offsetof(latch_overlay_config_data, sdk_proxy),
          "( OLcfgOvAt:99.5 "
          "NAME 'olcLatchSDKProxy' "
          "DESC 'Latch SDK Proxy' "
          "SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
        { "latch-sdk-timeout", "int", 2, 2, 0,
          ARG_INT | ARG_OFFSET,
          (void *) offsetof(latch_overlay_config_data, sdk_timeout),
          "( OLcfgOvAt:99.6 "
          "NAME 'olcLatchSDKTimeout' "
          "DESC 'Latch SDK Timeout' "
          "SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
        { "latch-sdk-curl-nosignal", "int", 2, 2, 0,
          ARG_INT | ARG_OFFSET,
          (void *) offsetof(latch_overlay_config_data, sdk_curl_nosignal),
          "( OLcfgOvAt:99.7 "
          "NAME 'olcLatchSDKCURLNoSignal' "
          "DESC 'Latch SDK CURL NoSignal' "
          "SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
        { "latch-sdk-tls-ca-file", "string", 2, 2, 0,
          ARG_STRING | ARG_OFFSET,
          (void *) offsetof(latch_overlay_config_data, sdk_tls_ca_file),
          "( OLcfgOvAt:99.8 "
          "NAME 'olcLatchSDKTLSCAFile' "
          "DESC 'Latch SDK TLS CA File' "
          "SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
        { "latch-sdk-tls-ca-path", "string", 2, 2, 0,
          ARG_STRING | ARG_OFFSET,
          (void *) offsetof(latch_overlay_config_data, sdk_tls_ca_path),
          "( OLcfgOvAt:99.9 "
          "NAME 'olcLatchSDKTLSCAPath' "
          "DESC 'Latch SDK TLS CA Path' "
          "SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
        { "latch-sdk-tls-crl-file", "string", 2, 2, 0,
          ARG_STRING | ARG_OFFSET,
          (void *) offsetof(latch_overlay_config_data, sdk_tls_crl_file),
          "( OLcfgOvAt:99.10 "
          "NAME 'olcLatchSDKTLSCRLFile' "
          "DESC 'Latch SDK TLS CRL File' "
          "SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
        { "latch-exclude", "pattern", 2, 2, 0,
          ARG_MAGIC | LATCH_OVERLAY_EXCLUDE,
          latch_overlay_config_gen,
          "( OLcfgOvAt:99.11 "
          "NAME 'olcLatchExclude' "
          "DESC 'Latch Excluded DNs' "
          "EQUALITY caseIgnoreMatch "
          "SYNTAX OMsDirectoryString )", NULL, NULL },
        { "latch-pattern", "pattern", 2, 2, 0,
          ARG_MAGIC | LATCH_OVERLAY_PATTERN,
          latch_overlay_config_gen,
          "( OLcfgOvAt:99.12 "
          "NAME 'olcLatchPattern' "
          "DESC 'Latch DN Pattern' "
          "SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
        { "latch-ldap-uri", "uri", 2, 2, 0,
          ARG_STRING | ARG_OFFSET,
          (void *) offsetof(latch_overlay_config_data, ldap_uri),
          "( OLcfgOvAt:99.13 "
          "NAME 'olcLatchLDAPURI' "
          "DESC 'Latch LDAP URI' "
          "SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
        { "latch-ldap-bind-dn", "uri", 2, 2, 0,
          ARG_STRING | ARG_OFFSET,
          (void *) offsetof(latch_overlay_config_data, ldap_bind_dn),
          "( OLcfgOvAt:99.14 "
          "NAME 'olcLatchLDAPBindDN' "
          "DESC 'Latch LDAP Bind DN' "
          "SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
        { "latch-ldap-bind-password", "uri", 2, 2, 0,
          ARG_STRING | ARG_OFFSET,
          (void *) offsetof(latch_overlay_config_data, ldap_bind_password),
          "( OLcfgOvAt:99.15 "
          "NAME 'olcLatchLDAPBindPassword' "
          "DESC 'Latch LDAP Bind Password' "
          "SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
        { "latch-ldap-search-base-dn", "dn", 2, 2, 0,
          ARG_STRING | ARG_OFFSET,
          (void *) offsetof(latch_overlay_config_data, ldap_search_base_dn),
          "( OLcfgOvAt:99.16 "
          "NAME 'olcLatchLDAPSearchBaseDN' "
          "DESC 'Latch LDAP Search Base DN' "
          "SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
        { "latch-ldap-search-filter", "filter", 2, 2, 0,
          ARG_STRING | ARG_OFFSET,
          (void *) offsetof(latch_overlay_config_data, ldap_search_filter),
          "( OLcfgOvAt:99.17 "
          "NAME 'olcLatchLDAPSearchFilter' "
          "DESC 'Latch LDAP Search Filter' "
          "SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
        { "latch-ldap-search-scope", "scope", 2, 2, 0,
          ARG_STRING | ARG_OFFSET,
          (void *) offsetof(latch_overlay_config_data, ldap_search_scope),
          "( OLcfgOvAt:99.18 "
          "NAME 'olcLatchLDAPSearchScope' "
          "DESC 'Latch LDAP Search Scope' "
          "SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
        { "latch-ldap-attribute", "attribute", 2, 2, 0,
          ARG_STRING | ARG_OFFSET,
          (void *) offsetof(latch_overlay_config_data, ldap_attribute),
          "( OLcfgOvAt:99.19 "
          "NAME 'olcLatchLDAPAttribute' "
          "DESC 'Latch LDAP Attribute' "
          "SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
        { "latch-ldap-tls-ca-file", "file", 2, 2, 0,
          ARG_STRING | ARG_OFFSET,
          (void *) offsetof(latch_overlay_config_data, ldap_tls_ca_file),
          "( OLcfgOvAt:99.20 "
          "NAME 'olcLatchLDAPTLSCAFile' "
          "DESC 'Latch LDAP TLS CA file' "
          "SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
        { "latch-required", "int", 2, 2, 0,
          ARG_INT | ARG_OFFSET,
          (void *) offsetof(latch_overlay_config_data, required),
          "( OLcfgOvAt:99.21 "
          "NAME 'olcLatchRequired' "
          "DESC 'Latch Required' "
          "SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
        { "latch-sdk-stop-on-error", "int", 2, 2, 0,
          ARG_INT | ARG_OFFSET,
          (void *) offsetof(latch_overlay_config_data, sdk_stop_on_error),
          "( OLcfgOvAt:99.22 "
          "NAME 'olcLatchSDKStopOnError' "
          "DESC 'Latch SDK Stop On Error' "
          "SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
        { "latch-ldap-stop-on-error", "int", 2, 2, 0,
          ARG_INT | ARG_OFFSET,
          (void *) offsetof(latch_overlay_config_data, ldap_stop_on_error),
          "( OLcfgOvAt:99.23 "
          "NAME 'olcLatchLDAPStopOnError' "
          "DESC 'Latch LDAP Stop On Error' "
          "SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
        { NULL, NULL, 0, 0, 0, ARG_IGNORED }
};

ConfigOCs latch_overlay_ocs[] = {
        { "( OLcfgOvOc:99.1 "
          "NAME 'olcLatchOverlayConfig' "
          "DESC 'Latch Overlay Configuration' "
          "SUP olcOverlayConfig "
          "MAY ( olcLatchApplicationId $"
          "      olcLatchSecret $"
          "      olcLatchOperationId $"
          "      olcLatchSDKHost $"
          "      olcLatchSDKProxy $"
          "      olcLatchSDKTimeout $"
          "      olcLatchSDKCURLNoSignal $"
          "      olcLatchSDKStopOnError $"
          "      olcLatchSDKTLSCAFile $"
          "      olcLatchSDKTLSCAPath $"
          "      olcLatchSDKTLSCRLFile $"
          "      olcLatchExclude $"
          "      olcLatchPattern $"
          "      olcLatchLDAPURI $"
          "      olcLatchLDAPBindDN $"
          "      olcLatchLDAPBindPassword $"
          "      olcLatchLDAPSearchBaseDN $"
          "      olcLatchLDAPSearchFilter $"
          "      olcLatchLDAPSearchScope $"
          "      olcLatchLDAPAttribute $"
          "      olcLatchLDAPTLSCAFile $"
          "      olcLatchLDAPStopOnError $"
          "      olcLatchRequired"
          "    )"
          ")",
          Cft_Overlay, latch_overlay_config },
        { NULL, 0, NULL }
};

static int latch_overlay_config_gen(ConfigArgs *c) {

    char **aux = NULL;
    char *auxvalue = NULL;
    int i = 0;
    int rc = 0;
    int new_excludes_length = 0;
    int old_excludes_length = 0;
    latch_overlay_config_data *cfg;
    struct berval auxberval;
    slap_overinst *on;

    Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, ">>> %s\n", __func__);

    on = (slap_overinst *) c->bi;
    cfg = (latch_overlay_config_data *) on->on_bi.bi_private;

    switch (c->op) {

    case SLAP_CONFIG_EMIT:

        Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: case SLAP_CONFIG_EMIT\n", __func__);

        switch (c->type) {

        case LATCH_OVERLAY_EXCLUDE:

            Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: case LATCH_OVERLAY_EXCLUDE\n", __func__);

            aux = cfg->excludes;

            while (*aux != NULL) {

                auxvalue = strdup(*aux);

                auxberval.bv_val = auxvalue;
                auxberval.bv_len = strlen(auxvalue);

                value_add_one(&c->rvalue_vals, &auxberval);
                value_add_one(&c->rvalue_nvals, &auxberval);

                free(auxvalue);
                auxvalue = NULL;

                aux++;

            }

            break;

        case LATCH_OVERLAY_PATTERN:

            Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: case LATCH_OVERLAY_PATTERN\n", __func__);

            if (cfg->pattern != NULL) {
                ber_str2bv(cfg->pattern, 0, 0, &auxberval);
                value_add_one(&c->rvalue_vals, &auxberval);
            }

            break;

        default:

            abort();

        }

        break;

    case LDAP_MOD_DELETE:

        Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: LDAP_MOD_DELETE\n", __func__);

        switch (c->type) {

        case LATCH_OVERLAY_EXCLUDE:

            Log2(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: case LATCH_OVERLAY_EXCLUDE %d\n", __func__, c->valx);

            if (c->valx >= 0) {

                free(cfg->excludes[c->valx]);

                for (i = c->valx; cfg->excludes[i] != NULL; i++) {
                    cfg->excludes[i] = cfg->excludes[i + 1];
                }

                for (i = 0; cfg->excludes[i] != NULL; i++) {
                    Log3(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: cfg->excludes[%d] %s\n", __func__, i, cfg->excludes[i]);
                }

            } else {

                for (i = 0; cfg->excludes[i] != NULL; i++) {

                    Log2(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: Freeing cfg->excludes[%d]\n", __func__, i);

                    free(cfg->excludes[i]);
                    cfg->excludes[i] = NULL;

                }

            }

            break;

        case LATCH_OVERLAY_PATTERN:

            Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: case LATCH_OVERLAY_PATTERN\n", __func__);

            free(cfg->pattern);
            cfg->pattern = NULL;

            break;

        default:

            abort();

        }

        break;

    case SLAP_CONFIG_ADD:
    case LDAP_MOD_ADD:

        Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: SLAP_CONFIG_ADD | LDAP_MOD_ADD\n", __func__);

        switch (c->type) {

        case LATCH_OVERLAY_EXCLUDE:

            Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: case LATCH_OVERLAY_EXCLUDE\n", __func__);

            aux = cfg->excludes;

            while (*aux != NULL) {
                aux++;
                old_excludes_length++;
            }

            new_excludes_length = old_excludes_length + 1;

            cfg->excludes = ch_realloc(cfg->excludes, (new_excludes_length + 1) * sizeof(char*));

            cfg->excludes[new_excludes_length - 1] = strdup(c->argv[1]);
            cfg->excludes[new_excludes_length] = NULL;

            break;

        case LATCH_OVERLAY_PATTERN:

            Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: case LATCH_OVERLAY_PATTERN\n", __func__);

            cfg->pattern = strdup(c->argv[1]);

            break;

        default:

            abort();

        }

        break;

    default:

        abort();

    }

    Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "<<< %s\n", __func__);

    return rc;

}

#endif /* SLAPD_OVER_LATCH */
