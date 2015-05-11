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

#include "pcre.h"

#define DEFAULT_PATTERN "uid=(.*?),.*"

static slap_overinst latch_overlay;

static int latch_overlay_bind_response(Operation *op, SlapReply *rs) {

    int i = 0;
    int rv = 0;
    int error_offset = 0;
    int excluded = 0;
    int match_offset[6];
    char *dn = NULL;
    char *id = NULL;
    const char *error;
    latch_overlay_config_data *cfg = NULL;
    pcre *exclude_re;
    pcre *re;

    Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, ">>> %s\n", __func__);

    if (rs->sr_err != LDAP_SUCCESS) {
        Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "<<< %s\n", __func__);
        return SLAP_CB_CONTINUE;
    }

    cfg = (latch_overlay_config_data *) op->o_callback->sc_private;

    /* We check that the required parameters are configured */

    if (cfg->application_id == NULL) {
        Log1(LDAP_DEBUG_ANY, LDAP_LEVEL_ERR, "    %s failed. No latchApplicationId in configuration!\n", __func__);
        Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "<<< %s\n", __func__);
        return SLAP_CB_CONTINUE;
    }

    if (cfg->secret == NULL) {
        Log1(LDAP_DEBUG_ANY, LDAP_LEVEL_ERR, "    %s failed. No latchSecret in configuration!\n", __func__);
        Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "<<< %s\n", __func__);
        return SLAP_CB_CONTINUE;
    }

    if (cfg->pattern == NULL) {
        Log2(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: No latchPattern in configuration. Using %s\n", __func__, DEFAULT_PATTERN);
    }

    if (cfg->ldap_uri == NULL) {
        Log1(LDAP_DEBUG_ANY, LDAP_LEVEL_ERR, "    %s failed. No latchLDAPURI in configuration!\n", __func__);
        Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "<<< %s\n", __func__);
        return SLAP_CB_CONTINUE;
    }

    if (cfg->ldap_search_base_dn == NULL) {
        Log1(LDAP_DEBUG_ANY, LDAP_LEVEL_ERR, "    %s failed. No latchLDAPSearchBaseDN in configuration!\n", __func__);
        Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "<<< %s\n", __func__);
        return SLAP_CB_CONTINUE;
    }

    if (cfg->ldap_search_filter == NULL) {
        Log1(LDAP_DEBUG_ANY, LDAP_LEVEL_ERR, "    %s failed. No latchLDAPSearchFilter in configuration!\n", __func__);
        Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "<<< %s\n", __func__);
        return SLAP_CB_CONTINUE;
    }

    if (cfg->ldap_attribute == NULL) {
        Log1(LDAP_DEBUG_ANY, LDAP_LEVEL_ERR, "    %s failed. No latchLDAPAttribute in configuration!\n", __func__);
        Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "<<< %s\n", __func__);
        return SLAP_CB_CONTINUE;
    }

    if (strncasecmp(cfg->ldap_uri, "ldaps://", strlen("ldaps://")) == 0) {
        if (cfg->ldap_tls_ca_file == NULL) {
            Log1(LDAP_DEBUG_ANY, LDAP_LEVEL_ERR, "    %s failed. No latchLDAPTLSCAFile in configuration!\n", __func__);
            Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "<<< %s\n", __func__);
            return SLAP_CB_CONTINUE;
        }
    }

    /* We check if the DN is in the exclude list */

    dn = malloc((op->o_req_ndn.bv_len + 1) * sizeof(char));

    memcpy(dn, op->o_req_ndn.bv_val, op->o_req_ndn.bv_len);
    dn[op->o_req_ndn.bv_len] = '\0';

    Log2(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: DN %s\n", __func__, dn);

    /* TODO Precompiled regex */

    if (cfg->excludes != NULL) {

        for (i = 0; cfg->excludes[i] != NULL; i++) {

            Log2(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: Checking exclude %s\n", __func__, cfg->excludes[i]);

            if ((exclude_re = pcre_compile(cfg->excludes[i], 0, &error, &error_offset, NULL)) != NULL) {

                if ((rv = pcre_exec(exclude_re, NULL, dn, strlen(dn), 0, 0, match_offset, 6)) > 0) {

                    Log2(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: dn matched exclude %s\n", __func__, cfg->excludes[i]);

                    excluded = 1;

                    /* TODO break on first match but free memory */

                }

                free(exclude_re);

            } else {

                Log4(LDAP_DEBUG_ANY, LDAP_LEVEL_ERR, "    %s: Error compiling regex %s. Error: %s (%d)\n", __func__, cfg->excludes[i], error, error_offset);

            }

        }

    }

    if (excluded == 0) {

        /* And we initialize and configure the Latch SDK. Unexpected results for more than one overlay */

        init(cfg->application_id, cfg->secret);

        if (cfg->sdk_host != NULL) {
            setHost(cfg->sdk_host);
        }

        if (cfg->sdk_proxy != NULL) {
            setProxy(cfg->sdk_proxy);
        }

        setTimeout(cfg->sdk_timeout);

        if (cfg->sdk_curl_nosignal == 1) {
            setNoSignal(cfg->sdk_curl_nosignal);
        }

        if (cfg->sdk_tls_ca_file != NULL) {
            setTLSCAFile(cfg->sdk_tls_ca_file);
        }

        if (cfg->sdk_tls_ca_path != NULL) {
            setTLSCAPath(cfg->sdk_tls_ca_path);
        }

        if (cfg->sdk_tls_crl_file != NULL) {
            setTLSCRLFile(cfg->sdk_tls_crl_file);
        }

        /* TODO We should try to compile the regex when the pattern changes */

        if ((re = pcre_compile(cfg->pattern == NULL ? DEFAULT_PATTERN : cfg->pattern, 0, &error, &error_offset, NULL)) != NULL) {

            if ((rv = pcre_exec(re, NULL, dn, strlen(dn), 0, 0, match_offset, 6)) != 2) {

                Log2(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: pcre_exec returned %d\n", __func__, rv);

            } else {

                if ( (match_offset[3] > match_offset[2]) ) {

                    id = malloc(((match_offset[3] - match_offset[2]) + 1) * sizeof(char));

                    memcpy(id, dn + match_offset[2], (match_offset[3] - match_offset[2]));
                    id[(match_offset[3] - match_offset[2])] = '\0';

                    Log2(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: id %s\n", __func__, id);

                    if (latch_overlay_check_latch(cfg, id) == LATCH_STATUS_LOCKED) {

                        Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: latch is locked\n", __func__);

                        rs->sr_err = LDAP_INVALID_CREDENTIALS;

                    }

                    free(id);

                }

            }

            pcre_free(re);

        } else {

            Log3(LDAP_DEBUG_ANY, LDAP_LEVEL_ERR, "    %s: Error compiling regex. Error: %s (%d)\n", __func__, error, error_offset);

        }

    }

    free(dn);
    dn = NULL;

    Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "<<< %s\n", __func__);

    return SLAP_CB_CONTINUE;

}

static int latch_overlay_bind(Operation *op, SlapReply *rs) {

    slap_callback *cb;
    slap_overinst *on = (slap_overinst *) op->o_bd->bd_info;

    Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, ">>> %s\n", __func__);

    cb = op->o_tmpcalloc(sizeof(slap_callback), 1, op->o_tmpmemctx);

    cb->sc_response = latch_overlay_bind_response;
    cb->sc_next = op->o_callback->sc_next;
    cb->sc_private = on->on_bi.bi_private;

    op->o_callback->sc_next = cb;

    Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "<<< %s\n", __func__);

    return SLAP_CB_CONTINUE;

}

static int latch_overlay_db_init(BackendDB *be, ConfigReply *cr) {

    int rc = 0;
    slap_overinst *on;
    latch_overlay_config_data *cfg;

    Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, ">>> %s\n", __func__);

    /* We reserve memory for and initialize the config structure */

    on = (slap_overinst *) be->bd_info;
    cfg = ch_calloc(1, sizeof(latch_overlay_config_data));

    cfg->application_id = NULL;
    cfg->secret = NULL;
    cfg->operation_id = NULL;
    cfg->sdk_host = NULL;
    cfg->sdk_proxy = NULL;
    cfg->sdk_timeout = 2;
    cfg->sdk_curl_nosignal = 0;
    cfg->sdk_tls_ca_file = NULL;
    cfg->sdk_tls_ca_path = NULL;
    cfg->sdk_tls_crl_file = NULL;

    cfg->excludes = ch_calloc(1, sizeof(char*));
    cfg->excludes[0] = NULL;

    cfg->pattern = NULL;
    cfg->ldap_uri = NULL;
    cfg->ldap_bind_dn = NULL;
    cfg->ldap_bind_password = NULL;
    cfg->ldap_search_base_dn = NULL;
    cfg->ldap_search_filter = NULL;
    cfg->ldap_search_scope = NULL;
    cfg->ldap_attribute = NULL;
    cfg->ldap_tls_ca_file = NULL;

    on->on_bi.bi_private = cfg;

    Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "<<< %s\n", __func__);

    return rc;

}

static int latch_overlay_db_open(BackendDB *be, ConfigReply *cr) {

    int i = 0;
    int rc = 0;
    slap_overinst *on;
    latch_overlay_config_data *cfg;

    Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, ">>> %s\n", __func__);

    on = (slap_overinst *) be->bd_info;
    cfg = on->on_bi.bi_private;

    /* We dump the configuration for debugging purpouses */

    Log2(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: cfg->application_id %s\n", __func__, cfg->application_id == NULL ? "NULL" : cfg->application_id);
    Log2(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: cfg->secret %s\n", __func__, cfg->secret == NULL ? "NULL" : cfg->secret);
    Log2(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: cfg->operation_id %s\n", __func__, cfg->operation_id == NULL ? "NULL" : cfg->operation_id);
    Log2(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: cfg->sdk_host %s\n", __func__, cfg->sdk_host == NULL ? "NULL" : cfg->sdk_host);
    Log2(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: cfg->sdk_proxy %s\n", __func__, cfg->sdk_proxy == NULL ? "NULL" : cfg->sdk_proxy);
    Log2(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: cfg->sdk_timeout %d\n", __func__, cfg->sdk_timeout);
    Log2(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: cfg->sdk_curl_nosignal %d\n", __func__, cfg->sdk_curl_nosignal);
    Log2(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: cfg->sdk_tls_ca_file %s\n", __func__, cfg->sdk_tls_ca_file == NULL ? "NULL" : cfg->sdk_tls_ca_file);
    Log2(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: cfg->sdk_tls_ca_path %s\n", __func__, cfg->sdk_tls_ca_path == NULL ? "NULL" : cfg->sdk_tls_ca_path);
    Log2(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: cfg->sdk_tls_crl_file %s\n", __func__, cfg->sdk_tls_crl_file == NULL ? "NULL" : cfg->sdk_tls_crl_file);

    for (i = 0; cfg->excludes[i] != NULL; i++) {
        Log3(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: cfg->excludes[%d] %s\n", __func__, i, cfg->excludes[i]);
    }

    Log2(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: cfg->pattern %s\n", __func__, cfg->pattern == NULL ? "NULL" : cfg->pattern);
    Log2(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: cfg->ldap_uri %s\n", __func__, cfg->ldap_uri == NULL ? "NULL" : cfg->ldap_uri);
    Log2(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: cfg->ldap_bind_bn %s\n", __func__, cfg->ldap_bind_dn == NULL ? "NULL" : cfg->ldap_bind_dn);
    Log2(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: cfg->ldap_bind_password %s\n", __func__, cfg->ldap_bind_password == NULL ? "NULL" : cfg->ldap_bind_password);
    Log2(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: cfg->ldap_search_base_dn %s\n", __func__, cfg->ldap_search_base_dn == NULL ? "NULL" : cfg->ldap_search_base_dn);
    Log2(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: cfg->ldap_search_filter %s\n", __func__, cfg->ldap_search_filter == NULL ? "NULL" : cfg->ldap_search_filter);
    Log2(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: cfg->ldap_search_scope %s\n", __func__, cfg->ldap_search_scope == NULL ? "NULL" : cfg->ldap_search_scope);
    Log2(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: cfg->ldap_attribute %s\n", __func__, cfg->ldap_attribute == NULL ? "NULL" : cfg->ldap_attribute);
    Log2(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: cfg->ldap_tls_ca_file %s\n", __func__, cfg->ldap_tls_ca_file == NULL ? "NULL" : cfg->ldap_tls_ca_file);

    Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "<<< %s\n", __func__);

    return rc;

}

static int latch_overlay_db_close(BackendDB *be, ConfigReply *cr) {

    int i = 0;
    int rc = 0;
    slap_overinst *on;
    latch_overlay_config_data *cfg;

    Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, ">>> %s\n", __func__);

    on = (slap_overinst *) be->bd_info;
    cfg = on->on_bi.bi_private;

    /* We free the config struct members */

    if (cfg->application_id != NULL) {
        Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: Freeing cfg->application_id\n", __func__);
        free(cfg->application_id);
        cfg->application_id = NULL;
    }

    if (cfg->secret != NULL) {
        Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: Freeing cfg->secret\n", __func__);
        free(cfg->secret);
        cfg->secret = NULL;
    }

    if (cfg->operation_id != NULL) {
        Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: Freeing cfg->operation_id\n", __func__);
        free(cfg->operation_id);
        cfg->operation_id = NULL;
    }

    if (cfg->sdk_host != NULL) {
        Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: Freeing cfg->sdk_host\n", __func__);
        free(cfg->sdk_host);
        cfg->sdk_host = NULL;
    }

    if (cfg->sdk_proxy != NULL) {
        Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: Freeing cfg->sdk_proxy\n", __func__);
        free(cfg->sdk_proxy);
        cfg->sdk_proxy = NULL;
    }

    if (cfg->sdk_tls_ca_file != NULL) {
        Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: Freeing cfg->sdk_tls_ca_file\n", __func__);
        free(cfg->sdk_tls_ca_file);
        cfg->sdk_tls_ca_file = NULL;
    }

    if (cfg->sdk_tls_ca_path != NULL) {
        Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: Freeing cfg->sdk_tls_ca_path\n", __func__);
        free(cfg->sdk_tls_ca_path);
        cfg->sdk_tls_ca_path = NULL;
    }

    if (cfg->sdk_tls_crl_file != NULL) {
        Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: Freeing cfg->sdk_tls_crl_file\n", __func__);
        free(cfg->sdk_tls_crl_file);
        cfg->sdk_tls_crl_file = NULL;
    }

    for (i = 0; cfg->excludes[i] != NULL; i++) {
        Log2(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: Freeing cfg->excludes[%d]\n", __func__, i);
        free(cfg->excludes[i]);
        cfg->excludes[i] = NULL;
    }

    if (cfg->pattern != NULL) {
        Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: Freeing cfg->pattern\n", __func__);
        free(cfg->pattern);
        cfg->pattern = NULL;
    }

    if (cfg->ldap_uri != NULL) {
        Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: Freeing cfg->ldap_uri\n", __func__);
        free(cfg->ldap_uri);
        cfg->ldap_uri = NULL;
    }

    if (cfg->ldap_bind_dn != NULL) {
        Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: Freeing cfg->ldap_bind_dn\n", __func__);
        free(cfg->ldap_bind_dn);
        cfg->ldap_bind_dn = NULL;
    }

    if (cfg->ldap_bind_password != NULL) {
        Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: Freeing cfg->ldap_bind_password\n", __func__);
        free(cfg->ldap_bind_password);
        cfg->ldap_bind_password = NULL;
    }

    if (cfg->ldap_search_base_dn != NULL) {
        Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: Freeing cfg->ldap_search_base_dn\n", __func__);
        free(cfg->ldap_search_base_dn);
        cfg->ldap_search_base_dn = NULL;
    }

    if (cfg->ldap_search_filter != NULL) {
        Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: Freeing cfg->ldap_search_filter\n", __func__);
        free(cfg->ldap_search_filter);
        cfg->ldap_search_filter = NULL;
    }

    if (cfg->ldap_search_scope != NULL) {
        Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: Freeing cfg->ldap_search_scope\n", __func__);
        free(cfg->ldap_search_scope);
        cfg->ldap_search_scope = NULL;
    }

    if (cfg->ldap_attribute != NULL) {
        Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: Freeing cfg->ldap_attribute\n", __func__);
        free(cfg->ldap_attribute);
        cfg->ldap_attribute = NULL;
    }

    if (cfg->ldap_tls_ca_file != NULL) {
        Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: Freeing cfg->ldap_tls_cacert_file\n", __func__);
        free(cfg->ldap_tls_ca_file);
        cfg->ldap_tls_ca_file = NULL;
    }

    Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "<<< %s\n", __func__);

    return rc;

}

static int latch_overlay_db_destroy(BackendDB *be, ConfigReply *cr) {

    int rc = 0;
    slap_overinst *on;
    latch_overlay_config_data *cfg;

    Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, ">>> %s\n", __func__);

    on = (slap_overinst *) be->bd_info;
    cfg = on->on_bi.bi_private;

    /* We free the config structure */

    if (cfg->excludes != NULL) {
        Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: Freeing cfg->excludes\n", __func__);
        free(cfg->excludes);
        cfg->excludes = NULL;
    }

    if (cfg != NULL) {
        Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: Freeing cfg\n", __func__);
        free(cfg);
        cfg = NULL;
    }

    Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "<<< %s\n", __func__);

    return rc;

}

int latch_overlay_initialize() {

    int rc = 0;

    Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, ">>> %s\n", __func__);

    latch_overlay.on_bi.bi_type = "latch";
    latch_overlay.on_bi.bi_db_init = latch_overlay_db_init;
    latch_overlay.on_bi.bi_db_open = latch_overlay_db_open;
    latch_overlay.on_bi.bi_db_close = latch_overlay_db_close;
    latch_overlay.on_bi.bi_db_destroy = latch_overlay_db_destroy;
    latch_overlay.on_bi.bi_op_bind = latch_overlay_bind;
    latch_overlay.on_bi.bi_cf_ocs = latch_overlay_ocs;

    rc = config_register_schema(latch_overlay_config, latch_overlay_ocs);

    Log2(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: config_register_schema returned %d\n", __func__, rc);

    if (rc) {
        Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "<<< %s\n", __func__);
        return rc;
    }

    rc = overlay_register(&latch_overlay);

    Log2(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: overlay_register returned %d\n", __func__, rc);
    Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "<<< %s\n", __func__);

    return rc;

}

#if SLAPD_OVER_LATCH == SLAPD_MOD_DYNAMIC && defined(PIC)
int init_module(int argc, char *argv[]) {

    int rc = 0;

    Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, ">>> %s\n", __func__);

    rc = latch_overlay_initialize();

    Log2(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "    %s: latch_overlay_initialize returned %d\n", __func__, rc);
    Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "<<< %s\n", __func__);

    return rc;

}
#endif

#endif /* SLAPD_OVER_LATCH */
