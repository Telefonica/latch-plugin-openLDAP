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
latch_overlay_map_ldap(latch_overlay_config_data *cfg, char *id, char **mapped_id) {

    int search_scope = LDAP_SCOPE_BASE;
    char *search_base_dn = NULL;
    char *search_filter = NULL;
    int rv = ERROR;

    Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, ">>> %s\n", __func__);

    search_base_dn = replace_str(cfg->map_ldap_search_base_dn, "@@@USER@@@", id);
    search_filter = replace_str(cfg->map_ldap_search_filter, "@@@USER@@@", id);

    if (cfg->map_ldap_search_scope != NULL) {
        if (strcmp("onelevel", cfg->map_ldap_search_scope) == 0) {
            search_scope = LDAP_SCOPE_ONELEVEL;
        }
        else if (strcmp("subtree", cfg->map_ldap_search_scope) == 0) {
            search_scope = LDAP_SCOPE_SUBTREE;
        }
    }

    rv = latch_overlay_get_entry_attribute(cfg->map_ldap_uri, cfg->map_ldap_bind_dn, cfg->map_ldap_bind_password, search_base_dn, search_filter, search_scope, cfg->map_ldap_attribute, cfg->map_ldap_tls_ca_file, mapped_id);

    free(search_base_dn);
    free(search_filter);

    Log1(LDAP_DEBUG_TRACE, LDAP_LEVEL_DEBUG, "<<< %s\n", __func__);

    return rv;

}

#endif /* SLAPD_OVER_LATCH */
