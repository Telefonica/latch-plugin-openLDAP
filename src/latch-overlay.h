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

#ifndef __LATCH_OVERLAY_H__
#define __LATCH_OVERLAY_H__

#include "config.h"
#include "latch.h"

#define OK 0
#define ERROR 1

#define LATCH_STATUS_UNLOCKED 0
#define LATCH_STATUS_LOCKED 1
#define LATCH_STATUS_UNKNOWN 2

#define MAP_MODE_DIRECT "direct"
#define MAP_MODE_LDAP "ldap"

typedef struct latch_overlay_config_data {
    char  *application_id;
    char  *secret;
    char  *operation_id;
    char  *sdk_host;
    char  *sdk_proxy;
     int   sdk_timeout;
     int   sdk_curl_nosignal;
     int   sdk_stop_on_error;
    char  *sdk_tls_ca_file;
    char  *sdk_tls_ca_path;
    char  *sdk_tls_crl_file;
    char **excludes;
    char  *pattern;
    char  *map_mode;
    char  *map_ldap_uri;
    char  *map_ldap_bind_dn;
    char  *map_ldap_bind_password;
    char  *map_ldap_search_base_dn;
    char  *map_ldap_search_filter;
    char  *map_ldap_search_scope;
    char  *map_ldap_attribute;
    char  *map_ldap_tls_ca_file;
     int   map_ldap_stop_on_error;
    char  *ldap_uri;
    char  *ldap_bind_dn;
    char  *ldap_bind_password;
    char  *ldap_search_base_dn;
    char  *ldap_search_filter;
    char  *ldap_search_scope;
    char  *ldap_attribute;
    char  *ldap_tls_ca_file;
     int   ldap_stop_on_error;
     int   required;
} latch_overlay_config_data;

extern ConfigTable latch_overlay_config[];
extern ConfigOCs latch_overlay_ocs[];

extern int latch_overlay_check_latch(latch_overlay_config_data *cfg, char *id);
extern int latch_overlay_get_entry_attribute(char *uri, char *bind_dn, char *bind_password, char *search_base_dn, char *search_filter, int search_scope, char *attribute_name, char *tls_ca_file, char **attribute_value);
extern int latch_overlay_map_ldap(latch_overlay_config_data *cfg, char *id, char **mapped_id);

extern char *replace_str(const char *str, const char *old, const char *new);

#endif /* __LATCH_OVERLAY_H__ */
