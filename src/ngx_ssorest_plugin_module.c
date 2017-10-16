/**
 * @file   ngx_idfc_module.c
 * @author Egor Lord <egor.lord-127@yandex.com>
 * @date   Wed Aug 17 12:06:52 2011
 *
 * @workflow 
 * 1. This module intercept access to any uri on resource.
 * 2. Forward all the request to SSO/Gateway using JSON specification.
 * 3. Listen the response from gateway.
 * 4. If the response contains 100-status code, proceed to original uri
 *    If not, enforce privacy defined by CA SSO(former SiteMider)
 *
 */

#include "ngx_ssorest_plugin_module.h"
#include "json_payload.h"
#include "request.h"
#include "logging.h"

static ngx_int_t ngx_ssorest_plugin_init(ngx_conf_t *cf);
static ngx_int_t ngx_ssorest_plugin_request_handler(ngx_http_request_t *r);

static void *ngx_ssorest_plugin_create_conf(ngx_conf_t *cf);
static char *ngx_ssorest_plugin_merge_conf(ngx_conf_t *cf, void *parent, void *child);

static char *ngx_conf_setSSOZone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_conf_setIgnoreExt(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_conf_setIgnoreUrl(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_conf_setIgnoreHeaders(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

/* Define Module Directives */
static ngx_command_t ngx_ssorest_plugin_module_commands[] = {
        {
        ngx_string("SSORestEnabled"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_FLAG,
                ngx_conf_set_flag_slot,
                NGX_HTTP_SRV_CONF_OFFSET,
                offsetof(ngx_ssorest_plugin_conf_t, enable),
                NULL
        },
        {
        ngx_string("SSORestTrace"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_FLAG,
                ngx_conf_set_flag_slot,
                NGX_HTTP_SRV_CONF_OFFSET,
                offsetof(ngx_ssorest_plugin_conf_t, trace_enable),
                NULL
        },
        {
        ngx_string("SSORestUseServerNameAsDefault"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_FLAG,
                ngx_conf_set_flag_slot,
                NGX_HTTP_SRV_CONF_OFFSET,
                offsetof(ngx_ssorest_plugin_conf_t, useServerNameAsDefault),
                NULL
        },
        {
        ngx_string("SSORestSendFormParameters"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_FLAG,
                ngx_conf_set_flag_slot,
                NGX_HTTP_SRV_CONF_OFFSET,
                offsetof(ngx_ssorest_plugin_conf_t, sendFormParameters),
                NULL
        },
        {
        ngx_string("SSORestACOName"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
                ngx_conf_set_str_slot,
                NGX_HTTP_SRV_CONF_OFFSET,
                offsetof(ngx_ssorest_plugin_conf_t, acoName),
                NULL
        },
        {
        ngx_string("SSORestGatewayUrl"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
                ngx_conf_set_str_slot,
                NGX_HTTP_SRV_CONF_OFFSET,
                offsetof(ngx_ssorest_plugin_conf_t, gatewayUrl),
                NULL
        },
        {
        ngx_string("SSORestLocalContent"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
                ngx_conf_set_str_slot,
                NGX_HTTP_SRV_CONF_OFFSET,
                offsetof(ngx_ssorest_plugin_conf_t, localrootpath),
                NULL
        },
        {
        ngx_string("SSORestPluginId"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
                ngx_conf_set_str_slot,
                NGX_HTTP_SRV_CONF_OFFSET,
                offsetof(ngx_ssorest_plugin_conf_t, pluginId),
                NULL
        },
        {
        ngx_string("SSORestSecretKey"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
                ngx_conf_set_str_slot,
                NGX_HTTP_SRV_CONF_OFFSET,
                offsetof(ngx_ssorest_plugin_conf_t, secretKey),
                NULL
        },
        {
        ngx_string("SSORestSSOZone"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_ANY,
                ngx_conf_setSSOZone,
                NGX_HTTP_SRV_CONF_OFFSET,
                0,
                NULL
        },
        {
        ngx_string("SSORestIgnoreExt"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_ANY,
                ngx_conf_setIgnoreExt,
                NGX_HTTP_SRV_CONF_OFFSET,
                0,
                NULL
        },
        {
        ngx_string("SSORestIgnoreUrl"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_ANY,
                ngx_conf_setIgnoreUrl,
                NGX_HTTP_SRV_CONF_OFFSET,
                0,
                NULL
        },
        {
        ngx_string("SSORestIgnoreHeaders"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_ANY,
                ngx_conf_setIgnoreHeaders,
                NGX_HTTP_SRV_CONF_OFFSET,
                0,
                NULL
        },
        ngx_null_command
        };

/* Define Module Context */
static ngx_http_module_t ngx_ssorest_plugin_module_ctx =
        {
        /* preconfiguration */
        NULL,

        /* postconfiguration */
        ngx_ssorest_plugin_init,

        /* create main configuration */
        NULL,

        /* init main configuration */
        NULL,

        /* create server configuration */
        ngx_ssorest_plugin_create_conf,

        /* merge server configuration */
        ngx_ssorest_plugin_merge_conf,

        /* create location configuration */
        NULL,

        /* merge location configuration */
        NULL
        // ngx_http_idfc_ssorest_merge_conf
        };

/* NGINX module definition. */
ngx_module_t ngx_ssorest_plugin_module =
        {
        NGX_MODULE_V1,
                &ngx_ssorest_plugin_module_ctx, /* module context */
                ngx_ssorest_plugin_module_commands, /* module directives */
                NGX_HTTP_MODULE, /* module type */
                NULL, /* init master */
                NULL, /* init module */
                NULL, /* init process */
                NULL, /* init thread */
                NULL, /* exit thread */
                NULL, /* exit process */
                NULL, /* exit master */
                NGX_MODULE_V1_PADDING
        };

/**
 * Plugin runtime request processor
 */
static ngx_int_t ngx_ssorest_plugin_request_handler(ngx_http_request_t *r)
{
    ngx_ssorest_plugin_conf_t *conf;
    conf = ngx_http_get_module_srv_conf(r, ngx_ssorest_plugin_module);

    /* Check if the module is enabled */
    if ( conf->enable == 0 || conf->enable == NGX_CONF_UNSET ) 
    {
        logDebug(r->connection->log, 0, "SSO/Rest Plugin is disabled");
        return NGX_DECLINED;
    }

    logInfo(r->connection->log, 0, "Processing new request");

    ngx_http_variable_value_t *v;
    ngx_str_t                 *ignore_value;
    char                      *uri;
    ngx_uint_t                 i;

    /* Get full url from the request object */
    v = ngx_pcalloc(r->pool, sizeof(ngx_http_variable_value_t));
    get_ngx_http_request_url(r, v, conf->useServerNameAsDefault);

    if (v == NULL || v->not_found) {
        get_ngx_http_request_uri(r, v);
    }
    uri = toStringSafety(r->pool, v);

    /* 1.Check if the request uri matches with ignored extension */
    if (conf->ignoreExt != NULL) {
        char *ignore_ext;
        get_ngx_http_request_extension(r, v);
        ignore_ext = toStringSafety(r->pool, v);
        if (v->valid == 1 && v->data != NULL) {
            ignore_value = conf->ignoreExt->elts;
            for (i = 0; i < conf->ignoreExt->nelts; i++) {
                if (ngx_strncmp(ignore_value[i].data, ignore_ext, v->len) == 0) {
                    logInfo(r->connection->log, 0, "Ignore Extension Matched");
                    return NGX_DECLINED;
                }
            }
        }
    }

    /* 2.Check if the request uri matches with ignored url */
    if (conf->ignoreUrl != NULL) {
        ignore_value = conf->ignoreUrl->elts;
        for (i = 0; i < conf->ignoreUrl->nelts; i++) {
            if (ngx_strstr(uri, ignore_value[i].data)) {
                logInfo(r->connection->log, 0, "Ignore Url Matched");
                return NGX_DECLINED;
            }
        }
    }

    // TODO handling of public endpoints
    // TODO log the start time - does NGINX have some special facility for telemetry?

    /* 3. Make A call to SSO Gateway */
    if (conf->gatewayUrl.data == NULL || conf->gatewayUrl.len == 0) {
        logDebug(r->connection->log, 0, "No SSORestGatewayUrl in configuration");
        return NGX_DECLINED;
    }

    int curl_result     = 0;
    ngx_pool_t *pool    = ngx_create_pool(NGX_MAX_ALLOC_FROM_POOL, r->connection->log);
    curl_result         = postRequestToGateway(NULL, r, (const char *) conf->gatewayUrl.data, conf, pool);

    //ngx_http_finalize_request(r, curl_result);
    logInfo(r->connection->log, 0, "Request to Gateway had result code: %d", curl_result);
    ngx_destroy_pool(pool);
    if (curl_result == NGX_HTTP_CONTINUE)
        return NGX_OK;
    return curl_result;
}

/**
 * Initializes the SSO/Rest Plugin
 */
static ngx_int_t ngx_ssorest_plugin_init(ngx_conf_t *cf) {
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_ssorest_plugin_request_handler;

    logNotice(cf->log, 0, "SSO/Rest Plugin initialized");

#if defined(SVN_REV) && defined(MOD_VER)
    logNotice(cf->log, 0, "SSO/Rest Plugin for NGINX v%s build %s", MOD_VER, SVN_REV);
#endif

    return NGX_OK;
}

/**
 * Allocate a new configuration object
 */
static void *ngx_ssorest_plugin_create_conf(ngx_conf_t *cf) {
    ngx_ssorest_plugin_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_ssorest_plugin_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     * conf->acoName    = { 0, NULL };
     * conf->gatewayUrl = { 0, NULL };
     * conf->pluginId   = { 0, NULL };
     * conf->secretKey  = { 0, NULL };
     */

    conf->enable = NGX_CONF_UNSET;
    conf->trace_enable = NGX_CONF_UNSET;
    conf->useServerNameAsDefault = NGX_CONF_UNSET;
    conf->sendFormParameters = NGX_CONF_UNSET;
    conf->ssoZone   = NULL;
    conf->ignoreExt = NULL;
    conf->ignoreUrl = NULL;

    conf->cf_pool = cf->pool; // save this for gateway token mgmt

    #if (NGX_PCRE)
        ngx_regex_compile_t rc;
        u_char                errstr[NGX_MAX_CONF_ERRSTR];
        ngx_str_t value = ngx_string("charset\\s*=\\s*([^\\s;]*)");

        ngx_memzero(&rc, sizeof(ngx_regex_compile_t));

        rc.pattern = value;
        rc.pool = cf->pool;
        rc.err.len = NGX_MAX_CONF_ERRSTR;
        rc.err.data = errstr;
        /* rc.options are passed as is to pcre_compile() */

        if (ngx_regex_compile(&rc) != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%V", &rc.err);
            return NGX_CONF_ERROR;
        }

        conf->regex = rc.regex;
    #else
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,"[SSORest]: This plugin requires PCRE library.");
        return NULL;
    #endif
    return conf;
}

static char *ngx_ssorest_plugin_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_ssorest_plugin_conf_t *prev = parent;
    ngx_ssorest_plugin_conf_t *conf = child;

    if (conf->enable == NGX_CONF_UNSET) {
        if (prev->enable == NGX_CONF_UNSET) {
            conf->enable = 0;

        }
        else {
            conf->enable = prev->enable;
        }
    }
    ngx_conf_merge_value(conf->trace_enable, prev->trace_enable, 0);
    ngx_conf_merge_value(conf->useServerNameAsDefault, prev->useServerNameAsDefault, 0);
    ngx_conf_merge_value(conf->sendFormParameters, prev->sendFormParameters, 0);
    ngx_conf_merge_str_value(conf->acoName, prev->acoName, "");
    ngx_conf_merge_str_value(conf->gatewayUrl, prev->gatewayUrl, "");
    ngx_conf_merge_str_value(conf->localrootpath, prev->localrootpath, "");
    ngx_conf_merge_str_value(conf->pluginId, prev->pluginId, "");
    ngx_conf_merge_str_value(conf->secretKey, prev->secretKey, "");
    // ngx_conf_merge_str_value(conf->ssoZone, prev->ssoZone, SSOZONE_DEFAULT);

    if (conf->ssoZone == NULL)
    {
        /* Merge if the parent 'ssoZone' is set */
        if (prev->ssoZone != NULL)
        {
            ngx_str_t  *prev_val;
            ngx_str_t  *cur_val;
            ngx_uint_t  i;
            ngx_uint_t  size;
            u_char     *last;
            
            size        = prev->ssoZone->nelts;
            prev_val    = prev->ssoZone->elts;

            /* Create array for storing ssoZone from the parent */
            conf->ssoZone = ngx_array_create(cf->pool, size, sizeof(ngx_str_t));
            if (conf->ssoZone == NULL) {
                logError(cf->log, 0, "Cannot Allocate Array Pool");
                return NGX_CONF_ERROR;
            }

            for (i = 0; i < size; i++) {
                cur_val     = ngx_array_push(conf->ssoZone);
                if (cur_val == NULL) {
                    if(conf->ssoZone)
                        ngx_array_destroy(conf->ssoZone);
                    logError(cf->log, 0, "Cannot Allocate Array Item");
                    return NGX_CONF_ERROR;
                }
                /* Copy one by one */
                cur_val->len    = prev_val[i].len;
                cur_val->data   = ngx_pcalloc(cf->pool, prev_val[i].len + 1);
                if(cur_val->data == NULL)
                {
                    if(conf->ssoZone)
                        ngx_array_destroy(conf->ssoZone);
                    logError(cf->log, 0, "Cannot Allocate Array Item");
                    return NGX_CONF_ERROR;
                }   
                last = ngx_copy(cur_val->data, prev_val[i].data, prev_val[i].len);
                *last = '\0';
            }
        }
    }

    if (conf->ignoreExt == NULL)
    {
        /* Merge if the parent 'ignoreExt' is set */
        if (prev->ignoreExt != NULL)
        {
            ngx_str_t  *prev_val;
            ngx_str_t  *cur_val;
            ngx_uint_t  i;
            ngx_uint_t  size;
            u_char     *last;
            
            size        = prev->ignoreExt->nelts;
            prev_val    = prev->ignoreExt->elts;

            /* Create array for storing ignoreExt from the parent */
            conf->ignoreExt = ngx_array_create(cf->pool, size, sizeof(ngx_str_t));
            if (conf->ignoreExt == NULL) {
                logError(cf->log, 0, "Cannot Allocate Array Pool");
                return NGX_CONF_ERROR;
            }

            for (i = 0; i < size; i++) {
                cur_val     = ngx_array_push(conf->ignoreExt);
                if (cur_val == NULL) {
                    if(conf->ignoreExt)
                        ngx_array_destroy(conf->ignoreExt);
                    logError(cf->log, 0, "Cannot Allocate Array Item");
                    return NGX_CONF_ERROR;
                }
                /* Copy one by one */
                cur_val->len    = prev_val[i].len;
                cur_val->data   = ngx_pcalloc(cf->pool, prev_val[i].len + 1);
                if(cur_val->data == NULL)
                {
                    if(conf->ignoreExt)
                        ngx_array_destroy(conf->ignoreExt);
                    logError(cf->log, 0, "Cannot Allocate Array Item");
                    return NGX_CONF_ERROR;
                }   
                last = ngx_copy(cur_val->data, prev_val[i].data, prev_val[i].len);
                *last = '\0';
            }
        }
    }

    if (conf->ignoreUrl == NULL)
    {
        if (prev->ignoreUrl != NULL)
        {
            ngx_str_t   *prev_val;
            ngx_str_t   *cur_val;
            ngx_uint_t   i;
            ngx_uint_t   size;
            u_char      *last;
            
            size        = prev->ignoreUrl->nelts;
            prev_val    = prev->ignoreUrl->elts;

            /* Create array for storing ignoreExt from the parent */
            conf->ignoreUrl = ngx_array_create(cf->pool, size, sizeof(ngx_str_t));
            if (conf->ignoreUrl == NULL) {
                logError(cf->log, 0, "Cannot Allocate Array Pool");
                return NGX_CONF_ERROR;
            }
            for (i = 0; i < size; i++) {
                cur_val = ngx_array_push(conf->ignoreUrl);
                if (cur_val == NULL) {
                    if(conf->ignoreUrl)
                        ngx_array_destroy(conf->ignoreUrl);
                    logError(cf->log, 0, "Cannot Allocate Array Item");
                    return NGX_CONF_ERROR;
                }
                /* Copy one by one */
                cur_val->len    = prev_val[i].len;
                cur_val->data   = ngx_pcalloc(cf->pool, prev_val[i].len + 1);
                if(cur_val->data == NULL)
                {
                    if(conf->ignoreUrl)
                        ngx_array_destroy(conf->ignoreUrl);
                    logError(cf->log, 0, "Cannot Allocate Array Item");
                    return NGX_CONF_ERROR;
                }
                last = ngx_copy(cur_val->data, prev_val[i].data, prev_val[i].len);
                *last = '\0';
            }

        }
    }

    if (conf->ignoreHeaders == NULL)
    {
        if (prev->ignoreHeaders != NULL)
        {
            ngx_str_t   *prev_val;
            ngx_str_t   *cur_val;
            ngx_uint_t   i;
            ngx_uint_t   size;
            u_char      *last;
            
            size        = prev->ignoreHeaders->nelts;
            prev_val    = prev->ignoreHeaders->elts;

            /* Create array for storing ignoreExt from the parent */
            conf->ignoreHeaders = ngx_array_create(cf->pool, size, sizeof(ngx_str_t));
            if (conf->ignoreHeaders == NULL) {
                logError(cf->log, 0, "Cannot Allocate Array Pool");
                return NGX_CONF_ERROR;
            }
            for (i = 0; i < size; i++) {
                cur_val = ngx_array_push(conf->ignoreHeaders);
                if (cur_val == NULL) {
                    if(conf->ignoreHeaders)
                        ngx_array_destroy(conf->ignoreHeaders);
                    logError(cf->log, 0, "Cannot Allocate Array Item");
                    return NGX_CONF_ERROR;
                }
                /* Copy one by one */
                cur_val->len    = prev_val[i].len;
                cur_val->data   = ngx_pcalloc(cf->pool, prev_val[i].len + 1);
                if(cur_val->data == NULL)
                {
                    if(conf->ignoreHeaders)
                        ngx_array_destroy(conf->ignoreHeaders);
                    logError(cf->log, 0, "Cannot Allocate Array Item");
                    return NGX_CONF_ERROR;
                }
                last = ngx_copy(cur_val->data, prev_val[i].data, prev_val[i].len);
                *last = '\0';
            }

        }
    }
    return NGX_CONF_OK;
}

static char *ngx_conf_setSSOZone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_ssorest_plugin_conf_t *idfc_conf = conf;
    ngx_str_t *value;
    ngx_str_t *ssozone;
    ngx_uint_t i;

    if (idfc_conf->ssoZone == NULL) {
        idfc_conf->ssoZone = ngx_array_create(cf->pool, 1, sizeof(ngx_str_t));
        if (idfc_conf->ssoZone == NULL) {
            return NGX_CONF_ERROR ;
        }
    }

    value = cf->args->elts;
    for (i = 1; i < cf->args->nelts; i++) {
        ssozone = ngx_array_push(idfc_conf->ssoZone);
        if (ssozone == NULL)
        {
            if(idfc_conf->ssoZone)
                ngx_array_destroy(idfc_conf->ignoreExt);
            logError(cf->log, 0, "Cannot Allocate Array Item");
            return NGX_CONF_ERROR ;
        }

        u_char *last;
        ssozone->len = value[i].len;
        ssozone->data = ngx_pnalloc(cf->pool, ssozone->len + 1);
        last = ngx_copy(ssozone->data, value[i].data, ssozone->len);
        *last = '\0';
    }
    return NGX_CONF_OK;
}

/**
 * Creates the IgnoreEXT array based upon our configuration
 */
static char *ngx_conf_setIgnoreExt(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_ssorest_plugin_conf_t *idfc_conf = conf;
    ngx_str_t *value;
    ngx_str_t *ignoreExt;
    ngx_uint_t i;

    if (idfc_conf->ignoreExt == NULL) {
        idfc_conf->ignoreExt = ngx_array_create(cf->pool, 1, sizeof(ngx_str_t));
        if (idfc_conf->ignoreExt == NULL) {
            return NGX_CONF_ERROR ;
        }
    }

    value = cf->args->elts;
    for (i = 1; i < cf->args->nelts; i++) {
        if (value[i].data[0] != '.' || value[i].len < 2) {
            if(idfc_conf->ignoreExt)
                ngx_array_destroy(idfc_conf->ignoreExt);
            return "should be start with '.'";
        }
        ignoreExt = ngx_array_push(idfc_conf->ignoreExt);
        if (ignoreExt == NULL)
        {
            if(idfc_conf->ignoreExt)
                ngx_array_destroy(idfc_conf->ignoreExt);
            logError(cf->log, 0, "Cannot Allocate Array Item");
            return NGX_CONF_ERROR ;
        }
        // strip off leading '.'
        u_char *last;
        ignoreExt->len = value[i].len - 1;
        ignoreExt->data = ngx_pnalloc(cf->pool, ignoreExt->len + 1);
        last = ngx_copy(ignoreExt->data, value[i].data + 1, ignoreExt->len);
        *last = '\0';
    }
    return NGX_CONF_OK;
}

/**
 * Creates the IgnoreURL array based upon our configuration
 */
static char *ngx_conf_setIgnoreUrl(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_ssorest_plugin_conf_t *idfc_conf = conf;
    ngx_str_t *value;
    ngx_str_t *ignoreUrl;
    ngx_uint_t i;

    if (idfc_conf->ignoreUrl == NULL) {
        idfc_conf->ignoreUrl = ngx_array_create(cf->pool, 1, sizeof(ngx_str_t));
        if (idfc_conf->ignoreUrl == NULL) {
            return NGX_CONF_ERROR ;
        }
    }

    value = cf->args->elts;
    for (i = 1; i < cf->args->nelts; i++) {
        if (value[i].data[0] != '/') {
            if(idfc_conf->ignoreUrl)
                ngx_array_destroy(idfc_conf->ignoreUrl);
            return "should be start with '/'";
        }
        ignoreUrl = ngx_array_push(idfc_conf->ignoreUrl);
        if (ignoreUrl == NULL)
        {
            if(idfc_conf->ignoreUrl)
                ngx_array_destroy(idfc_conf->ignoreUrl);
            logError(cf->log, 0, "Cannot Allocate Array Item");
            return NGX_CONF_ERROR ;
        }

        u_char *last;
        ignoreUrl->len  = value[i].len;
        ignoreUrl->data = ngx_pnalloc(cf->pool, ignoreUrl->len + 1);
        last = ngx_copy(ignoreUrl->data, value[i].data, ignoreUrl->len);
        *last = '\0';
    }
    return NGX_CONF_OK;
}

static char *ngx_conf_setIgnoreHeaders(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_ssorest_plugin_conf_t *idfc_conf = conf;
    ngx_str_t *value;
    ngx_str_t *ignoreHeader;
    ngx_uint_t i;

    if (idfc_conf->ignoreHeaders == NULL) {
        idfc_conf->ignoreHeaders = ngx_array_create(cf->pool, 1, sizeof(ngx_str_t));
        if (idfc_conf->ignoreHeaders == NULL) {
            return NGX_CONF_ERROR ;
        }
    }

    value = cf->args->elts;
    for (i = 1; i < cf->args->nelts; i++) {
        ignoreHeader = ngx_array_push(idfc_conf->ignoreHeaders);
        if (ignoreHeader == NULL)
        {
            if(idfc_conf->ignoreHeaders)
                ngx_array_destroy(idfc_conf->ignoreHeaders);
            logError(cf->log, 0, "Cannot Allocate Array Item");
            return NGX_CONF_ERROR ;
        }

        u_char *last;
        ignoreHeader->len  = value[i].len;
        ignoreHeader->data = ngx_pnalloc(cf->pool, ignoreHeader->len + 1);
        last = ngx_copy(ignoreHeader->data, value[i].data, ignoreHeader->len);
        *last = '\0';
    }
    return NGX_CONF_OK;
}