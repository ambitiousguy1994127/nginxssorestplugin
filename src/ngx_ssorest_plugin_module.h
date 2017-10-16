#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define SSOZONE_DEFAULT "SM"

typedef struct {
    ngx_flag_t enable;
    ngx_flag_t trace_enable;
    ngx_flag_t useServerNameAsDefault;
    ngx_flag_t sendFormParameters;
    ngx_str_t acoName;
    ngx_str_t gatewayUrl;
    ngx_str_t localrootpath;
    ngx_str_t pluginId;
    ngx_str_t secretKey;
    ngx_str_t gatewayToken;
    ngx_array_t *ssoZone;
    ngx_array_t *ignoreExt;
    ngx_array_t *ignoreUrl;
    ngx_array_t *ignoreHeaders;
    ngx_pool_t *cf_pool; // TODO saving the cf pool so we can store gatewayTokens in it, is this the right technique?
#if (NGX_PCRE)
    ngx_regex_t *regex;
#endif
} ngx_ssorest_plugin_conf_t;

extern ngx_module_t ngx_ssorest_plugin_module;