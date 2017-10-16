#include <json-c/json.h>
#include <curl/curl.h>
#include <ngx_http.h>

#define SC_NOT_EXTENDED      510
#define MY_POOL_SIZE 		4096

#define LOGGING_HEX

struct curl_fetch_st {
    char *payload;
    size_t size;
    ngx_pool_t *pool;
};

json_object *buildJsonArraySingleAttributes(ngx_http_request_t *r, ngx_ssorest_plugin_conf_t *conf);
json_object *buildJsonArrayHeaders(ngx_http_request_t *r);
json_object *buildJsonArrayCookies(ngx_http_request_t *r, ngx_array_t *ssoZone);
json_object *buildJsonArayAttributes(ngx_ssorest_plugin_conf_t *conf);
json_object *buildJsonArayGetParameters(ngx_http_request_t *r);
json_object *buildJsonRequest(ngx_http_request_t *r, ngx_pool_t *pool, ngx_ssorest_plugin_conf_t *conf);

CURLcode 	 curl_fetch_url(CURL *ch, const char *url, struct curl_fetch_st *fetch);
size_t 		 curl_callback(void *contents, size_t size, size_t nmemb, void *userp);
int 		 postRequestToGateway(json_object *request_json, ngx_http_request_t *r, const char *url, ngx_ssorest_plugin_conf_t *conf, ngx_pool_t *pool);
int 		 handleAllowContinue(json_object *res_json, ngx_http_request_t *r, const char *url, ngx_ssorest_plugin_conf_t *conf);
int 		 handleSignatureRequired(json_object *request_json, ngx_http_request_t *r, const char *url, ngx_ssorest_plugin_conf_t *conf, ngx_pool_t *pool);
void 		 propagateResponseHeadersAndCookies(ngx_http_request_t *r, ngx_ssorest_plugin_conf_t *conf, json_object *headers_json, json_object *cookies_json);
char		*toStringSafety(ngx_pool_t *pool, ngx_http_variable_value_t *v);
char 		*escape_str(ngx_pool_t *p, const char *src);
int 		 unescape_str(char *s, char *dec);
int 		 trace_libcurl(CURL *handle, curl_infotype type, char *data, size_t size, void *userp);
int 		 handleSendLocalFile(json_object *request_json, ngx_http_request_t *r, const char *url, ngx_ssorest_plugin_conf_t *conf, ngx_pool_t *pool);