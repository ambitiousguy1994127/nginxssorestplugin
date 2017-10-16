#include <string.h>
#include <stdio.h>
#include "ngx_ssorest_plugin_module.h"
#include "json_payload.h"
#include "request.h"
#include "crypto.h"
#include "logging.h"
#include "file.h"
static u_char expires[] = "; expires=Thu, 31-Dec-37 23:55:55 GMT";

CURLcode curl_fetch_url(CURL *ch, const char *url, struct curl_fetch_st *fetch) {
    CURLcode rcode;

    fetch->payload = malloc(1);
    fetch->size = 0;
    curl_easy_setopt(ch, CURLOPT_URL, url);
    curl_easy_setopt(ch, CURLOPT_WRITEFUNCTION, curl_callback);
    curl_easy_setopt(ch, CURLOPT_WRITEDATA, (void * ) fetch);
    curl_easy_setopt(ch, CURLOPT_USERAGENT, "libcurl-agent/1.0");
    curl_easy_setopt(ch, CURLOPT_TIMEOUT, 30);
    curl_easy_setopt(ch, CURLOPT_FOLLOWLOCATION, 1);
    // curl_easy_setopt(ch, CURLOPT_MAXREDIRS, 1);
    rcode = curl_easy_perform(ch);

    return rcode;
}

size_t curl_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct curl_fetch_st *p = (struct curl_fetch_st *) userp; /* cast pointer to fetch struct */

    p->payload = realloc(p->payload, p->size + realsize + 1);

    if (p->payload == NULL) {
        logDebug(p->pool->log, 0, "Could not allocate json payload");
        free(p->payload);
        return -1;
    }

    memcpy(&(p->payload[p->size]), contents, realsize);
    p->size += realsize;
    p->payload[p->size] = '\0';

    return realsize;
}

int trace_libcurl(CURL *handle, curl_infotype type, char *data, size_t size, void *userp)
{
    ngx_http_request_t *r = (ngx_http_request_t *)userp;
    const char *text;
    (void)handle; /* prevent compiler warning */
    int nohex = 1;
    char buf[200];
    char *p = buf;
    char *pos;
#ifdef LOGGING_HEX
    nohex = 0;
#endif
    switch(type) {  
    case CURLINFO_TEXT:

        if ((pos=strchr(data, '\n')) != NULL)
            *pos = '\0';
        sprintf(buf,  "== Info: %s", data);
        logDebug(r->connection->log, 0, buf);
        return 0;
    default:
        return 0;
    case CURLINFO_HEADER_OUT:
        text = "=> Send header";
        break;
    case CURLINFO_DATA_OUT:
        text = "=> Send data";
        break;
    case CURLINFO_SSL_DATA_OUT:
        text = "=> Send SSL data";
        break;
    case CURLINFO_HEADER_IN:
        text = "<= Recv header";
        break;
    case CURLINFO_DATA_IN:
        text = "<= Recv data";
        break;
    case CURLINFO_SSL_DATA_IN:
        text = "<= Recv SSL data";
        break;
    }

    // Logging
    size_t i;
    size_t c;

    unsigned int width=0x10;
    unsigned char *ptr = (unsigned char *) data;
    if(nohex)
        width = 0x40;

    sprintf(buf, "%s, %10.10ld bytes (0x%8.8lx)", text, (long)size, (long)size);
    logDebug(r->connection->log, 0, "%s", buf);

    for(i=0; i<size; i+= width) {
        p = buf;
        sprintf(p, "0x%4.4lx: ", (long)i);
        p+=8;

        if(!nohex) {
            for(c = 0; c < width; c++)
            {
                if(i+c < size)
                {
                    sprintf(p, "%02x ", ptr[i+c]);
                    p+=3;
                }
                else
                {
                    sprintf(p, "   ");
                    p+=3;   
                }
            }
        }

        for(c = 0; (c < width) && (i+c < size); c++) {
            if(nohex && (i+c+1 < size) && ptr[i+c]==0x0D && ptr[i+c+1]==0x0A) {
                i+=(c+2-width);
                break;
            }
            sprintf(p, "%c",
              (ptr[i+c]>=0x20) && (ptr[i+c]<0x80)?ptr[i+c]:'.');
            p++;
            if(nohex && (i+c+2 < size) && ptr[i+c+1]==0x0D && ptr[i+c+2]==0x0A) {
                i+=(c+3-width);
                break;
            }
        }
        *p = '\0';
        logDebug(r->connection->log, 0, "%s", buf);
    }
    return 0;
}

/**
 * Handles the callout to the SSO/Rest Gateway
 */
int postRequestToGateway(json_object *request_json, ngx_http_request_t *r, const char *url, ngx_ssorest_plugin_conf_t *conf, ngx_pool_t *pool) {
    struct curl_fetch_st curl_fetch;
    CURL *ch;
    json_object *json;
    json_object *res_json;
    CURLcode rcode;
    struct curl_fetch_st *cf = &curl_fetch;
    struct curl_slist *headers = NULL;
    enum json_tokener_error jerr = json_tokener_success;

    /* init curl handle */
    if ((ch = curl_easy_init()) == NULL) {
        logDebug(r->connection->log, 0, "Failed to initialize the curl");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* set content type */
    headers = curl_slist_append(headers, "Accept: application/json");
    headers = curl_slist_append(headers, "Content-Type: application/json");

    /* create json object for post */
    /* if this is subrequest ( request_json != NULL) then just reuse */
    if (request_json == NULL) {
        json = buildJsonRequest(r, pool, conf);
    }
    else
    {
        json = request_json;
    }

    // Show the pretty JSon request if we have debug level
    if (r->connection->log->log_level >= NGX_LOG_DEBUG) {
        const char *pretty = json_object_to_json_string_ext(json, JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_SPACED);
        //logDebug(r->connection->log, 0, "Sending JSon request to Gateway:%s", pretty);
        logDebug(r->connection->log, 0, "Sending JSon request to Gateway:");
        int linenr = 0;
        char *ptr, *temp = NULL;
        ptr = strtok_r((char * )pretty, "\n", &temp);
        while (ptr != NULL) {
            logDebug(r->connection->log, 0, "%2d: %s", ++linenr, ptr);
            ptr = strtok_r(NULL, "\n", &temp);
        }
    }

    curl_easy_setopt(ch, CURLOPT_CUSTOMREQUEST, "POST");
    curl_easy_setopt(ch, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(ch, CURLOPT_SSL_VERIFYPEER, FALSE);
    curl_easy_setopt(ch, CURLOPT_POSTFIELDS, json_object_to_json_string(json));

    // Add Debugging Options
    if(conf->trace_enable)
    {
        curl_easy_setopt(ch, CURLOPT_DEBUGFUNCTION, trace_libcurl);
        curl_easy_setopt(ch, CURLOPT_DEBUGDATA, r);
        curl_easy_setopt(ch, CURLOPT_VERBOSE, 1L);        
    }

    /* fetch page and capture return code */
    cf->pool = pool;
    rcode = curl_fetch_url(ch, url, cf);

    /* cleanup curl handle */
    curl_easy_cleanup(ch);

    /* free headers */
    curl_slist_free_all(headers);

    /* check return code */
    // TODO add gateway failover/retry here
    if (rcode != CURLE_OK || cf->size < 1) {
        logError(r->connection->log, 0, "Failed to fetch url (%s) - curl reported: %s", url, curl_easy_strerror(rcode));
        free(cf->payload);
        json_object_put(json);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* check we have a payload */
    if (cf->payload == NULL) {
        logError(r->connection->log, 0, "NULL payload returned from (%s) - curl reported: %s", url, curl_easy_strerror(rcode));
        free(cf->payload);
        json_object_put(json);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    logDebug(r->connection->log, 0, "Received raw gateway response, length=%d", cf->size);
    //if(conf->trace_enable) {
    //    logDebug(r->connection->log, 0, "Received raw gateway response");
    //    print_binary(r, cf->payload, cf->size);
    //}

    /* parse return */
    res_json = json_tokener_parse_verbose(cf->payload, &jerr);
    free(cf->payload);
    if (!res_json) {
        json_object_put(json);
        json_object_put(res_json);
        logError(r->connection->log, 0, "Failed to parse gateway response, error= %s", json_tokener_error_desc(jerr));
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    // Now we're ready to roll!
    // Show the parsed pretty JSon if we have debug level
    if (r->connection->log->log_level >= NGX_LOG_DEBUG) {
        const char *pretty = json_object_to_json_string_ext(res_json, JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_SPACED);
        //logDebug(r->connection->log, 0, "Parsed reply from Gateway:%s", pretty);
        logDebug(r->connection->log, 0, "Parsed reply from Gateway:");
        int linenr = 0;
        char *ptr, *temp = NULL;
        ptr = strtok_r((char *) pretty, "\n", &temp);
        while (ptr != NULL) {
            logDebug(r->connection->log, 0, "%3d: %s", ++linenr, ptr);
            ptr = strtok_r(NULL, "\n", &temp);
        }
    }

    json_object *response_json;
    json_object *response_status_json;
    json_object *response_headers_json;
    json_object *response_body_json;

    json_object_object_get_ex(res_json, "response", &response_json);
    json_object_object_get_ex(response_json, "status", &response_status_json);
    json_object_object_get_ex(response_json, "headers", &response_headers_json);
    json_object_object_get_ex(response_json, "body", &response_body_json);
    
    //now we process status
    int status = json_object_get_int(response_status_json);

    logInfo(r->connection->log, 0, "Gateway provided response status = %d", status);

    // store gatewayToken if received
    if (response_headers_json != NULL) {
        json_object *gwTokenJson = NULL;
        json_bool result = json_object_object_get_ex(response_headers_json, "gatewayToken", &gwTokenJson);
        if (result == TRUE && gwTokenJson != NULL) {
            json_object *gwTokenValue = NULL;
            if (json_object_array_length(gwTokenJson))
                gwTokenValue = json_object_array_get_idx(gwTokenJson, 0);

            if (gwTokenValue != NULL) {
                const char* gwToken = json_object_get_string(gwTokenValue);
                ngx_str_t *tmp = ngx_pcalloc(conf->cf_pool, sizeof(ngx_str_t)); // store this in the config
                tmp->len = strlen(gwToken);
                tmp->data = ngx_palloc(conf->cf_pool, tmp->len + 1);
                ngx_memcpy(tmp->data, (u_char* )gwToken, tmp->len);
                tmp->data[tmp->len] = '\0'; // FIX for SPNGINX-2
                conf->gatewayToken = *tmp;
                logDebug(r->connection->log, 0, "Plugin stored gatwayToken=%s, len=%d", conf->gatewayToken.data, conf->gatewayToken.len);
            }
        }
    }

    if (status == SC_NOT_EXTENDED) {
        // TODO add check for bodyContent = "Signature Needed"
        // from Java: if (bodyContent != null && bodyContent.indexOf("Signature Needed") >= 0) // for plugin validation only

        const char *bodyContent = json_object_get_string(response_body_json);
        char *p = NULL;
        if (bodyContent)
            p = strstr(bodyContent, "Signature Needed");
        if(p)
        {

            // New Challenge Model
            u_char *challenge = NULL;
            if (response_headers_json != NULL) {
                json_object *challengeJson = NULL;
                json_bool result = json_object_object_get_ex(response_headers_json, "Challenge", &challengeJson);

                if (result == TRUE && challengeJson != NULL) {
                    json_object *challengeValue = NULL;
                    if (json_object_array_length(challengeJson))
                        challengeValue = json_object_array_get_idx(challengeJson, 0);

                    if (challengeValue != NULL) {
                        const char* tmp = json_object_get_string(challengeValue);
                        u_char *last;
                        int len = strlen(tmp);
                        challenge = ngx_pcalloc(pool, len + 1);
                        last = ngx_copy(challenge, (u_char* )tmp, len);
                        *last = '\0';
                    }
                }
            }
            json_object_put(res_json);
            return handleSignatureRequired(json, r, url, conf, pool);
        } else {
            json_object_put(res_json);
            return handleSendLocalFile(json, r, url, conf, pool);
        }
    }

    json_object_put(json);

    if (status == NGX_HTTP_CONTINUE) {
        return handleAllowContinue(res_json, r, url, conf);
    }

    ngx_int_t rc;

    // For all other response codes, send along back to the browser
    logDebug(r->connection->log, 0, "Sending response status = %d", status);

    r->headers_out.status = status;
    json_object *response_content_type_json;
    json_object_object_get_ex(response_json, "content-type", &response_content_type_json);
    if (response_content_type_json != NULL) {
        const char* contentType;
        contentType = json_object_get_string(response_content_type_json);
        ngx_str_t str_tmp = ngx_string(contentType);
        r->headers_out.content_type = str_tmp;
    }
    json_object *response_cookies_json;
    json_object_object_get_ex(response_json, "cookies", &response_cookies_json);

    // Transfer response headers and cookies
    propagateResponseHeadersAndCookies(r, conf, response_headers_json, response_cookies_json);

    // Redirect?
    if (status == NGX_HTTP_MOVED_TEMPORARILY || status == NGX_HTTP_MOVED_PERMANENTLY) {
        // Headers already written, just end here
        json_object_put(res_json);
        return status;
    }

    //Transfer content
    if (response_body_json != NULL) {
        const char* body = json_object_get_string(response_body_json);
        if (body != NULL && strlen(body) > 0) {
            //logDebug(r->connection->log, 0, "raw body (%d) = %s",strlen(body), body);
            u_char* decoded_body = (u_char*) base64_decode(r, (unsigned char *) body);
            if (decoded_body == NULL) {
                // TODO error message here
                json_object_put(res_json);
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            ngx_buf_t *b;
            ngx_chain_t *out;
            size_t bodyLength = strlen((const char *) decoded_body);
            logDebug(r->connection->log, 0, "Decoded body length = %d", bodyLength);
            logDebug(r->connection->log, 0, "Decoded body = \n%s", decoded_body);

            // Set the content length header
            r->headers_out.content_length_n = bodyLength;
            rc = ngx_http_send_header(r);

            if (rc != NGX_OK) {
                logWarn(r->connection->log, 0, "Problem setting content length header, rc=%s", rc);
                json_object_put(res_json);
                return rc;
            }

            b = ngx_calloc_buf(r->pool);
            if (b == NULL) {
                // TODO error message here
                json_object_put(res_json);
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            out = ngx_alloc_chain_link(r->pool);

            out->buf = b;
            out->next = NULL;

            b->start = b->pos = decoded_body;
            b->end = b->last = decoded_body + bodyLength;
            b->memory = 1;
            b->last_buf = 1;

            rc = ngx_http_output_filter(r, out);
            if (rc != NGX_OK) {
                logWarn(r->connection->log, 0, "Problem writing response body, rc=%s", rc);
            }
            else {
                logDebug(r->connection->log, 0, "Finished writing response body");
            }
            json_object_put(res_json);
            return rc;
        }
    }

    // return rc;
    json_object_put(res_json);
    return NGX_OK;
}

/**
 * Handles if the Gateway needs our signature
 */
int handleSignatureRequired(json_object *request_json, ngx_http_request_t *r, const char *url, ngx_ssorest_plugin_conf_t *conf, ngx_pool_t *pool) {
    char randomText[33];
    const char* digest;

    generateSecureRandomString(randomText, 32);
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "Generated randomText: %s", randomText);
    digest = computeRFC2104HMAC(r, randomText, (char *) conf->secretKey.data);
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "Generated HMAC: %s", digest);

    json_object *atts_json;
    json_object_object_get_ex(request_json, "attributes", &atts_json);

    json_object *new_atts_json;
    enum json_tokener_error jerr = json_tokener_success; // TODO is this right?
    new_atts_json = json_tokener_parse_verbose(json_object_to_json_string(atts_json), &jerr);
    // TODO error handling here?

    // Escape String
    json_object_object_add(new_atts_json, "randomText", json_object_new_string(randomText));
    json_object_object_add(new_atts_json, "randomTextSigned", json_object_new_string(escape_str(r->pool, digest)));

    // Remove old gateway token if present
    json_object_object_del(new_atts_json, "gatewayToken");

    json_object_object_del(request_json, "attributes");
    json_object_object_add(request_json, "attributes", new_atts_json);

    logDebug(r->connection->log, 0, "New attributes for subrequest : %s", json_object_to_json_string(new_atts_json));

    //resend
    return postRequestToGateway(request_json, r, url, conf, pool);
}

/**
 * Handles if the Gateway needs content from a local file
 */
int handleSendLocalFile(json_object *request_json, ngx_http_request_t *r, const char *url, ngx_ssorest_plugin_conf_t *conf, ngx_pool_t *pool) {
    // TODO implement
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "Gateway response stated content required, looking for local content to supply");    
    struct fcc_fileinfo          fcc_file;
    struct fcc_fileinfo         *pfcc_file = &fcc_file;
    char                        *value;
    const char                  *enValue;
    u_char                      *last;
    ngx_str_t                    filename;
    int                          file_rc;
    ngx_http_variable_value_t   *v;

    v = ngx_pnalloc(pool, sizeof(ngx_http_variable_value_t));
    
    // Get requested file content
    get_ngx_http_request_document_uri(r, v);
    value = toStringSafety(pool, v);
    filename.len = strlen(value) + conf->localrootpath.len;
    filename.data = ngx_pnalloc(r->pool, filename.len + 1);
    last = ngx_copy(filename.data, conf->localrootpath.data, conf->localrootpath.len);
    last = ngx_copy(last, value, strlen(value));
    *last = '\0';

    file_rc = get_filecontent(r, pool, &filename, pfcc_file);
    
    // Logging is performed in get_filecontent functions.
    if (file_rc == FILE_NOT_FOUND)
        return NGX_HTTP_NOT_FOUND;
    if (file_rc == FILE_ERR) 
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    
    // Base64 Encode
    enValue = base64_encode(pool, pfcc_file->content);
    // ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "Local content found, resubmitting request to gateway");
    // ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "Content: %s", pfcc_file->content);
    // ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "Encoded Content: %s", enValue);

    json_object *atts_json;
    json_object_object_get_ex(request_json, "attributes", &atts_json);

    json_object_object_add(atts_json, "content", json_object_new_string(enValue));
    json_object_object_add(atts_json, "contentTimestamp", json_object_new_int64(pfcc_file->mtime));

    return postRequestToGateway(request_json, r, url, conf, pool);
}

void addSingleHeaderToRequest(ngx_http_request_t *r, const char *key, const char *value) {

    ngx_list_part_t *part;
    ngx_table_elt_t *h;
    ngx_table_elt_t *ho = NULL;
    ngx_uint_t       i;
    ngx_uint_t       key_len = strlen(key);
    
    ngx_ssorest_plugin_conf_t *conf = ngx_http_get_module_srv_conf(r, ngx_ssorest_plugin_module);
    if (conf->ignoreHeaders != NULL) {
        ngx_str_t *ignore_header = conf->ignoreHeaders->elts;
        for (i = 0; i < conf->ignoreHeaders->nelts; i++) {
            if (!strncasecmp(key, (char *) ignore_header[i].data, ignore_header[i].len)) {
                logError(r->connection->log, 0, "Skipping ignored header %s", key);
                return ;
            }
        }
    }


    part = &r->headers_in.headers.part;
    h = part->elts;

    for (i = 0; ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }
        if (key_len != h[i].key.len || ngx_strcasecmp((u_char *) key, h[i].key.data) != 0) {
            continue;
        }
        ho = &h[i];
    }
    if (ho == NULL)
    {
        ho = ngx_list_push(&r->headers_in.headers);
        if (ho == NULL) {
            logDebug(r->connection->log, 0, "Error retrieving headers from inbound request");
        }
        logDebug(r->connection->log, 0, "Adding new header %s", key);
    } else {
        //logDebug(r->connection->log, 0, "Found Original Header: '%s'-'%s'", ho->key.data, ho->value.data);
        logDebug(r->connection->log, 0, "Updating existing header %s", key);
    }
    ho->hash = 1;

    // Allocate the key
    ho->key.len = key_len;
    char* tmp_new_key = ngx_palloc(r->pool, ho->key.len + 1);
    tmp_new_key[0] = '\0';
    strcat(tmp_new_key, key);
    ho->key.data = (u_char *) tmp_new_key;

    //important!: set lowercases header key for hashing
    ho->lowcase_key = ngx_pnalloc(r->pool, ho->key.len);
    ngx_strlow(ho->lowcase_key, ho->key.data, ho->key.len);

    // Allocate the value
    ho->value.len = strlen(value);
    char* tmp_new_value = ngx_palloc(r->pool, ho->value.len + 1);
    tmp_new_value[0] = '\0';
    strcat(tmp_new_value, value);
    ho->value.data = (u_char *) tmp_new_value;

    logDebug(r->connection->log, 0, "Propagating request header: %s=%s", ho->key.data, ho->value.data);
}

/**
 * Handles when the Gateway says the request may continue
 */
int handleAllowContinue(json_object *res_json, ngx_http_request_t *r, const char *url, ngx_ssorest_plugin_conf_t *conf) {
    logDebug(r->connection->log, 0, "Entering handleAllowContinue");
    json_object *request_json;
    json_object *response_json;
    json_object *request_cookies_json;
    json_object *request_headers_json;
    json_object *jvalue;
    const char *value;
    json_object_object_get_ex(res_json, "response", &response_json);
    json_object_object_get_ex(res_json, "request", &request_json);
    json_object_object_get_ex(request_json, "headers", &request_headers_json);
    json_object_object_get_ex(request_json, "cookies", &request_cookies_json);

    // Transfer REQUEST headers and cookies (hint: not responses!)
    json_object_object_foreach(request_headers_json, key, valObj) {
        if (!json_object_array_length(valObj))
            continue;
        if (!strcasecmp(key, "cookie"))
            continue;
        jvalue = json_object_array_get_idx(valObj, 0);
        value = json_object_get_string(jvalue);
        addSingleHeaderToRequest(r, key, value);
    }
    // TODO transfer new request cookies too! And only the name=value pairs (not the addl cookie attributes)

    if (response_json != NULL) {
        json_object *response_cookies_json;
        json_object_object_get_ex(response_json, "cookies", &response_cookies_json);
        //Transfer any new cookies to the response
        propagateResponseHeadersAndCookies(r, conf, NULL, response_cookies_json);
    }

    /* free json object */
    json_object_put(res_json);
    logDebug(r->connection->log, 0, "Exiting handleAllowContinue");
    return NGX_HTTP_CONTINUE;
}

/**
 * Sends the response headers and cookies from the Gateway reply to the client response
 */
void propagateResponseHeadersAndCookies(ngx_http_request_t *r, ngx_ssorest_plugin_conf_t *conf, json_object *headers_json, json_object *cookies_json) {
    int i;
    int arraylen;

    // Transfer response cookies
    if (cookies_json != NULL) {
        ngx_table_elt_t *ho;
        arraylen = json_object_array_length(cookies_json);
        logDebug(r->connection->log, 0, "JSon cookies array length in response: %d", arraylen);
        json_object *cookie = NULL;
        for (i = 0; i < arraylen; i++) {
            cookie = json_object_array_get_idx(cookies_json, i);
            const char* cvalue = NULL;
            const char* cname = NULL;
            const char* cpath = NULL;
            const char* cdomain = NULL;
            int chttpOnly = 0, csecure = 0, cmaxAge = 0;
            int issetmaxAge = 0;
            json_object_object_foreach(cookie, key, val) {
                if (ngx_strncmp(key, "name", sizeof("name") - 1) == 0) {
                    cname = json_object_get_string(val);
                }
                else if (ngx_strncmp(key, "value", sizeof("value") - 1) == 0) {
                    cvalue = json_object_get_string(val);
                }
                else if (ngx_strncmp(key, "path", sizeof("path") - 1) == 0) {
                    cpath = json_object_get_string(val);
                }
                else if (ngx_strncmp(key, "domain", sizeof("domain") - 1) == 0) {
                    cdomain = json_object_get_string(val);
                }
                else if (ngx_strncmp(key, "maxAge", sizeof("maxAge") - 1) == 0) {
                    issetmaxAge = 1;
                    cmaxAge = json_object_get_int(val);
                }
                else if (ngx_strncmp(key, "secure", sizeof("secure") - 1) == 0) {
                    csecure = json_object_get_boolean(val);
                }
                // else if (ngx_strncmp(key, "version", sizeof("version") - 1) == 0) {
                //     version = json_object_get_int(val);
                // }
                else if (ngx_strncmp(key, "httpOnly", sizeof("httpOnly") - 1) == 0) {
                    chttpOnly = json_object_get_boolean(val);
                }
            }
            if (!cname || !cvalue)
                continue;
            logDebug(r->connection->log, 0, "Found Response cookie %s=%s", cname, cvalue);
            char * tmp_new_str;
            char *last;
            int clen = strlen(cname) + 1 + strlen(cvalue) + 1;

            if (issetmaxAge && cmaxAge != -1)
            {
                clen += sizeof(expires) - 1;
            }

            if (cdomain) {
                clen = clen + sizeof("; domain=") - 1 + strlen(cdomain);
            }
            if (cpath != NULL) {
                clen = clen + sizeof("; path=") - 1 + strlen(cpath);
            }
            if (chttpOnly)
                clen += sizeof("; HttpOnly") - 1;

            if (csecure)
                clen += sizeof("; Secure") - 1;



            tmp_new_str = ngx_palloc(r->pool, clen);
            last = (char *) ngx_copy(tmp_new_str, cname, strlen(cname));
            *last++ = '=';
            last = (char *) ngx_copy(last, cvalue, strlen(cvalue));

            if (issetmaxAge && cmaxAge != -1)
            {
                // Compute expires
                last = (char *) ngx_copy(last, "; expires=", sizeof("; expires=") - 1);
                if (cmaxAge > 0)
                {
                    last = (char *) ngx_http_cookie_time((u_char *) last, ngx_time() + cmaxAge);
                } else if (cmaxAge == 0)
                {
                    last = (char *) ngx_copy(last, "Thu, 01 Jan 1970 00:00:00 GMT", sizeof("Thu, 01 Jan 1970 00:00:00 GMT") - 1);
                }
            }

            if (cdomain)
            {
                last = (char *) ngx_copy(last, "; domain=", sizeof("; domain=") - 1);
                last = (char *) ngx_copy(last, cdomain, strlen(cdomain));
            }

            if (cpath)
            {
                last = (char *) ngx_copy(last, "; path=", sizeof("; path=") - 1);
                last = (char *) ngx_copy(last, cpath, strlen(cpath)); 
            }

            if (csecure)
            {
                last = (char *) ngx_copy(last, "; Secure", sizeof("; Secure") - 1);
            }

            if (chttpOnly)
            {
                last = (char *) ngx_copy(last, "; HttpOnly", sizeof("; HttpOnly") - 1);
            }

            
            *last = '\0';

            ho = ngx_list_push(&r->headers_out.headers);

            ho->key.len = sizeof("Set-Cookie") - 1;
            ho->key.data = (u_char *) "Set-Cookie";
            ho->value.len = strlen(tmp_new_str);
            ho->value.data = (u_char *) tmp_new_str;

            logDebug(r->connection->log, 0, "Sending cookie to client: %s\n", tmp_new_str);
        }
    }
    else
        logDebug(r->connection->log, 0, "No cookies in JSON response");

    // Transfer headers
    if (headers_json != NULL) {
        json_object_object_foreach(headers_json, key, val)
        {
            logDebug(r->connection->log, 0, "Processing response header from JSon: %s", key);
            
            if (ngx_strncmp(key, "gatewayToken", 12) == 0) // skip the gatewayToken
                continue;

            if (val != NULL) {
                arraylen = json_object_array_length(val);
                for (i = 0; i < arraylen; i++) {
                    ngx_table_elt_t *header;
                    json_object     *hvalue;
                    size_t          header_value_len, header_key_len;
                    u_char          *header_value, *header_key, *last;
                    char            *strValue;

                    header   = ngx_list_push(&r->headers_out.headers);
                    hvalue   = json_object_array_get_idx(val, i);
                    strValue = (char *) json_object_get_string(hvalue);

                    header_key_len   = strlen(key);
                    header_value_len = strlen(strValue);
                    
                    header_key = ngx_pnalloc(r->pool, header_key_len + 1);
                    last       = ngx_copy(header_key, key, header_key_len);
                    *last      = '\0';

                    header_value = ngx_pnalloc(r->pool, header_value_len + 1);
                    last         = ngx_copy(header_value, strValue, header_value_len);
                    *last        = '\0';
                    
                    header->hash = 1;
                    header->key.len = header_key_len;
                    header->key.data = header_key;
                    header->value.len = header_value_len;
                    header->value.data = header_value;
                    logDebug(r->connection->log, 0, "Adding %s header directly: %s (length=%d)", header_key, header_value, header_value_len);
                }
            }
        }
    }
    else
        logDebug(r->connection->log, 0, "No headers in JSON response");
}

json_object *buildJsonArraySingleAttributes(ngx_http_request_t *r, ngx_ssorest_plugin_conf_t *conf)
{
    json_object *json;
    json_object *jsonarray_locale;
    ngx_array_t *locales;
    ngx_str_t *locale;
    ngx_pool_t *pool;
    ngx_uint_t i;
    char *value = "";
    int int_val;
    ngx_http_variable_value_t *v;

    pool = ngx_create_pool(MY_POOL_SIZE, r->connection->log);
    json = json_object_new_object();
    v = ngx_pnalloc(pool, sizeof(ngx_http_variable_value_t));

    // Method
    get_ngx_http_request_method(r, v);
    value = toStringSafety(pool, v);
    json_object_object_add(json, "method", json_object_new_string(value));

    // URL
    get_ngx_http_request_url(r, v, conf->useServerNameAsDefault);
    value = toStringSafety(pool, v);
    json_object_object_add(json, "url", json_object_new_string(value));

    // Protocol
    get_ngx_http_request_protocol(r, v);
    value = toStringSafety(pool, v);
    json_object_object_add(json, "protocol", json_object_new_string(value));

    // Content Encoding
    // get_ngx_http_request_content_encoding(r, v);
    get_ngx_http_request_content_type(r, v);
    value = toStringSafety(pool, v);
    ngx_int_t  n;
    int        captures[(1 + 1) * 3];
    ngx_str_t input;
    input.data = (u_char *) value;
    input.len = strlen(value);
    
    n = ngx_regex_exec(conf->regex, &input, captures, (1 + 1) * 3);
    if (n >= 0) {
        /* string matches expression */
        value = value + captures[2];
    } else if (n == NGX_REGEX_NO_MATCHED) {
        value = "";
        logError(r->connection->log, 0, "No match was found");
    } else {
        value = "";
        logError(r->connection->log, 0, ngx_regex_exec_n " failed: %i", n);
    }

    json_object_object_add(json, "characterEncoding", json_object_new_string(value));

    // Content Length
    get_ngx_http_request_content_length(r, v);
    value = toStringSafety(pool, v);
    int_val = atoi(value);
    json_object_object_add(json, "contentLength", json_object_new_int(int_val));

    // Content Type
    get_ngx_http_request_content_type(r, v);
    value = toStringSafety(pool, v);
    json_object_object_add(json, "contentType", json_object_new_string(value));

    // Context Path
    get_ngx_http_request_context_path(r, v);
    value = toStringSafety(pool, v);
    json_object_object_add(json, "contextPath", json_object_new_string(value));

    // Local Address
    get_ngx_http_request_server_addr(r, v);
    value = toStringSafety(pool, v);
    json_object_object_add(json, "localAddr", json_object_new_string(value));

    // Local Name
    get_ngx_http_request_server_name(r, v);
    value = toStringSafety(pool, v);
    json_object_object_add(json, "localName", json_object_new_string(value));

    // LocalPort
    get_ngx_http_request_server_port(r, v);
    value = toStringSafety(pool, v);
    int_val = atoi(value);
    json_object_object_add(json, "localPort", json_object_new_int(int_val));

    // Remote Address
    get_ngx_http_request_remote_addr(r, v);
    value = toStringSafety(pool, v);
    json_object_object_add(json, "remoteAddr", json_object_new_string(value));

    // Remote Name
    get_ngx_http_request_remote_addr(r, v);
    value = toStringSafety(pool, v);
    json_object_object_add(json, "remoteHost", json_object_new_string(value));

    // Remote Port
    get_ngx_http_request_remote_port(r, v);
    value = toStringSafety(pool, v);
    int_val = atoi(value);
    json_object_object_add(json, "remotePort", json_object_new_int(int_val));

    // Secure
    get_ngx_http_request_issecure(r, v);
    value = toStringSafety(pool, v);
    int_val = atoi(value);
    json_object_object_add(json, "secure", json_object_new_boolean(int_val));

    // Scheme
    get_ngx_http_request_scheme(r, v);
    value = toStringSafety(pool, v);
    json_object_object_add(json, "scheme", json_object_new_string(value));

    // Server Name
    get_ngx_http_request_server_name(r, v);
    value = toStringSafety(pool, v);
    json_object_object_add(json, "serverName", json_object_new_string(value));

    // ServerPort
    get_ngx_http_request_server_port(r, v);
    value = toStringSafety(pool, v);
    int_val = atoi(value);
    json_object_object_add(json, "serverPort", json_object_new_int(int_val));

    // Servlet Path
    json_object_object_add(json, "servletPath", json_object_new_string(""));

    jsonarray_locale = json_object_new_array();
    locales = get_ngx_http_request_locales(r);
    locale = (ngx_str_t *) locales->elts;

    for (i = 0; i < locales->nelts; i++)
        json_object_array_add(jsonarray_locale, json_object_new_string((char*) locale[i].data));
    json_object_object_add(json, "locales", jsonarray_locale);

    ngx_destroy_pool(pool);
    return json;
}

json_object *buildJsonArrayHeaders(ngx_http_request_t *r)
{
    json_object *json;
    json_object *jsonarray_accept_language;
    json_object *jsonarray_accept_encoding;
    //json_object *jsonarray_connection;
    json_object *jsonarray_accept;
    json_object *jsonarray_host;
    json_object *jsonarray_user_agent;
    json_object *jsonarray_authorization;
    ngx_pool_t *pool;
    char *value = "";
    ngx_http_variable_value_t *v;

    pool = ngx_create_pool(MY_POOL_SIZE, r->connection->log);
    json = json_object_new_object();
    v = ngx_pnalloc(pool, sizeof(ngx_http_variable_value_t));

    // accept-language
    get_ngx_http_request_accept_language(r, v);
    value = toStringSafety(pool, v);
    jsonarray_accept_language = json_object_new_array();
    json_object_array_add(jsonarray_accept_language, json_object_new_string(value));
    json_object_object_add(json, "accept-language", jsonarray_accept_language);

    // COOKIE
    // We skip this because cookies are a separate structure

    // connection - skip this
    //get_ngx_http_request_connection(r, v);
    //value = toStringSafety(pool, v);
    //jsonarray_connection = json_object_new_array();
    //json_object_array_add(jsonarray_connection, json_object_new_string(value));
    //json_object_object_add(json, "connection", jsonarray_connection);

    // accept
    get_ngx_http_request_accept(r, v);
    value = toStringSafety(pool, v);
    jsonarray_accept = json_object_new_array();
    json_object_array_add(jsonarray_accept, json_object_new_string(value));
    json_object_object_add(json, "accept", jsonarray_accept);

    // host
    get_ngx_http_request_hostname(r, v);
    value = toStringSafety(pool, v);
    jsonarray_host = json_object_new_array();
    json_object_array_add(jsonarray_host, json_object_new_string(value));
    json_object_object_add(json, "host", jsonarray_host);

    // accept-encoding
    get_ngx_http_request_accept_encoding(r, v);
    value = toStringSafety(pool, v);
    jsonarray_accept_encoding = json_object_new_array();
    json_object_array_add(jsonarray_accept_encoding, json_object_new_string(value));
    json_object_object_add(json, "accept-encoding", jsonarray_accept_encoding);

    // user-agent
    get_ngx_http_request_user_agent(r, v);
    value = toStringSafety(pool, v);
    jsonarray_user_agent = json_object_new_array();
    json_object_array_add(jsonarray_user_agent, json_object_new_string(value));
    json_object_object_add(json, "user-agent", jsonarray_user_agent);

    if (r->headers_in.authorization != NULL) {
        jsonarray_authorization = json_object_new_array();

        logDebug(r->connection->log, 0, "found request authorization key = %s", r->headers_in.authorization->key.data);
        logDebug(r->connection->log, 0, "found request authorization value = %s", r->headers_in.authorization->value.data);

        json_object_array_add(jsonarray_authorization, json_object_new_string((const char *) r->headers_in.authorization->value.data));
        json_object_object_add(json, (const char *) r->headers_in.authorization->key.data, jsonarray_authorization);
    }
    ngx_destroy_pool(pool);
    return json;
}

json_object *buildJsonArrayCookies(ngx_http_request_t *r, ngx_array_t *ssoZone) {
    json_object *json;
    json_object *json_cookies;
    char *cookie = NULL;
    char *value = NULL;
    char *rest = NULL;
    char *cookie_name = NULL;
    char *cookie_value = NULL;
    ngx_http_variable_value_t *v;

    json = json_object_new_array();
    v = ngx_pnalloc(r->pool, sizeof(ngx_http_variable_value_t));

    get_ngx_http_request_unparsed_cookies(r, v);
    value = toStringSafety(r->pool, v);
    rest = value;
    while ((cookie = strtok_r(rest, "; ", &rest)))
    {
        json_cookies = json_object_new_object();

        cookie_name = ngx_palloc(r->pool, strlen(cookie));
        cookie_value = ngx_palloc(r->pool, strlen(cookie));
        sscanf(cookie, "%[^=]=%s", cookie_name, cookie_value);

        if(ssoZone)
        {
            size_t size;
            ngx_uint_t i;
            ngx_uint_t flag = 0;
            ngx_str_t *ssozone;

            size = ssoZone->nelts;
            ssozone = ssoZone->elts;

            for(i = 0; i < size; i++)
            {
                if (!strncasecmp((char *) cookie_name, (char *) ssozone[i].data, ssozone[i].len)) {
                    logDebug(r->connection->log, 0, "Transferring request cookie to JSon payload: %s=%s", cookie_name, cookie_value);
                    json_object_object_add(json_cookies, "name", json_object_new_string((const char*) cookie_name));
                    json_object_object_add(json_cookies, "value", json_object_new_string((const char*) cookie_value));
                    json_object_array_add(json, json_cookies);
                    flag = 1;
                    break;
                }
            }
            if(!flag)
                logDebug(r->connection->log, 0, "Skipping request cookie outside of our zone: %s", cookie_name);
        } else {
            logDebug(r->connection->log, 0, "Transferring request cookie to JSon payload: %s=%s", cookie_name, cookie_value);
            json_object_object_add(json_cookies, "name", json_object_new_string((const char*) cookie_name));
            json_object_object_add(json_cookies, "value", json_object_new_string((const char*) cookie_value));
            json_object_array_add(json, json_cookies); 
        }
        

        ngx_pfree(r->pool, cookie_name);
        ngx_pfree(r->pool, cookie_value);
    }
    
    return json;
}

json_object *buildJsonArayAttributes(ngx_ssorest_plugin_conf_t *conf) {
    json_object *json = json_object_new_object();
    if (conf->acoName.len > 0) {
        json_object_object_add(json, "acoName", json_object_new_string((const char*) conf->acoName.data));
    }
    json_object_object_add(json, "pluginID", json_object_new_string((const char*) conf->pluginId.data));
    if (conf->gatewayToken.len > 0) {
        json_object_object_add(json, "gatewayToken", json_object_new_string((const char*) conf->gatewayToken.data));
    }
    return json;
}

json_object *buildJsonArayGetParameters(ngx_http_request_t *r) {
    json_object *json;
    json_object *json_temp = NULL;
    json_object *jsonarray_value;
    ngx_http_variable_value_t *v;
    char *args = NULL;
    char *pair = NULL;
    char *saved = NULL;
    char *key = NULL;
    char *value = NULL;
    char *inner_args = NULL;
    char *inner_pair = NULL;
    char *inner_saved = NULL;
    char *inner_key = NULL;
    char *inner_value = NULL;
    ngx_pool_t *pool;

    pool = ngx_create_pool(MY_POOL_SIZE, r->connection->log);
    json = json_object_new_object();
    v = ngx_pnalloc(pool, sizeof(ngx_http_variable_value_t));

    get_ngx_http_request_args(r, v);
    args = toStringSafety(pool, v);

    for (pair = strtok_r(args, "&", &saved); pair; pair = strtok_r(NULL, "&", &saved)) {
        jsonarray_value = json_object_new_array();
        key = ngx_pcalloc(pool, strlen(pair));
        value = ngx_pcalloc(pool, strlen(pair));
        if (key == NULL || value == NULL)
        {
            logError(r->connection->log, 0, "Could not Allocate Memory");
            goto failed;
        }
        sscanf(pair, "%[^=]=%s", key, value);
        json_object_object_get_ex(json, key, &json_temp);
        if (json_temp != NULL) {
            ngx_pfree(pool, key);
            ngx_pfree(pool, value);
            continue;
        }

        // Unescape querystring Value
        char *unesc_str = ngx_pnalloc(pool, strlen(value) + 1);
        if (unesc_str == NULL)
        {
            logError(r->connection->log, 0, "Could not Allocate Memory");
            goto failed;
        }
        unescape_str(value, unesc_str);
        json_object_array_add(jsonarray_value, json_object_new_string(unesc_str));
        ngx_pfree(pool, unesc_str);

        inner_args = ngx_alloc(strlen(saved) + 1, r->connection->log);
        memcpy(inner_args, saved, strlen(saved));
        inner_args[strlen(saved)] = '\0';

        for (inner_pair = strtok_r(inner_args, "&", &inner_saved); inner_pair;
                inner_pair = strtok_r(NULL, "&", &inner_saved))
                        {
            inner_key = ngx_pcalloc(pool, strlen(inner_pair));
            inner_value = ngx_pcalloc(pool, strlen(inner_pair));
            sscanf(inner_pair, "%[^=]=%s", inner_key, inner_value);

            if (ngx_strcmp(key, inner_key) == 0)
                    {
                // Unescape querystring Value
                char *unesc_str = ngx_pnalloc(pool, strlen(inner_value) + 1);
                if (unesc_str == NULL)
                {
                    logError(r->connection->log, 0, "Could not Allocate Memory");
                    goto failed;
                }
                unescape_str(inner_value, unesc_str);
                json_object_array_add(jsonarray_value, json_object_new_string(unesc_str));
                ngx_pfree(pool, unesc_str);
            }
            ngx_pfree(pool, inner_key);
            ngx_pfree(pool, inner_value);

        }
        json_object_object_add(json, key, jsonarray_value);
        ngx_pfree(pool, key);
        ngx_pfree(pool, value);
    }
    failed:
    ngx_destroy_pool(pool);
    return json;
}

char* toStringSafety(ngx_pool_t *pool, ngx_http_variable_value_t *v) {
    if (v == NULL || v->not_found) {
        return "";
    }
    char *dst = ngx_pnalloc(pool, v->len + 1);
    strncpy(dst, (const char *) (v->data), v->len);
    dst[v->len] = '\0';
    return dst;
}

json_object *buildJsonRequest(ngx_http_request_t *r, ngx_pool_t *pool, ngx_ssorest_plugin_conf_t *conf) {
    json_object *json;
    json = buildJsonArraySingleAttributes(r, conf);
    json_object_object_add(json, "headers", buildJsonArrayHeaders(r));
    json_object *json_cookies = buildJsonArrayCookies(r, conf->ssoZone);
    if (json_cookies != NULL)
        json_object_object_add(json, "cookies", json_cookies);
    if(conf->sendFormParameters) {
        json_object *json_params = buildJsonArayGetParameters(r);
        if (json_params != NULL) {
            json_object_object_add(json, "parameters", json_params);
        }
    }
    json_object_object_add(json, "attributes", buildJsonArayAttributes(conf));

    return json;
}

char *escape_str(ngx_pool_t *p, const char *src)
{
    char *h = "0123456789abcdef";
    char *copy = ngx_palloc(p, 3 * strlen((char*) src) + 3);
    const u_char *s = (const u_char*) src;
    u_char *d = (u_char *) copy;
    unsigned c;
    while ((c = *s))
    {
        if (('a' <= c && c <= 'z')
                || ('A' <= c && c <= 'Z')
                || ('0' <= c && c <= '9') || c == '-' || c == '_' || c == '.')
            *d++ = c;
        else if (c == ' ')
            *d++ = '+';
        else {
            *d++ = '%';
            *d++ = h[c >> 4];
            *d++ = h[c & 0x0f];
        }
        ++s;
    }

    *d = '\0';
    return copy;
}

inline int ishex(int x)
{
    return (x >= '0' && x <= '9') ||
            (x >= 'a' && x <= 'f') ||
            (x >= 'A' && x <= 'F');
}

int unescape_str(char *s, char *dec)
{
    char *o;
    const char *end = s + strlen(s);
    int c;

    for (o = dec; s <= end; o++) {
        c = *s++;
        if (c == '+')
            c = ' ';
        else if (c == '%' && (!ishex(*s++) ||
                !ishex(*s++) ||
                !sscanf(s - 2, "%2x", &c)))
            return -1;

        if (dec)
            *o = c;
    }

    return o - dec;
}
