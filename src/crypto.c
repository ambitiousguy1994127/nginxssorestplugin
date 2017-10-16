#include <openssl/hmac.h>
#include "crypto.h"
#include "logging.h"

void generateSecureRandomString(char *s, const int length)
{
    static const char alphanum[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    int i;
    for (i = 0; i < length; ++i) {
        s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
    }

    s[length] = '\0';
}

const char *computeRFC2104HMAC(ngx_http_request_t *r, char *data, char *key)
{
    u_char* mdString;
    ngx_str_t src;
    ngx_str_t result;

    if (key == NULL || data == NULL)
    {
        logError(r->connection->log, 0, "Could not parse parameter");   
        return NULL;
    }

    /* Generate HMAC using openssl */
    mdString = HMAC(EVP_sha1(), key, strlen(key), (u_char*) data, strlen(data), NULL, NULL);

    /* Allocate Memory for generating hmac */
    src.data    = ngx_pnalloc(r->pool, SHA1_DIGESTLENGTH + 1);
    if(src.data == NULL)
    {
        logError(r->connection->log, 0, "Could not Allocate Memory");
        return NULL;
    }
    memcpy(src.data, mdString, SHA1_DIGESTLENGTH);
    src.len             = SHA1_DIGESTLENGTH;
    src.data[src.len]   = '\0';

    /* Base64Encode using Nginx Utility Api */
    result.len          = ngx_base64_encoded_length(src.len);
    result.data         = ngx_pnalloc(r->pool, result.len + 1);

    if(result.data  == NULL)
    {
        logError(r->connection->log, 0, "Could not Allocate Memory");
        return NULL;   
    }
    ngx_encode_base64(&result, &src);
    result.data[result.len] = '\0';

    // Free Memory
    ngx_pfree(r->pool, src.data);
    return (const char*) result.data;
}

const char *base64_encode(ngx_pool_t *pool, unsigned char *source)
{
    ngx_str_t dst;
    ngx_str_t src;
    src.len = strlen((char *) source);
    src.data = (u_char*)source;
    dst.len = ngx_base64_encoded_length(src.len);
    dst.data = ngx_pnalloc(pool, dst.len + 1);
    if(dst.data == NULL)
        return NULL;
    ngx_encode_base64(&dst, &src); 
    dst.data[dst.len] = '\0';
    return (const char*)dst.data;
}

const char *base64_decode(ngx_http_request_t *r, unsigned char *source)
{
    ngx_str_t dst;
    ngx_str_t src;
    ngx_int_t rc;
    
    src.len     = strlen((char *) source);
    src.data    = source;
    dst.len     = ngx_base64_decoded_length(src.len);
    dst.data    = ngx_pnalloc(r->pool, dst.len + 1);
    if (dst.data == NULL)
    {
        logError(r->connection->log, 0, "Could not allocate memory for base64decode");
        return NULL;
    }

    rc = ngx_decode_base64(&dst, &src);

    if (rc != NGX_OK)
    {
        logError(r->connection->log, 0, "Could not decode Base64 content, rc=%d", rc);
        return NULL;
    }
    dst.data[dst.len] = '\0';
    return (const char*) dst.data;
}

void print_binary(void *request, const void* data, int len)
{
  ngx_http_request_t *r = (ngx_http_request_t *) request;
  int     ii;
  int linenr = 0;
  u_char *p = (u_char *)data;
  
  size_t  size = LINE_CHARACTER*3 + 1;
  char   *value = ngx_pcalloc(r->pool, size);
  char *offset = value;
  memset(value, 0, size);
  
  for(ii = 0; ii < len; ii++)
  { 
    if(((ii+1) % LINE_CHARACTER == 0) || 
        ((ii == len - 1) && (len % LINE_CHARACTER)))
    {
        sprintf(offset, "%02x ", p[ii]);
        offset+=3;
        *offset = '\0';
        logDebug(r->connection->log, 0, "%2d: %s", ++linenr, value);
        memset(value, 0, size);
        offset = value;
        continue;
    }
    sprintf(offset, "%02x ", p[ii]);
    offset+=3;
   }
  // Free
  ngx_pfree(r->pool, value);
}
