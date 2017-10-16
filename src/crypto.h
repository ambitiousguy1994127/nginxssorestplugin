#include <ngx_http.h>

#define SHA1_DIGESTLENGTH 20
#define LINE_CHARACTER 40

void 		generateSecureRandomString(char *s, const int length);
const char *computeRFC2104HMAC(ngx_http_request_t *r, char *data, char *key);
const char *base64_encode(ngx_pool_t *pool, unsigned char *source);
const char *base64_decode(ngx_http_request_t *r, unsigned char *source);
void 		print_binary(void *request, const void* data, int len);