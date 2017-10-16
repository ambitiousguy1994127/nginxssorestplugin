#include <ngx_http.h>

#define FILE_OK			0
#define FILE_NOT_FOUND 	1
#define FILE_ERR		2

struct fcc_fileinfo
{
	u_char *content;
	time_t mtime;
};

ngx_int_t get_filecontent(ngx_http_request_t *r, ngx_pool_t *pool, ngx_str_t *name, struct fcc_fileinfo *file);