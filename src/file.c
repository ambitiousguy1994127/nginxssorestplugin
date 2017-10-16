#include "file.h"
#include <ngx_config.h>
#include <ngx_core.h>
#include "logging.h"

ngx_int_t get_filecontent(ngx_http_request_t *r, ngx_pool_t *pool, ngx_str_t *name, struct fcc_fileinfo *fcc_file)
{
    time_t                      mtime;
    size_t                      size;
    ssize_t                     n;
    ngx_int_t                   rc;
    ngx_file_t                  file;
    ngx_file_info_t             fi;

    ngx_memzero(&file, sizeof(ngx_file_t));
    file.name = *name;
    file.log = r->connection->log;

    file.fd = ngx_open_file(name->data, NGX_FILE_RDONLY, 0, 0);
    if (file.fd == NGX_INVALID_FILE) {
        logError(r->connection->log, ngx_errno,
                           ngx_open_file_n " \"%s\" failed", name->data);
        return FILE_NOT_FOUND;
    }

    if (ngx_fd_info(file.fd, &fi) == NGX_FILE_ERROR) {
        logError(r->connection->log, ngx_errno,
                           ngx_fd_info_n " \"%s\" failed", name->data);
        goto failed;
    }

    size = (size_t) ngx_file_size(&fi);
    mtime = ngx_file_mtime(&fi);
    fcc_file->mtime = mtime;
    
    fcc_file->content = (u_char*) ngx_palloc(pool, size + 1);
    if (fcc_file->content == NULL) {
        goto failed;
    }

    n = ngx_read_file(&file, fcc_file->content, size, 0);

    if (n == NGX_ERROR) {
        logError(r->connection->log, ngx_errno,
                           ngx_read_file_n " \"%s\" failed", name->data);
        goto failed;
    }

    // Add null terminate.
    fcc_file->content[size] = '\0';

    if ((size_t) n != size) {
        logError(r->connection->log, ngx_errno,
            ngx_read_file_n " \"%s\" returned only %z bytes instead of %z", name->data, n, size);
        goto failed;
    }


    rc = FILE_OK;

    goto done;

failed:

    rc = FILE_ERR;

done:

    if (ngx_close_file(file.fd) == NGX_FILE_ERROR) {
        logError(r->connection->log, ngx_errno,
                           ngx_close_file_n " \"%s\" failed", name->data);
    }

    return rc;
}