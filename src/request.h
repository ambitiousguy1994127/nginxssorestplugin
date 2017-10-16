#include <ngx_http.h>

ngx_int_t 	 get_ngx_http_request_method(ngx_http_request_t *r, ngx_http_variable_value_t *v);
ngx_int_t 	 get_ngx_http_request_url(ngx_http_request_t *r, ngx_http_variable_value_t *v, int default_servername);
ngx_int_t 	 get_ngx_http_request_protocol(ngx_http_request_t *r, ngx_http_variable_value_t *v);
ngx_int_t 	 get_ngx_http_request_content_encoding(ngx_http_request_t *r, ngx_http_variable_value_t *v);
ngx_int_t 	 get_ngx_http_request_content_length(ngx_http_request_t *r, ngx_http_variable_value_t *v);
ngx_int_t 	 get_ngx_http_request_content_type(ngx_http_request_t *r, ngx_http_variable_value_t *v);
ngx_int_t 	 get_ngx_http_request_context_path(ngx_http_request_t *r, ngx_http_variable_value_t *v);
ngx_int_t 	 get_ngx_http_request_server_addr(ngx_http_request_t *r, ngx_http_variable_value_t *v);
ngx_int_t 	 get_ngx_http_request_server_name(ngx_http_request_t *r, ngx_http_variable_value_t *v);
ngx_int_t 	 get_ngx_http_request_server_port(ngx_http_request_t *r, ngx_http_variable_value_t *v);
ngx_int_t 	 get_ngx_http_request_remote_addr(ngx_http_request_t *r, ngx_http_variable_value_t *v);
ngx_int_t 	 get_ngx_http_request_remote_port(ngx_http_request_t *r, ngx_http_variable_value_t *v);
ngx_int_t 	 get_ngx_http_request_issecure(ngx_http_request_t *r, ngx_http_variable_value_t *v);
ngx_int_t 	 get_ngx_http_request_scheme(ngx_http_request_t *r, ngx_http_variable_value_t *v);
ngx_int_t 	 get_ngx_http_request_uri(ngx_http_request_t *r, ngx_http_variable_value_t *v);
ngx_int_t 	 get_ngx_http_request_hostname(ngx_http_request_t *r, ngx_http_variable_value_t *v);
ngx_int_t 	 get_ngx_http_request_accept_language(ngx_http_request_t *r, ngx_http_variable_value_t *v);
ngx_int_t 	 get_ngx_http_request_connection(ngx_http_request_t *r, ngx_http_variable_value_t *v);
ngx_int_t 	 get_ngx_http_request_accept(ngx_http_request_t *r, ngx_http_variable_value_t *v);
ngx_int_t 	 get_ngx_http_request_accept_encoding(ngx_http_request_t *r, ngx_http_variable_value_t *v);
ngx_int_t 	 get_ngx_http_request_user_agent(ngx_http_request_t *r, ngx_http_variable_value_t *v);
ngx_int_t    get_ngx_http_request_unparsed_cookies(ngx_http_request_t *r, ngx_http_variable_value_t *v);
ngx_int_t 	 get_ngx_http_request_extension(ngx_http_request_t *r, ngx_http_variable_value_t *v);
ngx_int_t 	 get_ngx_http_request_args(ngx_http_request_t *r, ngx_http_variable_value_t *v);
ngx_int_t 	 get_ngx_http_request_document_uri(ngx_http_request_t *r, ngx_http_variable_value_t *v);
ngx_int_t	 get_ngx_http_request_headers(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
ngx_int_t 	 get_ngx_http_request_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
ngx_array_t *get_ngx_http_request_locales(ngx_http_request_t *r);


