#include "common.h"

#define DEFAULT_PORT 7000
#define DEFAULT_BACKLOG 128

typedef struct {
    uv_tcp_t server;
    zpl_pool connection_pool;
    zpl_allocator connection_pool_allocator;
    zpl_allocator general_allocator;
    zpl_allocator arena_allocator;
}server_context_t;

typedef struct {
    uv_tcp_t client;
    uv_write_t writer;
    server_context_t* server;
} connection_t;

typedef struct {
    const char* method;
    int status;
    size_t method_len;
    const char* path;
    size_t path_len;
    const char* msg;
    size_t msg_len;
}request_data;

static void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {

    zpl_allocator allocator =  ((connection_t *)handle->data)->server->arena_allocator;
    
    buf->base = (char*) zpl_alloc(allocator,suggested_size);
    buf->len = suggested_size;
}

static void on_close(uv_handle_t* handle) {
    zpl_allocator allocator =  ((connection_t *)handle->data)->server->connection_pool_allocator;
    zpl_free(allocator,((connection_t *)handle->data));
}

static void on_write(uv_write_t* req, int status){
    uv_close((uv_handle_t*) req->handle, on_close);
}


typedef void (*http_handler)(request_data data,zpl_string* response);

static int handle_get_func(http_handler handler,request_data data,const char* requested_path,zpl_string* response){
    int result = false;
    if(zpl_strncmp(data.method,"GET",3)==0){
        if(zpl_strncmp(data.path,requested_path,data.path_len)==0
           || (zpl_strncmp(requested_path,"/*",2)==0)) {
            handler(data,response);
            result = true;
        }
    }
    return result;
}

static int handle_post_func(http_handler handler,request_data data,const char* requested_path,zpl_string* response){
    int result = false;
    if(zpl_strncmp(data.method,"POST",4)==0){
        if(zpl_strncmp(data.path,requested_path,data.path_len)==0
           || (zpl_strncmp(requested_path,"/*",2)==0)) {
            handler(data,response);
            result = true;
        }
    }
    return result;
}


static void wildcard_path_handler(request_data data,zpl_string *response){
    
    *response = zpl_string_appendc(*response,"HTTP/1.1 200 OK \r\n" \
                               "\r\n");
    *response = zpl_string_appendc(*response,"<!DOCTYPE html>\r\n" \
                                  "<html>\r\n"\
                                  "<body>\r\n"\
                                  "\r\n"\
                                  "<h1>Heading</h1>\r\n" \
                                  "<p>Paragraph.</p>\r\n" \
                                  "<p>Path: ");
    *response = zpl_string_append_length(*response,data.path,data.path_len);
    *response = zpl_string_appendc(*response,"<p>\r\n" \
                                  "</body>\r\n"\
                                  "</html>\r\n");
}

static void forbidden_handler(request_data data,zpl_string *response){

    zpl_allocator allocator = ZPL_STRING_HEADER(*response)->allocator;
    *response = zpl_string_appendc(*response,"HTTP/1.1 403 Forbidden \r\n" \
                               "\r\n");
    *response = zpl_string_appendc(*response,"Forbidden\r\n");    
}

static void index_path_handler(request_data data,zpl_string *response){
    zpl_allocator allocator = ZPL_STRING_HEADER(*response)->allocator;
    *response = zpl_string_appendc(*response,"HTTP/1.1 200 OK \r\n" \
                               "\r\n");
    zpl_file_contents indexfile = zpl_file_read_contents(allocator,true,"index.html");
    *response = zpl_string_append_length(*response,indexfile.data,indexfile.size);    
    zpl_file_free_contents(&indexfile);
}

static void echo_read(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf) {
    zpl_allocator allocator =  ((connection_t *)client->data)->server->arena_allocator;
    uv_read_stop(client);
    if (nread > 0) {
        request_data data = {};
        int minor_version = 0;
        #define HEADER_NUM 32
        size_t num_headers = HEADER_NUM;
        struct phr_header headers[HEADER_NUM] = {};
        #undef HEADER_NUM
        int reqres = phr_parse_request(buf->base, buf->len, &(data.method), &(data.method_len), &(data.path), &(data.path_len),
                                    &minor_version, headers, (size_t *)&num_headers, 0);
        //int respres = phr_parse_response(buf->base, buf->len, &minor_version,&(data.status),&(data.msg),&(data.msg_len),  headers, (size_t *)&num_headers, 0);

        char* bodydata  = buf->base;
        if( num_headers>0){
            for(int i =0 ; i <= (num_headers + 1) ; i++) {
                bodydata = zpl_strchr(bodydata,'\n');
                bodydata++;
            }
        }
        zpl_string response = zpl_string_make_reserve(allocator,10);

        int handled = false;
        if(!handled) handled =  handle_get_func(index_path_handler,data,"/",&response);
        if(!handled) handled =  handle_get_func(index_path_handler,data,"/index.html",&response);
        if(!handled) handled =  handle_get_func(wildcard_path_handler,data,"/*",&response);
        if(!handled) handled =  handle_post_func(forbidden_handler,data,"/*",&response);
        zpl_free(allocator,buf->base);
        uv_buf_t buffer = {};
        buffer.len = zpl_string_length(response);
        buffer.base = zpl_alloc(allocator,buffer.len + 1);
        zpl_memcopy(buffer.base,response,zpl_string_length(response));
        zpl_string_free(response);
        uv_write_t* writer = &(((connection_t *)client)->writer);
        uv_write(writer,client,&buffer,1,on_write);
    }
    
    if (nread < 0) {
        if (nread != UV_EOF) fprintf(stderr, "Read error %s\n", uv_err_name(nread));
            uv_close((uv_handle_t*) client, on_close);
    }
}

static void on_new_connection(uv_stream_t *server, int status) {
    
    if (status < 0) {
        fprintf(stderr, "[Error]: New connection error %s\n", uv_strerror(status));
        return;
    }
    zpl_allocator connection_pool_allocator = (((server_context_t *)server)->connection_pool_allocator);
    connection_t *connection =  zpl_alloc(connection_pool_allocator,sizeof(connection_t));
    connection->server = (server_context_t *)server;
    uv_tcp_t* client = &(connection->client);
    client->data = (void *)connection;
    uv_tcp_init(uv_default_loop(), client);
    int r = uv_accept(server,(uv_stream_t *)client);
    if (r) {
        fprintf(stderr, "[Error]: Accept error %s\n", uv_strerror(r));
        zpl_free(connection_pool_allocator,connection);
        return ;
    }

    r = uv_read_start((uv_stream_t*) client, alloc_buffer, echo_read);
    if (r) {
        fprintf(stderr, "[Error]: Read error %s\n", uv_strerror(r));
        zpl_free(connection_pool_allocator,connection);
        return ;
    }
   
}

int main(int argc ,char** argv) {

    zpl_allocator general_allocator =  zpl_heap_allocator();
    server_context_t* server_context = zpl_alloc(general_allocator,sizeof(server_context_t));
    zpl_arena arena = {};
    zpl_arena_init_from_allocator(&arena,general_allocator,zpl_megabytes(20));
    zpl_allocator arena_allocator = zpl_arena_allocator(&arena);
    
    zpl_pool_init(&(server_context->connection_pool),general_allocator,128,sizeof(connection_t));

    zpl_allocator pool_allocator = zpl_pool_allocator(&(server_context->connection_pool));

    server_context->connection_pool_allocator = pool_allocator;
    server_context->general_allocator = general_allocator;
    server_context->arena_allocator = arena_allocator;
    
    uv_loop_t *loop = uv_default_loop();

    uv_tcp_t* server = (uv_tcp_t *)server_context;

    uv_tcp_init(loop,server);

    struct sockaddr_in* addr = (struct sockaddr_in *)calloc(sizeof(struct sockaddr_in),1);

    uv_ip4_addr("0.0.0.0", DEFAULT_PORT, (struct sockaddr_in *)addr);

    uv_tcp_bind(server, (const struct sockaddr*)addr, 0);
    int r = uv_listen((uv_stream_t*) server, DEFAULT_BACKLOG, on_new_connection);
    if (r) {
        fprintf(stderr, "Listen error %s\n", uv_strerror(r));
        return 1;
    }
    uv_run(loop, UV_RUN_DEFAULT);
    return 0;
}

