
#include "common.h"

#define DEFAULT_PORT 7000
#define DEFAULT_BACKLOG 128

typedef struct {
    uv_tcp_t client;
    uv_write_t writer;
} connection_t;

typedef struct {
    uv_tcp_t server;
    zpl_allocator pool_allocator;
    zpl_allocator general_allocator;
    zpl_allocator arena_allocator;
}server_context_t;


static void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {

    zpl_allocator allocator =  ((server_context_t *)handle->data)->arena_allocator;
    
    buf->base = (char*) zpl_alloc(allocator,suggested_size);
    buf->len = suggested_size;
}

static void on_close(uv_handle_t* handle) {
//    zpl_allocator allocator =  ((server_context_t *)handle->data)->arena_allocator;
//    zpl_free(allocator,handle);
}

static void on_write(uv_write_t* req, int status){

    uv_close((uv_handle_t*) req->handle, on_close);
    zpl_allocator allocator =  ((server_context_t *)req->data)->arena_allocator;
    zpl_free(allocator,req);

}

static void echo_read(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf) {
    zpl_allocator allocator =  ((server_context_t *)client->data)->arena_allocator;
    uv_read_stop(client);
    if (nread > 0) {
        const char* method;
        size_t method_len;
        const char* path;
        size_t path_len;
        int minor_version;
        struct phr_header headers[1];
        size_t num_headers = 1;

        int res = phr_parse_request(buf->base, buf->len, &method, &method_len, &path, &path_len,
                      &minor_version, headers, &num_headers, 0);

        zpl_string response ;
        if(!(zpl_strncmp(path,"/favicon.ico",path_len) == 0))
        {
            char *tempresponse;
            response = zpl_string_make(allocator,"HTTP/1.1 200 OK \r\n" \
                                        "\r\n");
            response = zpl_string_appendc(response,"<!DOCTYPE html>\r\n" \
                                          "<html>\r\n"\
                                          "<body>\r\n"\
                                          "\r\n"\
                                          "<h1>My First Heading</h1>\r\n" \
                                          "<p>My first paragraph.</p>\r\n" \
                                          "<p>Path: ");
            response = zpl_string_append_length(response,path,path_len);
            response = zpl_string_appendc(response,"<p>\r\n" \
                                          "\r\n"             \
                                          "</body>\r\n"\
                                          "</html>");
        }
        else
        {
            response = zpl_string_make(allocator ,"HTTP/1.1 200 OK \r\n" \
                                        "\r\n" \
                                        "Hello ");
        }
        uv_read_stop(client);
        zpl_free(allocator,buf->base);
        uv_buf_t buffer = {};
        buffer.len = zpl_string_length(response);
        buffer.base = zpl_alloc(allocator,buffer.len + 1);
        zpl_memcopy(buffer.base,response,zpl_string_length(response));
        zpl_string_free(response);
        uv_write_t* writer = &(((connection_t *)client)->writer);
        writer->data = client->data;
        uv_write(writer,(uv_stream_t*) client,&buffer,1,on_write);
    }
    
    if (nread < 0) {
        if (nread != UV_EOF) fprintf(stderr, "Read error %s\n", uv_err_name(nread));
    }
}

static void on_new_connection(uv_stream_t *server, int status) {

    zpl_allocator pool_allocator = (((server_context_t *)server)->pool_allocator);
    connection_t *connection =  zpl_alloc(pool_allocator,sizeof(connection_t));
    
    if (status < 0) {
        fprintf(stderr, "[Error]: New connection error %s\n", uv_strerror(status));
        return;
    }
    

    uv_tcp_t* client = &(connection->client);
    client->data = (void *)server;
    uv_tcp_init(uv_default_loop(), client);
    int r = uv_accept(server,(uv_stream_t *)client);
    if (r) {
        fprintf(stderr, "[Error]: Accept error %s\n", uv_strerror(r));    
        return ;
    }

    r = uv_read_start((uv_stream_t*) client, alloc_buffer, echo_read);
    if (r) {
        fprintf(stderr, "[Error]: Read error %s\n", uv_strerror(r));
        return ;
    }
   
}

int main(int argc ,char** argv) {

    zpl_allocator general_allocator =  zpl_heap_allocator();
    zpl_arena arena = {};
    zpl_arena_init_from_allocator(&arena,general_allocator,zpl_megabytes(20));
    zpl_allocator arena_allocator = zpl_arena_allocator(&arena);
    zpl_pool pool = {};
    
    zpl_pool_init(&pool,zpl_heap(),128,sizeof(connection_t));

    zpl_allocator pool_allocator = zpl_pool_allocator(&pool);

    server_context_t* server_context = zpl_alloc(general_allocator,sizeof(server_context_t));
    server_context->pool_allocator = pool_allocator;
    server_context->general_allocator = general_allocator;
    server_context->arena_allocator = arena_allocator;
    
    uv_loop_t *loop = uv_default_loop();

    uv_tcp_t* server = (uv_tcp_t *)server_context;

    uv_tcp_init(loop,server);

    //uv_tcp_keepalive(server,true,60);
    
    //uv_tcp_simultaneous_accepts(server,true);
    
    struct sockaddr_in* addr = (struct sockaddr_in *)calloc(sizeof(struct sockaddr_in),1);

    uv_ip4_addr("0.0.0.0", DEFAULT_PORT, (struct sockaddr_in *)addr);

    uv_tcp_bind(server, (const struct sockaddr*)addr, 0);
    int r = uv_listen((uv_stream_t*) server, DEFAULT_BACKLOG, on_new_connection);
    if (r) {
        fprintf(stderr, "Listen error %s\n", uv_strerror(r));
        return 1;
    }
    uv_run(loop, UV_RUN_DEFAULT);
    //zpl_pool_free(&pool);
    return 0;
}

