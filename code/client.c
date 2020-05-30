
#include "common.h"

#define DEFAULT_PORT 7000
#define DEFAULT_BACKLOG 128

static void on_write(uv_write_t* req, int status){

    if (status < 0) {
        fprintf(stderr, "write failed error %s\n", uv_err_name(status));
        free(req);
        return;
    }

    uv_close((uv_handle_t*) req->handle, NULL);   
}

static void on_connect(uv_connect_t *req, int status) {
    if (status < 0) {
        fprintf(stderr, "connect failed error %s\n", uv_err_name(status));
        free(req);
        return;
    }
    
    uv_write_t *Writer = (uv_write_t *)malloc(sizeof(uv_write_t));
    uv_write(Writer,req->handle,(uv_buf_t *)req->data,1,on_write);
}


int main(int argc ,char** argv) {

    uv_buf_t *Buffer = (uv_buf_t *) malloc(sizeof(uv_buf_t));
    if(argc == 1)
    {
        char request[] ="HTTP/1.0 200 OK\r\n\r"; 
        Buffer->len = strlen(request);
        Buffer->base = (char *)calloc(Buffer->len,1);
        memcpy(Buffer->base,request,Buffer->len);
    }
    else if(argc == 2)
    {
        Buffer->len = 6;
        Buffer->base = (char *)calloc(6,1);
        Buffer->base[0] = 'H'; 
        Buffer->base[1] = 'e'; 
        Buffer->base[2] = 'l'; 
        Buffer->base[3] = 'l'; 
        Buffer->base[4] = 'o'; 
    }
    else 
    {
        Buffer->len = strlen(argv[1]) + 1;
        Buffer->base = (char *)calloc(Buffer->len,1);
        memcpy(Buffer->base,argv[1],Buffer->len);   
    }

    uv_loop_t *loop = (uv_loop_t *)calloc(sizeof(uv_loop_t),1);
    uv_loop_init(loop);

    uv_tcp_t* socket = (uv_tcp_t*)calloc(sizeof(uv_tcp_t),1);
    uv_tcp_init(loop, socket);
    uv_tcp_keepalive(socket, 1, 60);

    uv_connect_t* connect = (uv_connect_t*)calloc(sizeof(uv_connect_t),1);

    struct sockaddr_in dest;
    uv_ip4_addr("0.0.0.0", 7000, &dest);
    connect->data = Buffer;
    int r = uv_tcp_connect(connect, socket, (const struct sockaddr*)&dest, on_connect);
    
    return uv_run(loop, UV_RUN_DEFAULT);
}

