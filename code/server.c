#include "common.h"

#define DEFAULT_PORT 7000
#define DEFAULT_BACKLOG 128


typedef struct {
    PGconn* dbConnection;
    PGresult* lastResult;
}DatabaseContext;

typedef struct {
    uv_tcp_t server;
    zpl_pool connectionPool;
    zpl_allocator connectionPoolAllocator;
    zpl_allocator generalAllocator;
    zpl_allocator arenaAllocator;
    DatabaseContext database;
}ServerContext;

typedef struct {
    uv_tcp_t client;
    uv_write_t writer;
    ServerContext* server;
}Connection;

typedef struct {
    const char* method;
    int status;
    size_t methodLength;
    const char* path;
    size_t pathLength;
    const char* message;
    size_t messageLength;
    struct phr_header* headers;
    int numHeaders;
    int headersCap;
    const char* body;
}RequestData;


static DatabaseContext ConnectToDatabase(){
    DatabaseContext result = {};
    PGconn* dbConnection = PQsetdbLogin("localhost","5432",NULL,NULL,"postgres","postgres","Shazanman123");
    result.dbConnection = dbConnection; 
    return result;
}

static void DisconnectDatabase(DatabaseContext *ctx){
    PQfinish(ctx->dbConnection);
}

static void* DatabaseReadValue(DatabaseContext *ctx,zpl_allocator allocator,int row ,int column){
    PGresult* result = ctx->lastResult;
    bool isBinaryFormat = (PQfformat(result,column) == 1);
    int outputSize = PQgetlength(result,row,column);
    void* output = 0;
        if(isBinaryFormat){
            output= zpl_alloc(allocator,(outputSize != 2 &&outputSize != 4 && outputSize != 8 ) ?outputSize + 1 :outputSize);
            zpl_memcopy(output,PQgetvalue(result,row,column),outputSize);
            if(outputSize == 2){
                *(zpl_u16 *)output = zpl_endian_swap16(*(zpl_u16 *)output);
            }
            else if(outputSize == 4){
                *(zpl_u32 *)output = zpl_endian_swap32(*(zpl_u32 *)output);
            }
            else if(outputSize == 8){
                *(zpl_u64 *)output = zpl_endian_swap64(*(zpl_u64 *)output);       
            }
        }
        else{
            output= zpl_alloc(allocator,outputSize + 1);
            zpl_memcopy(output,PQgetvalue(result,row,column),outputSize);
            ((char *)output)[outputSize] = 0;
        }
    return output;
}

static void DatabaseExecute(DatabaseContext *ctx ,const char* sql){
    ctx->lastResult = PQexecParams(ctx->dbConnection,sql,0,NULL,NULL,NULL,NULL,1);
    ExecStatusType Status = PQresultStatus(ctx->lastResult);
}

static void DatabaseExecuteParams(DatabaseContext *ctx ,const char* sql,int paramNum,const char* values[],int lengths[],int isBinary[])
{
    ctx->lastResult = PQexecParams(ctx->dbConnection,sql,paramNum,NULL,values,lengths,isBinary,1);
    ExecStatusType Status = PQresultStatus(ctx->lastResult);
}

static void RetrieveFromDatabase(DatabaseContext *ctx){
    DatabaseExecute(ctx,"Select id,cast(money*10000 AS int)  FROM test;");
    int tuples = PQntuples(ctx->lastResult);
    for(int i = 0;i < tuples;i++){
        char *id = (char *)DatabaseReadValue(ctx,zpl_heap(),i,0);
        int t = *(int *)DatabaseReadValue(ctx,zpl_heap(),i,1);
    }
}

static void DispatchToDatabase(DatabaseContext *ctx){
    int money = 298904435;
    money = zpl_endian_swap32(money);
    const char* data[] = { "5",(char *)&money };
    int binary[2] = {1,1};
    int sizes[2] = {strlen(data[0]) ,sizeof(int)};
    DatabaseExecuteParams(ctx,"INSERT INTO public.test (id, money) VALUES($1::varchar, ($2::int)/10000.0 ) ON CONFLICT (id) DO UPDATE SET money = excluded.money;",2,data,sizes,binary);
}


static void TestDatabase(){
    DatabaseContext Context = ConnectToDatabase();
    RetrieveFromDatabase(&Context);
    DispatchToDatabase(&Context);
    DisconnectDatabase(&Context);
}

static void AllocBuffer(uv_handle_t *handle, size_t suggestedSize, uv_buf_t *buf) {
    zpl_allocator allocator =  ((Connection *)handle->data)->server->arenaAllocator;
    buf->base = (char*) zpl_alloc(allocator,suggestedSize);
    buf->len = suggestedSize;
}

static void OnClose(uv_handle_t* handle) {
    zpl_allocator allocator =  ((Connection *)handle->data)->server->connectionPoolAllocator;
    zpl_free(allocator,((Connection *)handle->data));
}

static void OnWrite(uv_write_t* req, int status){
    uv_close((uv_handle_t*) req->handle, OnClose);
}


typedef void (*HttpHandler)(RequestData data,zpl_string* response);

static int HandleGetFunc(HttpHandler handler,RequestData data,const char* requestedPath,zpl_string* response){
    int result = false;
    if(zpl_strncmp(data.method,"GET",3)==0){
        if(zpl_strncmp(data.path,requestedPath,data.pathLength)==0
           || (zpl_strncmp(requestedPath,"/*",2)==0)) {
            handler(data,response);
            result = true;
        }
    }
    return result;
}

static int HandlePostFunc(HttpHandler handler,RequestData data,const char* requestedPath,zpl_string* response){
    int result = false;
    if(zpl_strncmp(data.method,"POST",4)==0){
        if(zpl_strncmp(data.path,requestedPath,data.pathLength)==0
           || (zpl_strncmp(requestedPath,"/*",2)==0)) {
            handler(data,response);
            result = true;
        }
    }
    return result;
}


static void TestWildcardHandler(RequestData data,zpl_string *response){
    *response = zpl_string_appendc(*response,"HTTP/1.1 200 OK \r\n" \
                               "\r\n");
    *response = zpl_string_appendc(*response,"<!DOCTYPE html>\r\n" \
                                  "<html>\r\n"\
                                  "<body>\r\n"\
                                  "\r\n"\
                                  "<h1>Heading</h1>\r\n" \
                                  "<p>Paragraph.</p>\r\n" \
                                  "<p>Path: ");
    *response = zpl_string_append_length(*response,data.path,data.pathLength);
    *response = zpl_string_appendc(*response,"<p>\r\n" \
                                  "</body>\r\n"\
                                  "</html>\r\n");
}

static void ForbiddenHandler(RequestData data,zpl_string *response){
    zpl_allocator allocator = ZPL_STRING_HEADER(*response)->allocator;
    *response = zpl_string_appendc(*response,"HTTP/1.1 403 Forbidden \r\n" \
                               "\r\n");
    *response = zpl_string_appendc(*response,"Forbidden\r\n");    
}

static void IndexHandler(RequestData data,zpl_string *response){
    zpl_allocator allocator = ZPL_STRING_HEADER(*response)->allocator;
    *response = zpl_string_appendc(*response,"HTTP/1.1 200 OK \r\n" \
                               "\r\n");
    zpl_file_contents indexfile = zpl_file_read_contents(allocator,true,"index.html");
    *response = zpl_string_append_length(*response,indexfile.data,indexfile.size);    
    zpl_file_free_contents(&indexfile);
}

static void LoginHandler(RequestData data,zpl_string *response){
    zpl_allocator allocator = ZPL_STRING_HEADER(*response)->allocator;
    *response = zpl_string_appendc(*response,"HTTP/1.1 200 OK \r\n" \
                               "\r\n");
    zpl_file_contents indexfile = zpl_file_read_contents(allocator,true,"login.html");
    *response = zpl_string_append_length(*response,indexfile.data,indexfile.size);    
    zpl_file_free_contents(&indexfile);
}

static void AdminHandler(RequestData data,zpl_string *response){
    zpl_allocator allocator = ZPL_STRING_HEADER(*response)->allocator;
    *response = zpl_string_appendc(*response,"HTTP/1.1 200 OK \r\n" \
                               "\r\n");
    zpl_file_contents indexfile = zpl_file_read_contents(allocator,true,"admin.html");
    *response = zpl_string_append_length(*response,indexfile.data,indexfile.size);    
    zpl_file_free_contents(&indexfile);
}

static void SignupHandler(RequestData data,zpl_string *response){
    zpl_allocator allocator = ZPL_STRING_HEADER(*response)->allocator;
    char* sessionid = "hfdhdf";
    *response = zpl_string_appendc(*response,"HTTP/1.1 200 OK \r\n" );
    *response = zpl_string_appendc(*response,"Set-Cookie: id=\"");
    *response = zpl_string_appendc(*response,sessionid);
    *response = zpl_string_appendc(*response,"\"; max-age=18000; path=/; Secure; HttpOnly");
    *response = zpl_string_appendc(*response,"\r\n");
    *response = zpl_string_appendc(*response,"\r\n");    
}

static uv_buf_t GenerateResponse(zpl_allocator allocator,RequestData data){

        zpl_string response = zpl_string_make_reserve(allocator,10);
        bool handled = false;
        bool clientauthenticated = false;
        if(clientauthenticated)
        {
            
        }

        if(!handled) handled = HandlePostFunc(SignupHandler,data,"/login",&response);
        if(!handled) handled = HandleGetFunc(IndexHandler,data,"/",&response);
        if(!handled) handled = HandleGetFunc(LoginHandler,data,"/login",&response);
        if(!handled) handled = HandleGetFunc(AdminHandler,data,"/admin",&response);
        if(!handled) handled = HandleGetFunc(ForbiddenHandler,data,"/*",&response);

        uv_buf_t buffer = {};
        buffer.len = zpl_string_length(response);
        buffer.base = zpl_alloc(allocator,buffer.len + 1);
        zpl_memcopy(buffer.base,response,zpl_string_length(response));
        zpl_string_free(response);
        return buffer;
}

static void EchoRead(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf) {
    zpl_allocator allocator =  ((Connection *)client->data)->server->arenaAllocator;
    uv_read_stop(client);
    if (nread > 0) {
        RequestData data = {};
        data.headersCap = 256;
        data.headers = zpl_alloc(allocator,sizeof(struct phr_header) *data.headersCap);
        data.numHeaders = data.headersCap;
        int minorVersion = 0;
        int bodyaddress = phr_parse_request(buf->base, buf->len, &(data.method), &(data.methodLength), &(data.path), &(data.pathLength),
                                       &minorVersion,(data.headers), (size_t *)&(data.numHeaders), 0);
        data.body  = buf->base + bodyaddress;
        uv_buf_t buffer =  GenerateResponse(allocator,data);
        int respres = phr_parse_response(buffer.base, strlen(buffer.base), &minorVersion,&(data.status),&(data.message),&(data.messageLength),  data.headers, (size_t *)&(data.numHeaders), 0);
        zpl_free(allocator,data.headers);
        zpl_free(allocator,buf->base);
        uv_write_t* writer = &(((Connection *)client)->writer);
        uv_write(writer,client,&buffer,1,OnWrite);
    }
    if (nread < 0) {
        if (nread != UV_EOF) fprintf(stderr, "Read error %s\n", uv_err_name(nread));
            uv_close((uv_handle_t*) client, OnClose);
    }
}

static void OnNewConnection(uv_stream_t *server, int status) {
    if (status < 0) {
        fprintf(stderr, "[Error]: New connection error %s\n", uv_strerror(status));
        return;
    }
    zpl_allocator connectionPoolAllocator = (((ServerContext *)server)->connectionPoolAllocator);
    Connection *connection =  zpl_alloc(connectionPoolAllocator,sizeof(Connection));
    connection->server = (ServerContext *)server;
    uv_tcp_t* client = &(connection->client);
    client->data = (void *)connection;
    uv_tcp_init(uv_default_loop(), client);
    int r = uv_accept(server,(uv_stream_t *)client);
    if (r) {
        fprintf(stderr, "[Error]: Accept error %s\n", uv_strerror(r));
        zpl_free(connectionPoolAllocator,connection);
        return ;
    }
    r = uv_read_start((uv_stream_t*) client, AllocBuffer, EchoRead);
    if (r) {
        fprintf(stderr, "[Error]: Read error %s\n", uv_strerror(r));
        zpl_free(connectionPoolAllocator,connection);
        return ;
    }   
}

int main(int argc ,char** argv) {
    TestDatabase();
    zpl_allocator generalAllocator =  zpl_heap_allocator();
    ServerContext* serverContext = zpl_alloc(generalAllocator,sizeof(ServerContext));
    zpl_arena arena = {};
    zpl_arena_init_from_allocator(&arena,generalAllocator,zpl_megabytes(20));
    zpl_allocator arenaAllocator = zpl_arena_allocator(&arena);
    zpl_pool_init(&(serverContext->connectionPool),generalAllocator,128,sizeof(Connection));
    zpl_allocator poolAllocator = zpl_pool_allocator(&(serverContext->connectionPool));
    serverContext->connectionPoolAllocator = poolAllocator;
    serverContext->generalAllocator = generalAllocator;
    serverContext->arenaAllocator = arenaAllocator;
    uv_loop_t *loop = uv_default_loop();
    uv_tcp_t* server = (uv_tcp_t *)serverContext;
    uv_tcp_init(loop,server);
    struct sockaddr_in* addr = (struct sockaddr_in *)calloc(sizeof(struct sockaddr_in),1);
    uv_ip4_addr("0.0.0.0", DEFAULT_PORT, (struct sockaddr_in *)addr);
    uv_tcp_bind(server, (const struct sockaddr*)addr, 0);
    int r = uv_listen((uv_stream_t*) server, DEFAULT_BACKLOG, OnNewConnection);
    if (r) {
        fprintf(stderr, "Listen error %s\n", uv_strerror(r));
        return 1;
    }
    uv_run(loop, UV_RUN_DEFAULT);
    return 0;
}

