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
    zpl_array(zpl_string) sessions;
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
    size_t bodyLength;
    zpl_string sessionid;
    bool generatesession;
    bool sessiongenerated;
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


static int HandlePutFunc(HttpHandler handler,RequestData data,const char* requestedPath,zpl_string* response){
    int result = false;
    if(zpl_strncmp(data.method,"PUT",3)==0){
        if(zpl_strncmp(data.path,requestedPath,data.pathLength)==0
           || (zpl_strncmp(requestedPath,"/*",2)==0)) {
            handler(data,response);
            result = true;
        }
    }
    return result;
}

static zpl_string HashPassword(zpl_string password){
    zpl_allocator allocator = ZPL_STRING_HEADER(password)->allocator;
    char out[crypto_pwhash_STRBYTES] = {};
    crypto_pwhash_str(out,password,zpl_string_length(password),crypto_pwhash_OPSLIMIT_INTERACTIVE ,crypto_pwhash_MEMLIMIT_INTERACTIVE);
    return zpl_string_make(allocator,out);
}

static bool CheckPassword(zpl_string hasedPassword,zpl_string passwordToVerify){
 int result =  crypto_pwhash_str_verify(hasedPassword,passwordToVerify,zpl_string_length(passwordToVerify));
 return (result == 0 ) ? true : false;
}

static void SignupHandler(RequestData data,zpl_string *response){
    zpl_allocator allocator = ZPL_STRING_HEADER(*response)->allocator;
    zpl_json_object object = {};
    zpl_u8 errcode;
    zpl_json_parse(&object,data.bodyLength ,data.body ,allocator,true,&errcode);
    char* name = zpl_json_find(&object,"name",false)->string;
    char* password = zpl_json_find(&object,"password",false)->string;
    char* email = zpl_json_find(&object,"email",false)->string;
    zpl_string hashedPassword = HashPassword(zpl_string_make(allocator,password));
    *response = zpl_string_appendc(*response,"HTTP/1.1 200 \r\n" );
    if(data.generatesession){
        zpl_u64 *sessiondata = zpl_alloc(allocator,16);
        randombytes_buf((void *)sessiondata,16);
        *response = zpl_string_appendc(*response,"Set-Cookie: sid=");
        data.sessionid = zpl_string_make(allocator,zpl_base64_encode(allocator,sessiondata,16));
        *response = zpl_string_append(*response,data.sessionid);
        *response = zpl_string_appendc(*response,"; max-age=18000; path=/; Secure;SameSite=Strict; HttpOnly\r\n");
        zpl_free(allocator,sessiondata);
        data.generatesession = false;
        data.sessiongenerated = true;
    }
    *response = zpl_string_appendc(*response,"\r\n");
    zpl_json_object jsonOutput ={};
    zpl_json_init_node(&jsonOutput,allocator,"redirect",ZPL_JSON_TYPE_STRING);
    jsonOutput.string = "true";
    zpl_json_add(&jsonOutput,"redirecturl",ZPL_JSON_TYPE_STRING)->string = "/login.html";
    zpl_file temp ={};
    zpl_file_temp(&temp);
    zpl_json_write(&temp,&jsonOutput,0);
    zpl_json_free(&jsonOutput);
    zpl_file_seek(&temp,0);
    zpl_file_seek_to_end(&temp);
    int filesize = zpl_file_tell(&temp);
    char * jsonStr = zpl_alloc(allocator,filesize);
    zpl_file_read(&temp,jsonStr,filesize);
    zpl_file_close(&temp);
    *response = zpl_string_appendc(*response,jsonStr);    
    *response = zpl_string_appendc(*response,"\r\n");    
    zpl_free(allocator,jsonStr);
}


static void LoginHandler(RequestData data,zpl_string *response){
    zpl_allocator allocator = ZPL_STRING_HEADER(*response)->allocator;
    zpl_json_object object = {};
    zpl_u8 errcode;
    zpl_json_parse(&object,data.bodyLength ,data.body ,allocator,true,&errcode);
    char* name = zpl_json_find(&object,"name",false)->string;
    zpl_string password = zpl_string_make(allocator,zpl_json_find(&object,"password",false)->string);
    zpl_string hashedPassword = HashPassword(password);
    bool IsVerfied = CheckPassword(hashedPassword,password);
    *response = zpl_string_appendc(*response,"HTTP/1.1 200 \r\n" );
    if(!(data.sessionid))
    {
        zpl_u64 *sessiondata = zpl_alloc(allocator,16);
        randombytes_buf((void *)sessiondata,16);
        *response = zpl_string_appendc(*response,"Set-Cookie: sid=");
        data.sessionid = zpl_string_make(allocator,zpl_base64_encode(allocator,sessiondata,16));
        *response = zpl_string_append(*response,data.sessionid);
        *response = zpl_string_appendc(*response,"; max-age=18000; path=/; Secure; HttpOnly\r\n");
        zpl_free(allocator,sessiondata);
        data.generatesession = false;
        data.sessiongenerated = true;
    }
    *response = zpl_string_appendc(*response,"\r\n");
    *response = zpl_string_appendc(*response,"\r\n");    
}

static uv_buf_t GenerateResponse(zpl_array(zpl_string) sessions ,zpl_allocator allocator,RequestData data){

        zpl_string response = zpl_string_make_reserve(allocator,10);
        bool handled = false;
        //Check SessionId
        for(int i = 0 ; i < data.numHeaders;i++){
            struct phr_header header =  data.headers[i];
            if(zpl_strncmp(header.name,"Cookie",6)==0){
                char *path = (char *)header.value;
                int p = 0 ;
                while(p < header.value_len){
                    if(zpl_strncmp(path,"sid=",4)){
                        int sessionidlen = (int)(zpl_strchr(path,';') - path) - 3 ;
                        sessionidlen = sessionidlen < header.value_len ? sessionidlen : header.value_len - (3 + 1);  
                        data.sessionid = zpl_string_make_length(allocator,path + 3,sessionidlen); 
                    }
                    path++;
                    p++;
                }
            }
        }
        data.generatesession = true;
        if(data.sessionid){
            for(int i =0 ; i < zpl_array_count(sessions);i++){
                if(zpl_string_are_equal(data.sessionid ,sessions[i])) data.generatesession = false;
            }
        }
        
        if(!handled) handled = HandlePostFunc(SignupHandler,data,"/signup",&response);
        if(!handled) handled = HandlePostFunc(LoginHandler,data,"/login",&response);
            
        if(data.sessiongenerated){
            zpl_array_append(sessions,data.sessionid);
            data.sessiongenerated = false;
        }
        uv_buf_t buffer = {};
        buffer.len = zpl_string_length(response);
        buffer.base = zpl_alloc(allocator,buffer.len + 1);
        zpl_memcopy(buffer.base,response,zpl_string_length(response));
        zpl_string_free(response);
        return buffer;
}

static void EchoRead(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf) {
    zpl_allocator allocator =  ((Connection *)client->data)->server->arenaAllocator;
    zpl_array(zpl_string) sessions = ((Connection *)client->data)->server->sessions;
    uv_read_stop(client);
    if (nread > 0) {
        RequestData data = {};
        data.headersCap = 256;
        data.headers = zpl_alloc(allocator,sizeof(struct phr_header) *data.headersCap);
        data.numHeaders = data.headersCap;
        int minorVersion = 0;
        int bodyoffset = phr_parse_request(buf->base, buf->len, &(data.method), &(data.methodLength), &(data.path), &(data.pathLength),
                                           &minorVersion,(data.headers), (size_t *)&(data.numHeaders), 0);
        for(int i = 0 ; i < data.numHeaders;i++){
            struct phr_header header =  data.headers[i];
            if(zpl_strncmp(header.name,"Content-Length",14)==0){
                char *path = zpl_strdup(allocator,header.value,header.value_len);
                data.bodyLength = zpl_str_to_u64(path,path + header.value_len ,10);
                zpl_free(allocator,path);
            }
            if(data.bodyLength) break;
            
        }
        data.body  = buf->base + bodyoffset;
        uv_buf_t buffer =  GenerateResponse(sessions,allocator,data);
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
    sodium_init();
    zpl_allocator generalAllocator =  zpl_heap_allocator();
    ServerContext* serverContext = zpl_alloc(generalAllocator,sizeof(ServerContext));
    zpl_arena arena = {};
    zpl_arena_init_from_allocator(&arena,generalAllocator,zpl_megabytes(20));
    zpl_allocator arenaAllocator = zpl_arena_allocator(&arena);
    zpl_pool_init(&(serverContext->connectionPool),generalAllocator,128,sizeof(Connection));
    zpl_array_init(serverContext->sessions,generalAllocator);
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
    randombytes_close();
    uv_run(loop, UV_RUN_DEFAULT);
    return 0;
}

