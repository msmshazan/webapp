#include "secrets.h"
#include "common.h"

#define DEFAULT_PORT 7000
#define DEFAULT_BACKLOG 128

typedef struct {
    PGconn* dbConnection;
    PGresult* lastResult;
}DatabaseContext;

typedef struct {
    zpl_string id;
    zpl_string name;
}
SessionID;

typedef struct {
    uv_tcp_t server;
    zpl_pool connectionPool;
    zpl_allocator connectionPoolAllocator;
    zpl_allocator generalAllocator;
    zpl_allocator arenaAllocator;
    DatabaseContext database;
    zpl_array(SessionID) sessions;
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
    SessionID sessionID;
    bool generateSession;
    bool sessionGenerated;
    DatabaseContext database;
}RequestData;


static DatabaseContext ConnectToDatabase(){
    DatabaseContext result = {};
    PGconn* dbConnection = PQsetdbLogin(DBHOST,DBPORT,NULL,NULL,DBNAME,DBUSER,DBPASSWORD);
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
    if(ctx->lastResult) PQclear(ctx->lastResult);
    ctx->lastResult = PQexecParams(ctx->dbConnection,sql,0,NULL,NULL,NULL,NULL,1);
    ExecStatusType Status = PQresultStatus(ctx->lastResult);
}

static void DatabaseExecuteParams(DatabaseContext *ctx ,const char* sql,int paramNum,const char* values[],int lengths[],int isBinary[]){
    if(ctx->lastResult) PQclear(ctx->lastResult);
    ctx->lastResult = PQexecParams(ctx->dbConnection,sql,paramNum,NULL,values,lengths,isBinary,1);
    ExecStatusType Status = PQresultStatus(ctx->lastResult);
}

static void RegisterUserOnDatabase(DatabaseContext *ctx,zpl_string name,zpl_string email,zpl_string hashedPassword){
    const char* data[] = {name,email,hashedPassword};
    int binary[3] = {1};
    int sizes[3] = {zpl_string_length(name) ,zpl_string_length(email),zpl_string_length(hashedPassword)};
    DatabaseExecuteParams(ctx,"INSERT INTO users (name,email,passwordhash) VALUES($1::varchar, $2::varchar,$3::varchar ) ;",3,data,sizes,binary);
}

static zpl_string RetriveHashedPassword(DatabaseContext *ctx,zpl_string name){
    zpl_allocator allocator = ZPL_STRING_HEADER(name)->allocator;
    const char* data[] = {name};
    int binary[1] = {1};
    int sizes[1] = {zpl_string_length(name)};
    DatabaseExecuteParams(ctx,"SELECT (passwordhash) FROM users WHERE name=($1:varchar);",1,data,sizes,binary);
    void *passFromDb = DatabaseReadValue(ctx,allocator,0,0);
    zpl_string hashedPassword = zpl_string_make(allocator,(char*)passFromDb);
    zpl_free(allocator,data);
    return hashedPassword;
}

static bool UserExists(DatabaseContext* ctx,zpl_string name){
    const char* data[] = {name};
    int binary[1] = {1};
    int sizes[1] = {zpl_string_length(name)};
    DatabaseExecuteParams(ctx,"SELECT 1 FROM users WHERE name=($1::varchar) ;",1,data,sizes,binary);
    bool result = PQntuples(ctx->lastResult)  > 0 ? true : false;
    return result;
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


typedef void (*HttpHandler)(RequestData* data,zpl_string* response);

static int HandleGetFunc(HttpHandler handler,RequestData* data,const char* requestedPath,zpl_string* response){
    bool result = false;
    if(zpl_strncmp(data->method,"GET",3)==0){
        if(zpl_strncmp(data->path,requestedPath,data->pathLength)==0
           || (zpl_strncmp(requestedPath,"/*",2)==0)) {
            handler(data,response);
            result = true;
        }
    }
    return result;
}

static int HandlePutFunc(HttpHandler handler,RequestData* data,const char* requestedPath,zpl_string* response){
    bool result = false;
    if(zpl_strncmp(data->method,"PUT",3)==0){
        if(zpl_strncmp(data->path,requestedPath,data->pathLength)==0
           || (zpl_strncmp(requestedPath,"/*",2)==0)) {
            handler(data,response);
            result = true;
        }
    }
    return result;
}


static int HandleDeleteFunc(HttpHandler handler,RequestData* data,const char* requestedPath,zpl_string* response){
    bool result = false;
    if(zpl_strncmp(data->method,"DELETE",6)==0){
        if(zpl_strncmp(data->path,requestedPath,data->pathLength)==0
           || (zpl_strncmp(requestedPath,"/*",2)==0)) {
            handler(data,response);
            result = true;
        }
    }
    return result;
}


static int HandlePostFunc(HttpHandler handler,RequestData* data,const char* requestedPath,zpl_string* response){
    bool result = false;
    if(zpl_strncmp(data->method,"POST",4)==0){
        if(zpl_strncmp(data->path,requestedPath,data->pathLength)==0) {
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

static void GenerateSessionID(zpl_string username ,zpl_allocator allocator,RequestData* data){
        char key[crypto_auth_KEYBYTES] = {};
        crypto_auth_keygen((uint8_t *)key);
        data->sessionID.name = zpl_string_duplicate(ZPL_STRING_HEADER(username)->allocator,username);
        data->sessionID.id = zpl_string_make(ZPL_STRING_HEADER(username)->allocator,key);
        data->generateSession = false;
        data->sessionGenerated = true;
}

static void InsertPostToDatabase(DatabaseContext *ctx,zpl_string title,zpl_string author,zpl_string summary,zpl_string content){
    const char* data[] = {title,author,summary,content};
    int binary[4] = {1};
    int sizes[4] = {zpl_string_length(title) ,zpl_string_length(author),zpl_string_length(summary),zpl_string_length(content)};
    DatabaseExecuteParams(ctx,"INSERT INTO posts (title,author,summary,content,date) VALUES($1::varchar, $2::varchar,$3::varchar,$4::varchar,current_timestamp ) ;",4,data,sizes,binary);
}

static void UpdatePostInDatabase(DatabaseContext *ctx,zpl_string title,zpl_string author,zpl_string summary,zpl_string content){
    const char* data[] = {title,author,summary,content};
    int binary[4] = {1};
    int sizes[4] = {zpl_string_length(title) ,zpl_string_length(author),zpl_string_length(summary),zpl_string_length(content)};
    DatabaseExecuteParams(ctx,"UPDATE posts SET author=$2::varchar,summary=$3::varchar,content=$4::varchar,date=current_timestamp WHERE title=$1::varchar;",4,data,sizes,binary);
}

static void DeletePostInDatabase(DatabaseContext *ctx,zpl_string title){
    const char* data[] = {title};
    int binary[1] = {1};
    int sizes[1] = {zpl_string_length(title)};
    DatabaseExecuteParams(ctx,"DELETE FROM posts WHERE title=$1::varchar;",1,data,sizes,binary);
}

typedef struct Post
{

    
}Post;

static Post RetrivePostFromDatabase(DatabaseContext *ctx,zpl_string title){
    const char* data[] = {title};
    int binary[1] = {1};
    int sizes[1] = {zpl_string_length(title)};
    DatabaseExecuteParams(ctx,"SELECT (title,author,summary,content,date) FROM posts WHERE title=$1::varchar;",1,data,sizes,binary);
    
}

static void RenderPostHandler(RequestData* data,zpl_string *response){
    zpl_allocator allocator = ZPL_STRING_HEADER(*response)->allocator;
    zpl_json_object object = {};
    zpl_u8 errcode;
    zpl_string jsonBody = zpl_string_make_length(allocator,data->body,data->bodyLength);
    zpl_json_parse(&object,zpl_string_length(jsonBody) ,jsonBody ,allocator,true,&errcode);
    zpl_string postTitle = zpl_string_make(allocator,zpl_json_find(&object,"title",false)->string);
    RetrivePostFromDatabase(&(data->database),postTitle);
    *response = zpl_string_appendc(*response,"HTTP/1.1 200 \r\n" );
    char* status = NULL;
    *response = zpl_string_appendc(*response,"\r\n");
    zpl_json_object jsonOutput ={};
    zpl_json_init_node(&jsonOutput,allocator,"<root>",ZPL_JSON_TYPE_OBJECT);
    zpl_json_add(&jsonOutput,"status",ZPL_JSON_TYPE_STRING)->string = status;
    zpl_json_add(&jsonOutput,"redirectlink",ZPL_JSON_TYPE_STRING)->string = "/login.html";
    zpl_json_add(&jsonOutput,"redirect",ZPL_JSON_TYPE_STRING)->string = "true";
    zpl_string jsonStr = zpl_json_write_string(allocator,&jsonOutput,0);
    *response = zpl_string_appendc(*response,jsonStr);
    *response = zpl_string_appendc(*response,"\r\n");
    zpl_string_free(jsonBody);
    zpl_json_free(&object);
    zpl_json_free(&jsonOutput);
}


static void AddPostHandler(RequestData* data,zpl_string *response){
    zpl_allocator allocator = ZPL_STRING_HEADER(*response)->allocator;
    zpl_json_object object = {};
    zpl_u8 errcode;
    zpl_string jsonBody = zpl_string_make_length(allocator,data->body,data->bodyLength);
    zpl_json_parse(&object,zpl_string_length(jsonBody) ,jsonBody ,allocator,true,&errcode);
    zpl_string postTitle = zpl_string_make(allocator,zpl_json_find(&object,"title",false)->string);
    zpl_string postContent = zpl_string_make(allocator,zpl_json_find(&object,"content",false)->string);
    zpl_string postSummary = zpl_string_make(allocator,zpl_json_find(&object,"summary",false)->string);
    zpl_string postAuthor = data->sessionID.name;
    InsertPostToDatabase(&(data->database),postTitle,postAuthor,postSummary,postContent);
    *response = zpl_string_appendc(*response,"HTTP/1.1 200 \r\n" );
    char* status = NULL;
    *response = zpl_string_appendc(*response,"\r\n");
    zpl_json_object jsonOutput ={};
    zpl_json_init_node(&jsonOutput,allocator,"<root>",ZPL_JSON_TYPE_OBJECT);
    zpl_json_add(&jsonOutput,"status",ZPL_JSON_TYPE_STRING)->string = status;
    zpl_json_add(&jsonOutput,"redirectlink",ZPL_JSON_TYPE_STRING)->string = "/login.html";
    zpl_json_add(&jsonOutput,"redirect",ZPL_JSON_TYPE_STRING)->string = "true";
    zpl_string jsonStr = zpl_json_write_string(allocator,&jsonOutput,0);
    *response = zpl_string_appendc(*response,jsonStr);
    *response = zpl_string_appendc(*response,"\r\n");
    zpl_string_free(jsonBody);
    zpl_json_free(&object);
    zpl_json_free(&jsonOutput);
}


static void DeletePostHandler(RequestData* data,zpl_string *response){
    zpl_allocator allocator = ZPL_STRING_HEADER(*response)->allocator;
    zpl_json_object object = {};
    zpl_u8 errcode;
    zpl_string jsonBody = zpl_string_make_length(allocator,data->body,data->bodyLength);
    zpl_json_parse(&object,zpl_string_length(jsonBody) ,jsonBody ,allocator,true,&errcode);
    zpl_string postTitle = zpl_string_make(allocator,zpl_json_find(&object,"title",false)->string);
    DeletePostInDatabase(&(data->database),postTitle);
    *response = zpl_string_appendc(*response,"HTTP/1.1 200 \r\n" );
    char* status = NULL;
    *response = zpl_string_appendc(*response,"\r\n");
    zpl_json_object jsonOutput ={};
    zpl_json_init_node(&jsonOutput,allocator,"<root>",ZPL_JSON_TYPE_OBJECT);
    zpl_json_add(&jsonOutput,"status",ZPL_JSON_TYPE_STRING)->string = status;
    zpl_json_add(&jsonOutput,"redirectlink",ZPL_JSON_TYPE_STRING)->string = "/login.html";
    zpl_json_add(&jsonOutput,"redirect",ZPL_JSON_TYPE_STRING)->string = "true";
    zpl_string jsonStr = zpl_json_write_string(allocator,&jsonOutput,0);
    *response = zpl_string_appendc(*response,jsonStr);
    *response = zpl_string_appendc(*response,"\r\n");
    zpl_string_free(jsonBody);
    zpl_json_free(&object);
    zpl_json_free(&jsonOutput);
}

static void UpdatePostHandler(RequestData* data,zpl_string *response){
    zpl_allocator allocator = ZPL_STRING_HEADER(*response)->allocator;
    zpl_json_object object = {};
    zpl_u8 errcode;
    zpl_string jsonBody = zpl_string_make_length(allocator,data->body,data->bodyLength);
    zpl_json_parse(&object,zpl_string_length(jsonBody) ,jsonBody ,allocator,true,&errcode);
    zpl_string postTitle = zpl_string_make(allocator,zpl_json_find(&object,"title",false)->string);
    zpl_string postContent = zpl_string_make(allocator,zpl_json_find(&object,"content",false)->string);
    zpl_string postSummary = zpl_string_make(allocator,zpl_json_find(&object,"summary",false)->string);
    zpl_string postAuthor = data->sessionID.name;
    UpdatePostInDatabase(&(data->database),postTitle,postAuthor,postSummary,postContent);
    *response = zpl_string_appendc(*response,"HTTP/1.1 200 \r\n" );
    char* status = NULL;
    *response = zpl_string_appendc(*response,"\r\n");
    zpl_json_object jsonOutput ={};
    zpl_json_init_node(&jsonOutput,allocator,"<root>",ZPL_JSON_TYPE_OBJECT);
    zpl_json_add(&jsonOutput,"status",ZPL_JSON_TYPE_STRING)->string = status;
    zpl_json_add(&jsonOutput,"redirectlink",ZPL_JSON_TYPE_STRING)->string = "/login.html";
    zpl_json_add(&jsonOutput,"redirect",ZPL_JSON_TYPE_STRING)->string = "true";
    zpl_string jsonStr = zpl_json_write_string(allocator,&jsonOutput,0);
    *response = zpl_string_appendc(*response,jsonStr);
    *response = zpl_string_appendc(*response,"\r\n");
    zpl_string_free(jsonBody);
    zpl_json_free(&object);
    zpl_json_free(&jsonOutput);
}

static void SignupHandler(RequestData* data,zpl_string *response){
    zpl_allocator allocator = ZPL_STRING_HEADER(*response)->allocator;
    zpl_json_object object = {};
    zpl_u8 errcode;
    zpl_string jsonBody = zpl_string_make_length(allocator,data->body,data->bodyLength);
    zpl_json_parse(&object,zpl_string_length(jsonBody) ,jsonBody ,allocator,true,&errcode);
    zpl_string name = zpl_string_make(allocator,zpl_json_find(&object,"name",false)->string);
    zpl_string password = zpl_string_make(allocator,zpl_json_find(&object,"password",false)->string);
    zpl_string email = zpl_string_make(allocator,zpl_json_find(&object,"email",false)->string);
    zpl_string hashedPassword = HashPassword(password);
    *response = zpl_string_appendc(*response,"HTTP/1.1 200 \r\n" );
    char* status = NULL;
    if(!UserExists(&(data->database),name)){
        RegisterUserOnDatabase(&(data->database),name,email,hashedPassword);
        status = "User Registered";
    }else{
        status = "User Exists";
    }
    *response = zpl_string_appendc(*response,"\r\n");
    zpl_json_object jsonOutput ={};
    zpl_json_init_node(&jsonOutput,allocator,"<root>",ZPL_JSON_TYPE_OBJECT);
    zpl_json_add(&jsonOutput,"status",ZPL_JSON_TYPE_STRING)->string = status;
    zpl_json_add(&jsonOutput,"redirectlink",ZPL_JSON_TYPE_STRING)->string = "/login.html";
    zpl_json_add(&jsonOutput,"redirect",ZPL_JSON_TYPE_STRING)->string = "true";
    zpl_string jsonStr = zpl_json_write_string(allocator,&jsonOutput,0);
    *response = zpl_string_appendc(*response,jsonStr);
    *response = zpl_string_appendc(*response,"\r\n");
    zpl_string_free(jsonBody);
    zpl_json_free(&object);
    zpl_json_free(&jsonOutput);
}


static void LoginHandler(RequestData* data,zpl_string *response){
    zpl_allocator allocator = ZPL_STRING_HEADER(*response)->allocator;
    zpl_json_object object = {};
    zpl_u8 errcode;
    zpl_string jsonBody = zpl_string_make_length(allocator,data->body,data->bodyLength);
    zpl_json_parse(&object,data->bodyLength,data->body,allocator,true,&errcode);
    zpl_string name = zpl_string_make(allocator,zpl_json_find(&object,"name",false)->string);
    zpl_string password = zpl_string_make(allocator,zpl_json_find(&object,"password",false)->string);
    zpl_string hashedPassword = RetriveHashedPassword(&(data->database),name);
    bool IsVerfied = CheckPassword(hashedPassword,password);
    *response = zpl_string_appendc(*response,"HTTP/1.1 200 \r\n" );
    const char* status = NULL;
    if(IsVerfied){
        status = "UserExists";
        if(data->generateSession){
            GenerateSessionID(name,allocator,data);
            *response = zpl_string_appendc(*response,"Set-Cookie: sid=");
            *response = zpl_string_append(*response,data->sessionID.id);
            *response = zpl_string_appendc(*response,"; max-age=18000; path=/; Secure; HttpOnly\r\n");
            *response = zpl_string_appendc(*response,"Set-Cookie: name=");
            *response = zpl_string_append(*response,data->sessionID.name);
            *response = zpl_string_appendc(*response,"; max-age=18000; path=/; Secure; HttpOnly\r\n");
        }
    }
    *response = zpl_string_appendc(*response,"\r\n");
    zpl_json_object jsonOutput ={};
    zpl_json_init_node(&jsonOutput,allocator,"<root>",ZPL_JSON_TYPE_OBJECT);
    zpl_json_add(&jsonOutput,"status",ZPL_JSON_TYPE_STRING)->string = "Forbidden";
    zpl_json_add(&jsonOutput,"redirectlink",ZPL_JSON_TYPE_STRING)->string = "/admin.html";
    zpl_json_add(&jsonOutput,"redirect",ZPL_JSON_TYPE_STRING)->string = "true";
    zpl_string jsonStr = zpl_json_write_string(allocator,&jsonOutput,0);
    *response = zpl_string_appendc(*response,jsonStr);
    *response = zpl_string_appendc(*response,"\r\n");
    zpl_string_free(jsonBody);
    zpl_json_free(&object);
    zpl_json_free(&jsonOutput);
}

static void ForbiddenHandler(RequestData* data,zpl_string *response){
    zpl_allocator allocator = ZPL_STRING_HEADER(*response)->allocator;
    *response = zpl_string_appendc(*response,"HTTP/1.1 403 Forbidden \r\n" );
    *response = zpl_string_appendc(*response,"\r\n");
    zpl_json_object jsonOutput ={};
    zpl_json_init_node(&jsonOutput,allocator,"<root>",ZPL_JSON_TYPE_OBJECT);
    zpl_json_add(&jsonOutput,"status",ZPL_JSON_TYPE_STRING)->string = "Forbidden";
    zpl_json_add(&jsonOutput,"redirectlink",ZPL_JSON_TYPE_STRING)->string = "/index.html";
    zpl_json_add(&jsonOutput,"redirect",ZPL_JSON_TYPE_STRING)->string = "true";
    zpl_string jsonStr = zpl_json_write_string(allocator,&jsonOutput,0);
    *response = zpl_string_appendc(*response,jsonStr);
    *response = zpl_string_appendc(*response,"\r\n");
    zpl_json_free(&jsonOutput);
}

static uv_buf_t GenerateResponse(zpl_array(SessionID) sessions ,zpl_allocator allocator,RequestData* data){
        zpl_string response = zpl_string_make_reserve(allocator,10);
        bool handled = false;
        //Check SessionID
        for(int i = 0 ; i < data->numHeaders;i++){
            struct phr_header header = data->headers[i];
            if(zpl_strncmp(header.name,"Cookie",6)==0){
                char *path = (char *)header.value;
                int p = 0 ;
                while(p < header.value_len){
                    if(zpl_strncmp(path,"sid=",4)){
                        int sessionIDLength = (int)(zpl_strchr(path,';') - path) - 3 ;
                        sessionIDLength = sessionIDLength < header.value_len ? sessionIDLength : header.value_len - (3 + 1);
                        data->sessionID.id = zpl_string_make_length(allocator,path + 3,sessionIDLength);
                    }
                    if(zpl_strncmp(path,"name=",4)){
                        int nameLength = (int)(zpl_strchr(path,';') - path) - 3 ;
                        nameLength = nameLength < header.value_len ? nameLength : header.value_len - (3 + 1);
                        data->sessionID.name = zpl_string_make_length(allocator,path + 3,nameLength);
                    }
                    path++;
                    p++;
                }
            }
        }
        bool sessionvalid = false;
        if(data->sessionID.id){
            for(int i =0 ; i < zpl_array_count(sessions);i++){
                if(zpl_string_are_equal(data->sessionID.id ,sessions[i].id)){
                    if(zpl_string_are_equal(data->sessionID.name,sessions[i].name)){
                        sessionvalid = true;
                    }
                }
            }
        }
        if(zpl_utf8_strlen((zpl_u8 *)data->body) >  0)
        {
            data->generateSession = true;
            if(!handled) handled = HandlePostFunc(SignupHandler,data,"/signup",&response);
            data->generateSession = false;
            if(!handled) handled = HandlePostFunc(LoginHandler,data,"/login",&response);
            if(!handled){
                if(sessionvalid){
                    // Session Valid
                    if(!handled) handled = HandlePostFunc(AddPostHandler,data,"/post",&response);
                    if(!handled) handled = HandleDeleteFunc(DeletePostHandler,data,"/post",&response);
                    if(!handled) handled = HandlePutFunc(UpdatePostHandler,data,"/post",&response);
                    if(!handled) handled = HandlePostFunc(RenderPostHandler,data,"/render",&response);
                }else{
                    //NOTE(shazan): Invalid Session
                    //              Return Forbidden Response
                    handled = HandlePostFunc(ForbiddenHandler,data,"/*",&response);
                }
            }
            if(data->sessionGenerated){
                zpl_array_append(sessions,data->sessionID);
                data->sessionGenerated = false;
            }
        }else{
            response = zpl_string_appendc(response,"HTTP/1.1 400 Bad Request \r\n" );
            response = zpl_string_appendc(response,"\r\n" );
            response = zpl_string_appendc(response,"\r\n" );

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
    zpl_array(SessionID) sessions = ((Connection *)client->data)->server->sessions;
    uv_read_stop(client);
    if (nread > 0) {
        RequestData data = {};
        data.database = ((Connection *)client->data)->server->database;
        data.headersCap = 256;
        data.headers = zpl_alloc(allocator,sizeof(struct phr_header) *data.headersCap);
        data.numHeaders = data.headersCap;
        int minorVersion = 0;
        int bodyoffset = phr_parse_request(buf->base, buf->len, &(data.method), &(data.methodLength), &(data.path), &(data.pathLength),
                                           &minorVersion,(data.headers), (size_t *)&(data.numHeaders), 0);
        for(int i = 0 ; i < data.numHeaders;i++){
            struct phr_header header =  data.headers[i];
            if(zpl_strncmp(header.name,"Content-Length",14)==0 ||
               zpl_strncmp(header.name,"content-length",14)==0){
                char *path = zpl_strdup(allocator,(char *)header.value,header.value_len);
                data.bodyLength = zpl_str_to_u64(path,(char **)(path) ,10);
                zpl_free(allocator,path);
            }
            if(data.bodyLength) break;

        }
        data.body  = buf->base + bodyoffset;
        uv_buf_t buffer =  GenerateResponse(sessions,allocator,&data);
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
        log_error("New connection error %s\n", uv_strerror(status));
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
        log_error("Accept error %s\n", uv_strerror(r));
        zpl_free(connectionPoolAllocator,connection);
        return ;
    }
    r = uv_read_start((uv_stream_t*) client, AllocBuffer, EchoRead);
    if (r) {
        log_error( "Read error %s\n", uv_strerror(r));
        zpl_free(connectionPoolAllocator,connection);
        return ;
    }
}

int main(int argc ,char** argv) {
    FILE* logfile;
    fopen_s(&logfile,"logs.txt","w");
    log_add_fp(logfile, LOG_TRACE);
    sodium_init();
    zpl_allocator generalAllocator =  zpl_heap_allocator();
    ServerContext* serverContext = zpl_alloc(generalAllocator,sizeof(ServerContext));
    serverContext->database = ConnectToDatabase();
    zpl_arena arena = {};
    zpl_arena_init_from_allocator(&arena,generalAllocator,zpl_megabytes(200));
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
    log_trace("Server Listening");
    if (r) {
        log_error("Listen error %s\n", uv_strerror(r));
        return 1;
    }
    randombytes_close();
    uv_run(loop, UV_RUN_DEFAULT);
    DisconnectDatabase(&(serverContext->database));
    log_trace("Server Closed");
    fclose(logfile);
    return 0;
}

