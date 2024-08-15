
#include <unistd.h>
#include <ssr.h>
#include <sds.h>
#include <mlog.h>
#include <adlist.h>
#include <zmalloc.h>

static list * g_list_ssr_connection = NULL;

char HTTP_METHOD_NAMES[HTTP_METHOD_Max][64] = {
    "GET",
    "POST",
    "HEAD"
};

char SSR_TYPE_NAMES[SSR_TYPE_Max][64] = {
    "SSR_TYPE_AUTH",
    "SSR_TYPE_CONNECT",
    "SSR_TYPE_DATA",
    "SSR_TYPE_CLIENT_CLOSE"
};

char * httpMethodName(HTTP_METHOD method)
{
    return HTTP_METHOD_NAMES[method];
}

char * ssrTypeName(SSR_TYPE type)
{
    return SSR_TYPE_NAMES[type];
}

/*
    POST /msock/data HTTP/1.1
    Host     :
    SSR_VER  : [SSR_VERSION_0x01]
    SSR_TYPE : [SSR_TYPE_AUTH]

    Content-Type:application/x-www-form-urlencoded
    或者
    Content-Type:application/octet-stream
*/
static void _ssrBaseHttpRequest_Client(sds *buf,SSR_TYPE type,int version)
{
    sdsCatprintf(buf,"%s %s HTTP/1.1%s",httpMethodName(HTTP_METHOD_POST),SSR_URL,HTTP_LINE_END);

    sdsCatprintf(buf,"Host:%s%s",SSR_HEAD_HOST,HTTP_LINE_END);
    
    sdsCatprintf(buf,"%s:%d%s",SSR_HEADER_VER,version,HTTP_LINE_END);

    sdsCatprintf(buf,"%s:%d%s",SSR_HEADER_TYPE,type,HTTP_LINE_END);

    if(SSR_TYPE_DATA != type)
    {
        sdsCatprintf(buf,"Content-Type:application/x-www-form-urlencoded%s",HTTP_LINE_END);
    }
    else
    {
        sdsCatprintf(buf,"Content-Type:application/octet-stream%s",HTTP_LINE_END);
    }
}

/*
    HTTP/1.1 200 Connection Established
    Content-Type:
    Content-Length:36{uuid数据}
*/
static void _ssrBaseHttpReponse_Server(sds *buf,SSR_TYPE type,int version,int data_len)
{
    sdsCatprintf(buf,"HTTP/1.1 200 Connection Established%s",HTTP_LINE_END);

    if(SSR_TYPE_DATA == type)
    {
        sdsCatprintf(buf,"Content-Type:application/octet-stream%s",HTTP_LINE_END);
    }
    else
    {
        sdsCatprintf(buf,"Content-Type:application/x-www-form-urlencoded%s",HTTP_LINE_END);
    }

    sdsCatprintf(buf,"%s:%d%s",SSR_HEADER_VER,version,HTTP_LINE_END);
    sdsCatprintf(buf,"%s:%d%s",SSR_HEADER_TYPE,type,HTTP_LINE_END);

    if(data_len > 0)
    {
        sdsCatprintf(buf,"Content-Length:%d%s",data_len,HTTP_LINE_END);
    }
    else
    {
        sdsCatprintf(buf,"Content-Length:%d%s",0,HTTP_LINE_END);
    }
}

/*
    POST /msock/data HTTP/1.1
    Host     :
    SSR_VER  : [SSR_VERSION_0x10]
    SSR_TYPE : [SSR_TYPE_AUTH]

    Content-Type:application/x-www-form-urlencoded
    Content-Length:***[真实数据的长度]

    u={username}&p={password}
*/
int ssrAuth_Request(SSL *ssl,const char * username,const char * password)
{
    int ssl_sended = 0;

    sds * buf = sdsCreateEmpty(1024);
    sds *auth_data = sdsCreateEmpty(128);

    sdsCatprintf(auth_data,"u=%s&p=%s",username,password);

    _ssrBaseHttpRequest_Client(buf,SSR_TYPE_AUTH,SSR_VERSION_0x01);

    sdsCatprintf(buf,"Content-Length:%d%s",sdsLength(auth_data),HTTP_LINE_END);
    
    sdsCatprintf(buf,"%s",HTTP_HEAD_END);

    sdsCatprintf(buf,"%s",sdsString(auth_data,0));

    ///printf("ssrAuth_Client_Request():\r\n%s\r\n",sdsString(buf,0));
    ssl_sended = anetSSLWrite(ssl,sdsPTR(buf),sdsLength(buf));
    ///printf("ssrAuth_Request() anetSSLWrite() ssl_len %d\r\n",ssl_sended);

    sdsRelease(buf);
    buf = NULL;

    sdsRelease(auth_data);
    auth_data = NULL;

    return ssl_sended;
}

/*
    HTTP/1.1 200 Connection Established
    Content-Type:
    Content-Length:36{uuid数据}


    6b3609b7-3c77-4ba5-a90c-bbbeede19293
*/
int ssrAuth_Response(SSL *ssl,const char * data)
{
    int len = strlen(data);
    int ssl_sended = 0;

    sds *buf = sdsCreateEmpty(128);

    _ssrBaseHttpReponse_Server(buf,SSR_TYPE_AUTH,SSR_VERSION_0x01,len);

    sdsCat(buf,HTTP_LINE_END);

    sdsCat(buf,data);

    ssl_sended = anetSSLWrite(ssl,sdsPTR(buf),sdsLength(buf));
    ///printf("ssrAuth_Response() anetSSLWrite() ssl_len %d\r\n",ssl_sended);

    sdsRelease(buf);
    buf = NULL;

    return ssl_sended;
}

/*
    POST /msock/data HTTP/1.1
    Host     :
    SSR_VER  : [SSR_VERSION_0x01]
    SSR_TYPE : [SSR_TYPE_CONNECT]

    Content-Type:application/x-www-form-urlencoded
    Content-Length:***[真实数据的长度]

    h={hostname}&p={port}
*/
int ssrConnect_Request(SSL *ssl,const char *hostname,short port)
{
    int ssl_sended = 0;

    sds * buf = sdsCreateEmpty(1024);
    sds * real_host = sdsCreateEmpty(128);

    sdsCatprintf(real_host,"h=%s&p=%d",hostname,port);

    _ssrBaseHttpRequest_Client(buf,SSR_TYPE_CONNECT,SSR_VERSION_0x01);

    sdsCatprintf(buf,"Content-Length:%d%s",sdsLength(real_host),HTTP_LINE_END);

    sdsCatprintf(buf,"%s",HTTP_LINE_END);

    sdsCatprintf(buf,"%s",sdsString(real_host,0));

    ///printf("ssrConnect_Client_Request():\r\n%s\r\n",sdsString(buf,0));
    
    ssl_sended = anetSSLWrite(ssl,sdsString(buf,0),sdsLength(buf));

    sdsRelease(buf);
    buf = NULL;

    sdsRelease(real_host);
    real_host = NULL;

    return ssl_sended;
}

int ssrConnect_Response(SSL *ssl,bool ok)
{
    int len = 1;
    int ssl_len = 0;

    sds *buf = sdsCreateEmpty(128);

    _ssrBaseHttpReponse_Server(buf,SSR_TYPE_CONNECT,SSR_VERSION_0x01,len);

    sdsCat(buf,HTTP_LINE_END);

    sdsCatprintf(buf,"%d",ok);
    
    ssl_len = anetSSLWrite(ssl,sdsPTR(buf),sdsLength(buf));
    ///printf("ssrConnect_Response() anetSSLWrite() ssl_len %d\r\n",ssl_len);

    sdsRelease(buf);
    buf = NULL;

    return ssl_len;
}

/*
    POST /msock/data HTTP/1.1
    Host     :
    SSR_VER  : [SSR_VERSION_0x01]
    SSR_TYPE : [SSR_TYPE_DATA]

    Content-Type:application/octet-stream
    Content-Length:***[真实数据的长度]

    {data}
*/
int ssrData_Request(SSL *ssl,const char * data,int len)
{
    int ssl_sended = 0;
    sds * buf = sdsCreateEmpty(1024);

    _ssrBaseHttpRequest_Client(buf,SSR_TYPE_DATA,SSR_VERSION_0x01);

    sdsCatprintf(buf,"Content-Length:%d%s",len,HTTP_LINE_END);
    sdsCatprintf(buf,"%s",HTTP_LINE_END);
    sdsCatlen(buf,data,len);

    ssl_sended = anetSSLWrite(ssl,sdsPTR(buf),sdsLength(buf));
    ///printf("ssrData_Request() anetSSLWrite() ssl_len %d\r\n",ssl_sended);

    sdsRelease(buf);
    buf = NULL;

    return ssl_sended;
}

int ssrData_Response(SSL *ssl,const char * data,int len)
{
    int ssl_len = 0;
    sds *buf = sdsCreateEmpty(4096);

    _ssrBaseHttpReponse_Server(buf,SSR_TYPE_DATA,SSR_VERSION_0x01,len);
    sdsCat(buf,HTTP_LINE_END);
    sdsCatlen(buf,data,len);

    ssl_len = anetSSLWrite(ssl,sdsPTR(buf),sdsLength(buf));
    ///printf("ssrData_Response() anetSSLWrite() ssl_len %d\r\n",ssl_len);

    sdsRelease(buf);
    buf = NULL;

    return ssl_len;
}

int ssrClientClose_Request(SSL *ssl)
{
    int ssl_sended = 0;
    sds * buf = sdsCreateEmpty(1024);

    _ssrBaseHttpRequest_Client(buf,SSR_TYPE_CLIENT_CLOSE,SSR_VERSION_0x01);

    sdsCatprintf(buf,"Content-Length:%d%s",0,HTTP_LINE_END);

    ssl_sended = anetSSLWrite(ssl,sdsPTR(buf),sdsLength(buf));
    ///printf("ssrData_Request() anetSSLWrite() ssl_len %d\r\n",ssl_sended);

    sdsRelease(buf);
    buf = NULL;

    return ssl_sended;
}

int ssrFake_html(SSL *ssl,const char *data,int len)
{
    int ssl_sended = 0;
    sds * buf = sdsCreateEmpty(2048);
    char gmt_time[128] = {0};
    mlogTick_gmt(gmt_time,128);

    sdsCatprintf(buf,"HTTP/1.1 200 OK%s",HTTP_LINE_END);
    sdsCatprintf(buf,"Server:WAF%s",HTTP_LINE_END);
    sdsCatprintf(buf,"Date:%s%s",gmt_time,HTTP_LINE_END);
    sdsCatprintf(buf,"Content-Type:text/html; charset=utf-8%s",HTTP_LINE_END);
    
    if(len > 0)
    {
        sdsCatprintf(buf,"Content-Length:%d%s",len,HTTP_LINE_END);

        sdsCat(buf,HTTP_LINE_END);
        sdsCatlen(buf,data,len);
    }
    else
    {
        sdsCatprintf(buf,"Content-Length:%d%s",0,HTTP_LINE_END);
    }

    ssl_sended = anetSSLWrite(ssl,sdsPTR(buf),sdsLength(buf));
    ///printf("ssrFake_html() anetSSLWrite() ssl_len %d\r\n",ssl_sended);

    sdsRelease(buf);
    buf = NULL;
    
    return ssl_sended;
}

int ssrResponseType(http_response *res)
{
    int ask_type = -1;

    listNode *node = listFirst(res->header_list);
    while(NULL != node)
    {
        http_header *h = (http_header*)node->value;
        if(0 == strcasecmp(sdsPTR(h->key),SSR_HEADER_TYPE))
        {
            return atoi(sdsPTR(h->value));
        }

        node = listNextNode(node);
    }

    return ask_type;
}

/*
    SSR_CONNECTION
*/
SSR_CONNECTION * ssrConnectionNew()
{
    SSR_CONNECTION *conn = zmalloc(sizeof(SSR_CONNECTION));
    if(NULL != conn)
    {
        conn->fd_ssr_server = -1;
        conn->ssl = NULL;

        conn->used = false;
    }

    return conn;
}

void ssrConnectionRelease(SSR_CONNECTION * conn)
{
    if(NULL == conn)
    {
        return;
    }

    if(conn->fd_ssr_server > 0)
    {
        close(conn->fd_ssr_server);
        conn->fd_ssr_server = -1;
    }

    if(conn->ssl)
    {
        anetSSLClose(conn->ssl);
        conn->ssl = NULL;
    }

    conn->used = false;

    zfree(conn);
    conn = NULL;
}

bool ssrConnectionUsedGet(SSR_CONNECTION *conn)
{
    return conn->used;
}

void ssrConnectionUsedSet(SSR_CONNECTION *conn,bool used)
{
    conn->used = used;
}

void _ssrConnection_Free(void * ptr)
{
    ssrConnectionRelease(ptr);
    ptr = NULL;
}

bool ssrConnectionListInit(int size)
{
    int index = 0;

    if(NULL != g_list_ssr_connection)
    {
        return true;
    }

    g_list_ssr_connection = listCreate();
    if(NULL == g_list_ssr_connection)
    {
        return false;
    }

    listSetFreeMethod(g_list_ssr_connection,_ssrConnection_Free);

    for(index = 0; index < size;index++)
    {
        char err_str[ANET_ERR_LEN] = {0};
        bool connected_ssr = false;

        SSR_CONNECTION *conn = ssrConnectionNew();
        if(NULL == conn)
        {
            break;
        }

        conn->fd_ssr_server = anetTcpNonBlockConnect(err_str,SSR_HOST,SSR_PORT);
        if(conn->fd_ssr_server > 0)
        {
            conn->ssl = anetSSLConnect(err_str,conn->fd_ssr_server);
            if(NULL != conn->ssl)
            {
                listAddNodeTail(g_list_ssr_connection,conn);
                connected_ssr = true;
            }
        }

        if(!connected_ssr)
        {
            ssrConnectionRelease(conn);
            conn = NULL;
        }
    }

    if(listLength(g_list_ssr_connection))
    {
        return true;
    }

    return false;
}

void ssrConnectionListFree()
{
    if(NULL == g_list_ssr_connection)
    {
        return;
    }

    listRelease(g_list_ssr_connection);
    g_list_ssr_connection = NULL;
}

SSR_CONNECTION *ssrConnectionListGet()
{
    if(NULL == g_list_ssr_connection)
    {
        return NULL;
    }

    listNode *node = listFirst(g_list_ssr_connection);
    while(NULL != node)
    {
        //找到一个不用的node.
        if(ssrConnectionUsedGet(node->value))
        {
            node = node->next;
        }
        else
        {
            break;
        }
    }

    if(NULL != node)
    {
        return node->value;
    }

    return NULL;
}

int ssrConnectionListSize()
{
    if(NULL == g_list_ssr_connection)
    {
        return 0;
    }

    return listLength(g_list_ssr_connection);
}
