
#include <ssr.h>
#include <sds.h>

char HTTP_METHOD_NAMES[HTTP_METHOD_Max][64] = {
    "GET",
    "POST",
    "HEAD"
};

char SSR_TYPE_NAMES[SSR_TYPE_Max][64] = {
    "SSR_TYPE_AUTH",
    "SSR_TYPE_CONNECT",
    "SSR_TYPE_DATA"
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
    printf("ssrAuth_Request() anetSSLWrite() ssl_len %d\r\n",ssl_sended);

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
    printf("ssrAuth_Response() anetSSLWrite() ssl_len %d\r\n",ssl_sended);

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
    printf("ssrConnect_Response() anetSSLWrite() ssl_len %d\r\n",ssl_len);

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
    printf("ssrData_Request() anetSSLWrite() ssl_len %d\r\n",ssl_sended);

    sdsRelease(buf);
    buf = NULL;

    return ssl_sended;
}

int ssrData_Response(SSL *ssl,const char * data,int len)
{
    int ssl_len = 0;
    sds *buf = sdsCreateEmpty(128);

    _ssrBaseHttpReponse_Server(buf,SSR_TYPE_DATA,SSR_VERSION_0x01,len);
    sdsCat(buf,HTTP_LINE_END);
    sdsCatlen(buf,data,len);

    ssl_len = anetSSLWrite(ssl,sdsPTR(buf),sdsLength(buf));
    printf("ssrData_Response() anetSSLWrite() ssl_len %d\r\n",ssl_len);

    sdsRelease(buf);
    buf = NULL;

    return ssl_len;
}

int ssrFake_html(SSL *ssl,const char *data,int len)
{
    int ssl_sended = 0;
    sds * buf = sdsCreateEmpty(2048);

    sdsCatprintf(buf,"HTTP/1.1 200%s",HTTP_LINE_END);
    sdsCatprintf(buf,"Server:nginx 1.x%s",HTTP_LINE_END);
    sdsCatprintf(buf,"Content-Type:text/html; charset=utf-8%s",HTTP_LINE_END);
    
    if(len > 0)
    {
        sdsCatprintf(buf,"Content-Length:%d%s",len,HTTP_LINE_END);
    }
    else
    {
        sdsCatprintf(buf,"Content-Length:%d%s",0,HTTP_LINE_END);
    }

    sdsCat(buf,HTTP_LINE_END);
    sdsCatlen(buf,data,len);

    ssl_sended = anetSSLWrite(ssl,sdsPTR(buf),sdsLength(buf));
    printf("ssrFake_html() anetSSLWrite() ssl_len %d\r\n",ssl_sended);

    sdsRelease(buf);
    buf = NULL;

    return ssl_sended;
}
