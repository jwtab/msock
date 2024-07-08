
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
    POST /msock/data HTTP/1.1
    Host     :
    SSR_VER  : [SSR_VERSION_0x10]
    SSR_TYPE : [SSR_TYPE_AUTH]

    Content-Type:application/x-www-form-urlencoded
    Content-Length:***[真实数据的长度]

    u={username}&p={password}
*/
void ssrAuth_Client_Request(int fd,const char * username,const char * password)
{
    sds * buf = sdsCreateEmpty(1024);
    sds *auth_data = sdsCreateEmpty(128);

    sdsCatprintf(auth_data,"u=%s&p=%s",username,password);

    _ssrBaseHttpRequest_Client(buf,SSR_TYPE_AUTH,SSR_VERSION_0x01);

    sdsCatprintf(buf,"Content-Length:%d%s",sdsLength(auth_data),HTTP_LINE_END);
    
    sdsCatprintf(buf,"%s",HTTP_HEAD_END);

    sdsCatprintf(buf,"%s",sdsString(auth_data,0));

    ///printf("ssrAuth_Client_Request():\r\n%s\r\n",sdsString(buf,0));

    sdsRelease(buf);
    buf = NULL;

    sdsRelease(auth_data);
    auth_data = NULL;
}

/*
    HTTP/1.1 200 Connection Established
    Content-Length:36{uuid数据}


    6b3609b7-3c77-4ba5-a90c-bbbeede19293
*/
void ssrAuth_Client_Response(int fd)
{

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
void ssrConnect_Client_Request(int fd,const char *hostname,short port)
{
    sds * buf = sdsCreateEmpty(1024);
    sds * real_host = sdsCreateEmpty(128);

    sdsCatprintf(real_host,"h=%s&p=%d",hostname,port);

    _ssrBaseHttpRequest_Client(buf,SSR_TYPE_CONNECT,SSR_VERSION_0x01);

    sdsCatprintf(buf,"Content-Length:%d%s",sdsLength(real_host),HTTP_LINE_END);

    sdsCatprintf(buf,"%s",HTTP_HEAD_END);

    sdsCatprintf(buf,"%s",sdsString(real_host,0));

    ///printf("ssrConnect_Client_Request():\r\n%s\r\n",sdsString(buf,0));

    sdsRelease(buf);
    buf = NULL;

    sdsRelease(real_host);
    real_host = NULL;
}

void ssrConnect_Client_Response(int fd)
{

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

void ssrRelay(int fd,const char * data,int data_len)
{
    sds * buf = sdsCreateEmpty(1024);

    _ssrBaseHttpRequest_Client(buf,SSR_TYPE_DATA,SSR_VERSION_0x01);

    sdsCatprintf(buf,"Content-Length:%d%s",data_len,HTTP_LINE_END);
    sdsCatprintf(buf,"%s",HTTP_HEAD_END);

    ///printf("ssrRelay():\r\n%s\r\n",sdsString(buf,0));

    sdsCatlen(buf,data,data_len);
    
    sdsRelease(buf);
    buf = NULL;
}
