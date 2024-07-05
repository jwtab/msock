
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
    SSR_VER  : [SSR_VERSION_0x10]
    SSR_TYPE : [SSR_TYPE_AUTH]

    Content-Type:application/x-www-form-urlencoded

    Content-Type:application/octet-stream
*/
static void _ssrBaseHttpRequest(sds *buf,SSR_TYPE type,int version)
{
    sdsCatprintf(buf,"%s %s HTTP/1.1%s",httpMethodName(HTTP_METHOD_POST),SSR_URL,HTTP_LINE_END);

    sdsCatprintf(buf,"Host:%s%s",SSR_HEAD_HOST,HTTP_LINE_END);
    
    sdsCatprintf(buf,"%s:%d%s",SSR_HEADER_VER,version,HTTP_LINE_END);

    sdsCatprintf(buf,"%s:%d%s",SSR_HEADER_TYPE,type,HTTP_LINE_END);

    if(SSR_TYPE_DATA != type)
    {
        sdsCatprintf(buf,"Content-Type:application/x-www-form-urlencoded%s",SSR_HEADER_TYPE,type,HTTP_LINE_END);
    }
    else
    {
        sdsCatprintf(buf,"Content-Type:application/octet-stream%s",SSR_HEADER_TYPE,type,HTTP_LINE_END);
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
void ssrAuth_Request(int fd,const char * username,const char * password)
{
    sds * buf = sdsCreateEmpty(1024);

    _ssrBaseHttpRequest(buf,SSR_VERSION_0x10,SSR_TYPE_AUTH);

    sdsRelease(buf);
    buf = NULL;
}

/*
    HTTP/1.1 200 Connection Established
    Content-Length:49


    6b3609b7-3c77-4ba5-a90c-bbbeede19293
*/
void ssrAuth_Response(int fd)
{

}

/*
    POST /msock/data HTTP/1.1
    Host     :
    SSR_VER  : [SSR_VERSION_0x10]
    SSR_TYPE : [SSR_TYPE_CONNECT]

    Content-Type:application/x-www-form-urlencoded
    Content-Length:***[真实数据的长度]

    h={hostname}&p={port}
*/
void ssrConnect_Request(int fd)
{
    sds * buf = sdsCreateEmpty(1024);

    _ssrBaseHttpRequest(buf,SSR_VERSION_0x10,SSR_TYPE_CONNECT);

    sdsRelease(buf);
    buf = NULL;
}

void ssrConnect_Response(int fd)
{

}

/*
    POST /msock/data HTTP/1.1
    Host     :
    SSR_VER  : [SSR_VERSION_0x10]
    SSR_TYPE : [SSR_TYPE_DATA]

    Content-Type:application/octet-stream
    Content-Length:***[真实数据的长度]

    {data}
*/

void ssrRelay()
{

}
