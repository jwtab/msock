#ifndef __MODULE_HTTP_PROXY_H__
#define __MODULE_HTTP_PROXY_H__

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <arpa/inet.h>

#include <net_inc.h>
#include <http.h>

//#define HTTP_PROXY_LOCAL

#define HTTP_PROXY_BUF_SIZE 2048

#define HTTP_PROXY_CONNECT "CONNECT"

#define HTTP_PROXY_LINE_END "\r\n"
#define HTTP_PROXY_BODY_END "\r\n\r\n"

#define HTTP_PROXY_RET_200 "HTTP/1.1 200 Connection Established"
#define HTTP_PROXY_RET_502 "HTTP/1.1 502 Bad Gateway"
#define HTTP_PROXY_RET_504 "HTTP/1.1 504 Gateway timeout"

#define HTTP_HEADER_PROXY_AUTH "Proxy-Authorization"
/*
    定义http代理协议的阶段.
*/
typedef enum HTTP_Proxy_Status
{
    HTTP_PROXY_STATUS_CONNECT = 0,
    HTTP_PROXY_STATUS_RELAY,
    HTTP_PROXY_STATUS_Max
}HTTP_PROXY_STATUS;

typedef struct _http_fds
{
    HTTP_PROXY_STATUS status;

    int fd_real_client;
    int fd_real_server;

    void * ssl;
    http_response * res;

    //数据.
    sds * buf;

    unsigned long upstream_byte;
    unsigned long downstream_byte;

    //真实服务器.
    char real_host[256];
    short real_port;
    int proxy_type;

    //认证信息.
    char username[64];
    char password[64];
}http_fds;

http_fds *httpFDsNew();
void httpFDsFree(http_fds *http);

//Proxy处理数据函数.
void httpProxy_proxy(struct aeEventLoop *eventLoop, int fd, void *clientData, int mask);
void httpProxy_ssr(struct aeEventLoop *eventLoop, int fd, void *clientData, int mask);
void httpProxy_accept(struct aeEventLoop *eventLoop, int fd, void *clientData, int mask);

char * httpProxyStatusName(int status);

void httpCONNECT_Request(http_fds *http);
void httpCONNECT_Response(struct aeEventLoop *eventLoop,http_fds *http);

bool HttpCONNECT_Response_local(struct aeEventLoop *eventLoop,http_fds *http);
bool HttpCONNECT_Remote_ssr(struct aeEventLoop *eventLoop,http_fds *http);

void httpRelay_local(struct aeEventLoop *eventLoop,int fd,http_fds *http);
void httpRelay_ssr(struct aeEventLoop *eventLoop,http_fds *http);

void proxyProc_fun(http_fds *node,struct aeEventLoop *eventLoop);

#endif //__MODULE_HTTP_PROXY_H__
