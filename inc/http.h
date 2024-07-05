#ifndef __MODULE_HTTP_H__
#define __MODULE_HTTP_H__

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <arpa/inet.h>

#include <net_inc.h>

#define HTTP_PROXY_BUF_SIZE 2048

#define HTTP_PROXY_CONNECT "CONNECT"

#define HTTP_PROXY_LINE_END "\r\n"
#define HTTP_PROXY_BODY_END "\r\n\r\n"

#define HTTP_PROXY_RET_200 "HTTP/1.1 200 Connection Established"
#define HTTP_PROXY_RET_502 "HTTP/1.1 502 Bad Gateway"
#define HTTP_PROXY_RET_504 "HTTP/1.1 504 Gateway timeout"

/*
    定义http代理协议的阶段.
*/
typedef enum HTTP_Status
{
    HTTP_STATUS_CONNECT = 0,
    HTTP_STATUS_RELAY,
    HTTP_STATUS_Max
}HTTP_STATUS;

typedef struct _http_fds
{
    HTTP_STATUS status;

    int fd_real_client;
    int fd_real_server;

    //数据.
    char * buf;
    int alloc_len;
    int buf_len;

    unsigned long upstream_byte;
    unsigned long downstream_byte;

    //真实服务器.
    char real_host[256];
    short real_port;
}http_fds;

char * httpStatusName(int status);

http_fds *httpFDsNew();
void httpFDsFree(http_fds *http);

void httpCONNECT_Request(http_fds *http);
void httpCONNECT_Response(struct aeEventLoop *eventLoop,aeFileProc *proc,http_fds *http);

void httpRelay(struct aeEventLoop *eventLoop,int fd,http_fds *http);

void httpProcess(struct aeEventLoop *eventLoop,int fd,int mask,http_fds *http,aeFileProc *proc);

#endif //__MODULE_HTTP_H__
