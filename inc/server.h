
#ifndef __MODULE_SEVER_H__
#define __MODULE_SEVER_H__

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include <net_main.h>
#include <http.h>

#include <sds.h>

typedef struct _server_node
{
    int fd_real_client;
    SSL *ssl;

    int fd_real_server;

    sds *buf;
    http_request * req;
}sever_node;

sever_node *serverNodeNew();
void serverNodeFree(sever_node*node);

//事件处理函数.
void serverProc_real_Data(struct aeEventLoop *eventLoop, int fd, void *clientData, int mask);
void serverProc_Data(struct aeEventLoop *eventLoop, int fd, void *clientData, int mask);
void serverProc_Accept(struct aeEventLoop *eventLoop, int fd, void *clientData, int mask);

void serverProc_fun(sever_node *node,struct aeEventLoop *eventLoop);
void server_Auth(sever_node *node);
void server_Connect(sever_node *node,struct aeEventLoop *eventLoop);
void server_Data(sever_node *node);

#endif //__MODULE_SEVER_H__
