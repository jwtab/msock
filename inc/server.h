
#ifndef __MODULE_SEVER_H__
#define __MODULE_SEVER_H__

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include <net_main.h>
#include <http.h>

#include <sds.h>

#define SEVER_BUF_SIZE 8192

typedef struct _server_node
{
    int fd_real_client;
    SSL *ssl;

    int fd_real_server;

    sds *buf;
    http_request * req;

    unsigned long upstream_byte;
    unsigned long downstream_byte;
}server_node;

server_node *serverNodeNew();
void serverNodeFree(server_node*node);

//事件处理函数.
void serverProc_real_Data(struct aeEventLoop *eventLoop, int fd, void *clientData, int mask);
void serverProc_Data(struct aeEventLoop *eventLoop, int fd, void *clientData, int mask);
void serverProc_Accept(struct aeEventLoop *eventLoop, int fd, void *clientData, int mask);

void serverProc_fun(server_node *node,struct aeEventLoop *eventLoop);
void server_Auth(server_node *node);
void server_Connect(server_node *node,struct aeEventLoop *eventLoop);
void server_Data(server_node *node);

void server_send_fake_html(SSL *ssl);

#endif //__MODULE_SEVER_H__
