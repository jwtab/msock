
#ifndef __MODULE_SEVER_H__
#define __MODULE_SEVER_H__

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include <net_main.h>

#include <sds.h>

typedef struct _server_node
{
    int fd;
    SSL *ssl;

    sds *buf;

}SERVER_NODE;

SERVER_NODE *serverNodeNew();
void serverNodeFree(SERVER_NODE*node);

//事件处理函数.
void serverProc_Data(struct aeEventLoop *eventLoop, int fd, void *clientData, int mask);
void serverProc_Accept(struct aeEventLoop *eventLoop, int fd, void *clientData, int mask);


#endif //__MODULE_SEVER_H__
