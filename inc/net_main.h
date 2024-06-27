
#ifndef __NET_MAIN_H__
#define __NET_MAIN_H__

#include <stdio.h>
#include <stdlib.h>

#include <net_inc.h>

#include <sys/types.h>

#define ANET_OK 0
#define ANET_ERR -1
#define ANET_ERR_LEN 256


/*
    aeEventLoop 相关函数.
*/
aeEventLoop *aeCreateEventLoop(int setsize);
void aeDeleteEventLoop(aeEventLoop *eventLoop);

int aeCreateFileEvent(aeEventLoop *eventLoop, int fd, int mask,aeFileProc *proc, void *clientData);
void aeDeleteFileEvent(aeEventLoop *eventLoop, int fd, int mask);

int aeGetFileEvents(aeEventLoop *eventLoop, int fd);
void *aeGetFileClientData(aeEventLoop *eventLoop, int fd);

void aeStop(aeEventLoop *eventLoop);
int aeProcessEvents(aeEventLoop *eventLoop, int flags);
void aeMain(aeEventLoop *eventLoop);

int aeGetSetSize(aeEventLoop *eventLoop);
int aeResizeSetSize(aeEventLoop *eventLoop, int setsize);
void aeSetDontWait(aeEventLoop *eventLoop, int noWait);

char *aeGetApiName(void);

/*
    socket基本操作.
*/
int anetCreateSocket(char *err, int domain);
int anetTcpServer(char *err, int port, char *bindaddr, int backlog);
int anetTcp6Server(char *err, int port, char *bindaddr, int backlog);
int anetTcpAccept(char *err, int serversock, char *ip, size_t ip_len, int *port);

int anetSetReuseAddr(char *err, int fd);
int anetNonBlock(char *err, int fd);
int anetBlock(char *err, int fd);

int anetCloexec(int fd);

#endif //__NET_MAIN_H__
