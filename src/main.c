
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <unistd.h>
#include <signal.h>
#include <errno.h>

#include <zmalloc.h>
#include <net_main.h>
#include <s5.h>

#define WATCH_SOCK_SIZE 512

void msockProc_Data(struct aeEventLoop *eventLoop, int fd, void *clientData, int mask);
void msockProc_Accept(struct aeEventLoop *eventLoop, int fd, void *clientData, int mask);

int fd_server  = -1;
aeEventLoop *event_loop;

void signal_handler(int signum) 
{
    if (signum == SIGINT) 
    {
        aeStop(event_loop);
    }
}

int main(int argc,char **argv)
{
    printf("Hello world\r\n");

    char err_str[ANET_ERR_LEN] = {0};

    event_loop = aeCreateEventLoop(WATCH_SOCK_SIZE);

    fd_server = anetTcpServer(err_str,1080,"127.0.0.1",10);
    if(-1 == fd_server)
    {
        printf("anetTcpServer() error %s\r\n",err_str);
    }

    signal(SIGINT, signal_handler);

    //增加Accept处理函数.
    aeCreateFileEvent(event_loop,fd_server,AE_READABLE|AE_WRITABLE,msockProc_Accept,NULL);

    aeMain(event_loop);

    printf("\r\nMain exit\r\n");
    
    aeDeleteEventLoop(event_loop);
    event_loop = NULL;
}

void msockProc_Data(struct aeEventLoop *eventLoop, int fd, void *clientData, int mask)
{
    s5Process(eventLoop,fd,mask,(s5_fds*)clientData,msockProc_Data);
}

void msockProc_Accept(struct aeEventLoop *eventLoop, int fd, void *clientData, int mask)
{
    char err_str[ANET_ERR_LEN] = {0};
    char ip[128] = {0};
    int port = 0;
    int fd_client = -1;

    fd_client = anetTcpAccept(err_str,fd,ip,128,&port);
    if(fd_client <= 0)
    {
        printf("anetTcpAccept() error %s\r\n",err_str);
        return;
    }

    printf("anetTcpAccept() OK %s:%d \r\n",ip,port);

    //增加数据处理函数.
    s5_fds *s5 = s5FDsNew();
    if(NULL != s5)
    {
        s5->fd_real_client = fd_client;
        s5->fd_real_server = -1;
        s5->status = S5_STATUS_HANDSHAKE_1;
        s5->auth = S5_AUTH_NONE;

        anetNonBlock(err_str,fd_client);
        aeCreateFileEvent(event_loop,fd_client,AE_READABLE,msockProc_Data,s5);
    }
}
