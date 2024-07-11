
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <getopt.h>

#include <zmalloc.h>
#include <net_main.h>

#include <socks.h>
#include <http.h>

#define WATCH_SOCK_SIZE 512

//SOCKS
int main_http();
void msockProc_Data(struct aeEventLoop *eventLoop, int fd, void *clientData, int mask);
void msockProc_Accept(struct aeEventLoop *eventLoop, int fd, void *clientData, int mask);

//http
int main_socks();
void httpProc_Data(struct aeEventLoop *eventLoop, int fd, void *clientData, int mask);
void httpProc_Accept(struct aeEventLoop *eventLoop, int fd, void *clientData, int mask);

int fd_server  = -1;
aeEventLoop *event_loop;

char listen_host[64] = {0};
int listen_port = 1080;

void signal_handler(int signum) 
{
    if (signum == SIGINT) 
    {
        aeStop(event_loop);
    }
}

int main_arg(int argc,char **argv)
{
    strcpy(listen_host,"*");
    listen_port = 1080;
    char ch;

    while((ch = getopt(argc, argv, "h:p:")) != -1)
    {
        switch (ch) 
        {
            case 'h':
            {
                strcpy(listen_host,optarg);
                break;
            }
                
            case 'p':
            {
                listen_port = atol(optarg);
                break;
            }

            default:
            {
                break;
            }
        }
    }

    return 0;
}

int main(int argc,char **argv)
{
    main_arg(argc,argv);

    anetSSLInit();

    //main_http(argc,argv);
    main_socks(argc,argv);

    anetSSLUnInit();
    
    return 0;
}

int main_http()
{
    char err_str[ANET_ERR_LEN] = {0};

    event_loop = aeCreateEventLoop(WATCH_SOCK_SIZE);

    fd_server = anetTcpServer(err_str,listen_port,listen_host,10);
    if(-1 == fd_server)
    {
        printf("anetTcpServer() error %s\r\n",err_str);
    }

    printf("HTTP_PROXY ::: listening %s:%d\r\n",listen_host,listen_port);

    signal(SIGINT, signal_handler);

    //增加Accept处理函数.
    aeCreateFileEvent(event_loop,fd_server,AE_READABLE|AE_WRITABLE,httpProc_Accept,NULL);

    aeMain(event_loop);

    printf("\r\nMain exit\r\n");
    
    aeDeleteEventLoop(event_loop);
    event_loop = NULL;

    return 0;
}

int main_socks()
{
    char err_str[ANET_ERR_LEN] = {0};

    event_loop = aeCreateEventLoop(WATCH_SOCK_SIZE);

    fd_server = anetTcpServer(err_str,listen_port,listen_host,10);
    if(-1 == fd_server)
    {
        printf("anetTcpServer() error %s\r\n",err_str);
    }

    printf("SOCKS ::: listening %s:%d\r\n",listen_host,listen_port);

    signal(SIGINT, signal_handler);

    //增加Accept处理函数.
    aeCreateFileEvent(event_loop,fd_server,AE_READABLE|AE_WRITABLE,msockProc_Accept,NULL);

    aeMain(event_loop);

    printf("\r\nMain exit\r\n");
    
    aeDeleteEventLoop(event_loop);
    event_loop = NULL;

    return 0;
}

void msockProc_Data(struct aeEventLoop *eventLoop, int fd, void *clientData, int mask)
{
    socksProcess(eventLoop,fd,mask,(s5_fds*)clientData,msockProc_Data);
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
        printf("msockProc_Accept() anetTcpAccept() error %s\r\n",err_str);
        return;
    }

    printf("msockProc_Accept() anetTcpAccept() OK %s:%d \r\n",ip,port);

    //增加数据处理函数.
    s5_fds *s5 = s5FDsNew();
    if(NULL != s5)
    {
        s5->fd_real_client = fd_client;
        s5->fd_real_server = -1;
        s5->status = SOCKS_STATUS_HANDSHAKE_1;
        s5->auth_type = S5_AUTH_NONE;

        anetNonBlock(err_str,fd_client);
        
        anetRecvTimeout(err_str,fd_client,SOCKET_RECV_TIMEOUT);
        anetSendTimeout(err_str,fd_client,SOCKET_SEND_TIMEOUT);

        if(AE_OK != aeCreateFileEvent(event_loop,fd_client,AE_READABLE,msockProc_Data,s5))
        {
            printf("msockProc_Accept() aeCreateFileEvent(%d) errno %d\r\n",fd_client,errno);
        }
    }
}

void httpProc_Data(struct aeEventLoop *eventLoop, int fd, void *clientData, int mask)
{
    httpProcess(eventLoop,fd,mask,(http_fds*)clientData,httpProc_Data);
}

void httpProc_Accept(struct aeEventLoop *eventLoop, int fd, void *clientData, int mask)
{
    char err_str[ANET_ERR_LEN] = {0};
    char ip[128] = {0};
    int port = 0;
    int fd_client = -1;

    fd_client = anetTcpAccept(err_str,fd,ip,128,&port);
    if(fd_client <= 0)
    {
        printf("httpProc_Accept() anetTcpAccept() error %s\r\n",err_str);
        return;
    }

    printf("httpProc_Accept() anetTcpAccept() OK %s:%d \r\n",ip,port);

    //增加数据处理函数.
    http_fds *http = httpFDsNew();
    if(NULL != http)
    {
        http->fd_real_client = fd_client;
        http->fd_real_server = -1;
        http->status = HTTP_STATUS_CONNECT;

        anetNonBlock(err_str,fd_client);
        
        anetRecvTimeout(err_str,fd_client,SOCKET_RECV_TIMEOUT);
        anetSendTimeout(err_str,fd_client,SOCKET_SEND_TIMEOUT);

        if(AE_OK != aeCreateFileEvent(event_loop,fd_client,AE_READABLE,httpProc_Data,http))
        {
            printf("httpProc_Accept() aeCreateFileEvent(%d) errno %d\r\n",fd_client,errno);
        }
    }
}
