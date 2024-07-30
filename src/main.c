
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
#include <http_proxy.h>
#include <server.h>
#include <mlog.h>

#define WATCH_SOCK_SIZE 512

//SOCKS
int main_socks();

//http
int main_http();

//https server
int main_server();

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

#ifdef MSOCK_SEVER
    listen_port = 443;
#else 
    listen_port = 1080;
#endif

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

#ifdef MSOCK_SEVER
    anetSSLInit(false);
#else
    anetSSLInit(true);
#endif

#ifdef MSOCK_SEVER
    main_server();
#else
    #ifdef MSOCK_SOCKS
        main_socks();
    #else
        main_http();
    #endif
#endif 

    anetSSLUnInit();
    
    return 0;
}

int main_http()
{
    char err_str[ANET_ERR_LEN] = {0};

    event_loop = aeCreateEventLoop(WATCH_SOCK_SIZE);
    printf("main_http() apiName %s\r\n",aeGetApiName());

    fd_server = anetTcpServer(err_str,listen_port,listen_host,10);
    if(-1 == fd_server)
    {
        printf("main_http() anetTcpServer(%s:%d) error %s\r\n",listen_host,listen_port,err_str);

        return 1;
    }

    printf("main_http() HTTP_PROXY ::: listening %s:%d\r\n",listen_host,listen_port);

    signal(SIGINT, signal_handler);

    //增加Accept处理函数.
    aeCreateFileEvent(event_loop,fd_server,AE_READABLE|AE_WRITABLE,httpProxy_accept,NULL);

    aeMain(event_loop);

    printf("\r\nmain_http() Main exit\r\n");
    
    aeDeleteEventLoop(event_loop);
    event_loop = NULL;

    return 0;
}

int main_socks()
{
    char err_str[ANET_ERR_LEN] = {0};

    event_loop = aeCreateEventLoop(WATCH_SOCK_SIZE);
    printf("main_http() apiName %s\r\n",aeGetApiName());

    fd_server = anetTcpServer(err_str,listen_port,listen_host,10);
    if(-1 == fd_server)
    {
        printf("main_socks() anetTcpServer(%s:%d) error %s\r\n",listen_host,listen_port,err_str);

        return 1;
    }

    printf("SOCKS ::: listening %s:%d\r\n",listen_host,listen_port);

    signal(SIGINT, signal_handler);

    //增加Accept处理函数.
    aeCreateFileEvent(event_loop,fd_server,AE_READABLE|AE_WRITABLE,sockProxy_accept,NULL);

    aeMain(event_loop);

    printf("\r\nmain_socks() Main exit\r\n");
    
    aeDeleteEventLoop(event_loop);
    event_loop = NULL;

    return 0;
}

int main_server()
{
    char err_str[ANET_ERR_LEN] = {0};

    event_loop = aeCreateEventLoop(WATCH_SOCK_SIZE);
    printf("main_server() apiName %s\r\n",aeGetApiName());

    fd_server = anetTcpServer(err_str,listen_port,listen_host,10);
    if(-1 == fd_server)
    {
        printf("main_server() anetTcpServer(%s:%d) error %s\r\n",listen_host,listen_port,err_str);

        return 1;
    }

    printf("main_server(https) ::: listening %s:%d\r\n",listen_host,listen_port);

    signal(SIGINT, signal_handler);

    if(AE_OK == anetSSLServerInit("./fullchain.pem","./privkey.pem"))
    {
        //增加Accept处理函数.
        aeCreateFileEvent(event_loop,fd_server,AE_READABLE|AE_WRITABLE,serverProc_Accept,NULL);

        aeMain(event_loop);

        printf("\r\nmain_server() Main exit\r\n");
        
        aeDeleteEventLoop(event_loop);
        event_loop = NULL;
    }
    else
    {
        printf("main_server() anetSSLServerInit() error\r\n");
    }
    
    return 0;
}
