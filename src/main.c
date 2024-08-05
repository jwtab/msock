
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

#define WATCH_SOCK_SIZE 8192

//SOCKS
int main_socks_proxy(MLOG *log);

//http
int main_https_proxy(MLOG *log);

//https server
int main_server(MLOG *log);

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

    signal(SIGPIPE, SIG_IGN);

    MLOG *log = mlogNew("./log.txt");

#ifdef MSOCK_SEVER
    anetSSLInit(false);
#else
    anetSSLInit(true);
#endif

#ifdef MSOCK_SEVER
    main_server(log);
#else
    #ifdef MSOCK_SOCKS
        main_socks_proxy(log);
    #else
        main_https_proxy(log);
    #endif
#endif 

    anetSSLUnInit();

    mlogRelease(log);
    
    return 0;
}

int main_https_proxy(MLOG *log)
{
    char err_str[ANET_ERR_LEN] = {0};

    event_loop = aeCreateEventLoop(WATCH_SOCK_SIZE);
    mlogInfo(log,"main_https_proxy() apiName %s",aeGetApiName());

    event_loop->ref_log_ptr = log;
    
    fd_server = anetTcpServer(err_str,listen_port,listen_host,10);
    if(-1 == fd_server)
    {
        mlogFatal(log,"main_https_proxy() anetTcpServer(%s:%d) error %s",listen_host,listen_port,err_str);

        return 1;
    }

    mlogInfo(log,"main_https_proxy() listening %s:%d,PID %d",listen_host,listen_port,getpid());

    signal(SIGINT, signal_handler);

    //增加Accept处理函数.
    aeCreateFileEvent(event_loop,fd_server,AE_READABLE|AE_WRITABLE,httpProxy_accept,NULL);

    aeMain(event_loop);

    mlogInfo(log,"main_https_proxy() Main exit","");
    
    aeDeleteEventLoop(event_loop);
    event_loop = NULL;

    return 0;
}

int main_socks_proxy(MLOG *log)
{
    char err_str[ANET_ERR_LEN] = {0};

    event_loop = aeCreateEventLoop(WATCH_SOCK_SIZE);
    mlogInfo(log,"main_socks_proxy() apiName %s",aeGetApiName());

    event_loop->ref_log_ptr = log;

    fd_server = anetTcpServer(err_str,listen_port,listen_host,10);
    if(-1 == fd_server)
    {
        mlogFatal(log,"main_socks_proxy() anetTcpServer(%s:%d) error %s",listen_host,listen_port,err_str);

        return 1;
    }

    mlogInfo(log,"main_socks_proxy() listening %s:%d",listen_host,listen_port);

    signal(SIGINT, signal_handler);

    //增加Accept处理函数.
    aeCreateFileEvent(event_loop,fd_server,AE_READABLE|AE_WRITABLE,sockProxy_accept,NULL);

    aeMain(event_loop);
    
    mlogInfo(log,"main_socks_proxy() Main exit");
    
    aeDeleteEventLoop(event_loop);
    event_loop = NULL;

    return 0;
}

int main_server(MLOG *log)
{
    char err_str[ANET_ERR_LEN] = {0};

    event_loop = aeCreateEventLoop(WATCH_SOCK_SIZE);
    mlogInfo(log,"main_server() apiName %s",aeGetApiName());

    event_loop->ref_log_ptr = log;

    fd_server = anetTcpServer(err_str,listen_port,listen_host,10);
    if(-1 == fd_server)
    {
        mlogFatal(log,"main_server() anetTcpServer(%s:%d) error %s",listen_host,listen_port,err_str);

        return 1;
    }

    mlogInfo(log,"main_server() by_https listening %s:%d",listen_host,listen_port);

    signal(SIGINT, signal_handler);

    if(AE_OK == anetSSLServerInit("./fullchain.pem","./privkey.pem"))
    {
        //增加Accept处理函数.
        aeCreateFileEvent(event_loop,fd_server,AE_READABLE|AE_WRITABLE,serverProc_Accept,NULL);

        aeMain(event_loop);

        mlogInfo(log,"main_server() Main exit %s","");
        
        aeDeleteEventLoop(event_loop);
        event_loop = NULL;
    }
    else
    {
        mlogFatal(log,"main_server() anetSSLServerInit() error:%s","NOT SSL/TLS cert");
    }
    
    return 0;
}
