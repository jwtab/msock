
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

void get_current_dir(const char *exe_path,char *dir,int dir_len);

int fd_server  = -1;
aeEventLoop *event_loop;

char listen_host[128] = {0};
int listen_port = 1080;
bool is_daemon = false;
bool ipv6 = false;

void signal_handler(int signum) 
{
    if (signum == SIGINT ||
        signum == SIGTERM) 
    {
        aeStop(event_loop);
    }
}

void main_help(const char * bin_path)
{
    printf("mSock usage:\r\n");
    printf("        -h usage \r\n");
    printf("        -d deamon mode\r\n");
    printf("        -hstr set ip,default *\r\n");
    printf("        -pnum set port,default 443,1080\r\n");
    printf("        -t6/4 set ipv4/ipv6,default ipv4\r\n");
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

    while((ch = getopt(argc, argv, "h::p:dt:")) != -1)
    {
        switch (ch) 
        {
            case 'h':
            {
                if(NULL == optarg || 0x00 == optarg)
                {
                    main_help(argv[0]);
                    exit(0);
                }
                else
                {
                    strcpy(listen_host,optarg);
                }
                
                break;
            }
                
            case 'p':
            {
                listen_port = atol(optarg);
                break;
            }

            case 'd':
            {
                is_daemon = true;
                break;
            }

            case 't':
            {
                if(6 == atol(optarg))
                {
                    ipv6 = true;
                }

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
    char exe_dir[512] = {0};
    char log_path[1024] = {0};

    main_arg(argc,argv);

    get_current_dir((const char*)argv[0],exe_dir,512);
    snprintf(log_path,1024,"%s/log/msock.log",exe_dir);

    if(is_daemon)
    {
        daemon(0,0);
    }

    signal(SIGPIPE, SIG_IGN);

    MLOG *log = mlogNew(log_path);

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
    
    if(ipv6)
    {
        fd_server = anetTcp6Server(err_str,listen_port,listen_host,10);
    }
    else
    {
        fd_server = anetTcpServer(err_str,listen_port,listen_host,10);
    }
    
    if(-1 == fd_server)
    {
        mlogFatal(log,"main_https_proxy() anetTcpServer(%s:%d) error %s",listen_host,listen_port,err_str);

        return 1;
    }

    mlogInfo(log,"main_https_proxy() listening %s:%d,PID %d",listen_host,listen_port,getpid());

    signal(SIGINT, signal_handler);
    signal(SIGTERM,signal_handler);

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

    if(ipv6)
    {
        fd_server = anetTcp6Server(err_str,listen_port,listen_host,10);
    }
    else
    {
        fd_server = anetTcpServer(err_str,listen_port,listen_host,10);
    }

    if(-1 == fd_server)
    {
        mlogFatal(log,"main_socks_proxy() anetTcpServer(%s:%d) error %s",listen_host,listen_port,err_str);

        return 1;
    }

    mlogInfo(log,"main_socks_proxy() listening %s:%d",listen_host,listen_port);

    signal(SIGINT, signal_handler);
    signal(SIGTERM,signal_handler);

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
    
    char exe_dir[512] = {0};
    char cert_public_path[1024] = {0};
    char cert_privite_path[1024] = {0};

    get_current_dir("",exe_dir,512);
    snprintf(cert_public_path,1024,"%s/config/fullchain.pem",exe_dir);
    snprintf(cert_privite_path,1024,"%s/config/privkey.pem",exe_dir);

    mlogInfo(log,"main_server() public_cert_path %s",cert_public_path);
    mlogInfo(log,"main_server() privite_cert_path %s",cert_privite_path);

    event_loop = aeCreateEventLoop(WATCH_SOCK_SIZE);
    mlogInfo(log,"main_server() apiName %s",aeGetApiName());

    event_loop->ref_log_ptr = log;

    if(ipv6)
    {
        fd_server = anetTcp6Server(err_str,listen_port,listen_host,10);
    }
    else
    {
        fd_server = anetTcpServer(err_str,listen_port,listen_host,10);
    }

    if(-1 == fd_server)
    {
        mlogFatal(log,"main_server() anetTcpServer(%s:%d) error %s",listen_host,listen_port,err_str);

        return 1;
    }

    mlogInfo(log,"main_server() by_https listening %s:%d",listen_host,listen_port);

    signal(SIGINT, signal_handler);
    signal(SIGTERM,signal_handler);

    if(AE_OK == anetSSLServerInit(cert_public_path,cert_privite_path))
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

void get_current_dir(const char *exe_path,char *dir,int dir_len)
{
    char exe_path_[2048] = {0};
    char *tmp = NULL;

    //macOS 没有该目录.
    if(readlink("/proc/self/exe",exe_path_,2048) <= 0)
    {
        snprintf(exe_path_,2048,"%s",exe_path);
    }

    tmp = strrchr(exe_path_,'/');
    if(NULL != tmp)
    {
        tmp[0] = 0x00;
        tmp = strrchr(exe_path_,'/');
        if(NULL != tmp)
        {
            tmp[0] = 0x00;

            snprintf(dir,dir_len,"%s",exe_path_);
        }
    }
}
