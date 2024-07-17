
#include <unistd.h>
#include <server.h>

#include <zmalloc.h>

sever_node *serverNodeNew()
{
    sever_node * node = (sever_node*)zmalloc(sizeof(sever_node));
    if(node)
    {
        node->fd = -1;
        node->ssl = NULL;

        node->buf = sdsCreateEmpty(1024);
    }

    return node;
}

void serverNodeFree(sever_node *node)
{
    if(NULL != node) 
    {
        sdsRelease(node->buf);
        node->buf = NULL;

        close(node->fd);

        anetSSLClose(node->ssl);
    }
}

void serverProc_Accept(struct aeEventLoop *eventLoop, int fd, void *clientData, int mask)
{
    char err_str[ANET_ERR_LEN] = {0};
    char ip[128] = {0};
    int port = 0;
    int fd_client = -1;
    
    fd_client = anetTcpAccept(err_str,fd,ip,128,&port);
    if(fd_client <= 0)
    {
        printf("serverProc_Accept() anetTcpAccept() error %s\r\n",err_str);
        return;
    }

    printf("serverProc_Accept() anetTcpAccept() OK %s:%d \r\n",ip,port);

    sever_node *node = serverNodeNew();
    node->ssl = anetSSLAccept(err_str,fd_client);
    node->fd = fd_client;
    
    if(NULL == node->ssl)
    {
        printf("serverProc_Accept() anetSSLAccept() error %s\r\n",err_str);
        return;
    }
    else
    {
        printf("serverProc_Accept() anetSSLAccept() OK %s by fd_%d \r\n",SSL_get_cipher(node->ssl),fd_client);
    }

    anetRecvTimeout(err_str,fd_client,SOCKET_RECV_TIMEOUT);
    anetSendTimeout(err_str,fd_client,SOCKET_SEND_TIMEOUT);

    if(AE_OK != aeCreateFileEvent(eventLoop,fd_client,AE_READABLE|AE_WRITABLE,serverProc_Data,node))
    {
        printf("serverProc_Accept() aeCreateFileEvent(%d) errno %d\r\n",fd_client,errno);
    }
}

void serverProc_Data(struct aeEventLoop *eventLoop, int fd, void *clientData, int mask)
{
    char buf[2048] = {0};
    int len = 0;
    sever_node *node = (sever_node*)clientData;

    if(mask&AE_READABLE)
    {       
        len = anetSSLRead(node->ssl,buf,2048);
        if(len > 0)
        {
            sdsCatlen(node->buf,buf,len);
        }
        else if(0 == len)
        {
            printf("serverProc_Data() fd_%d closed\r\n",node->fd);
            serverNodeFree(node);
        }
    }
    else if(mask&AE_WRITABLE)
    {

    }
}
