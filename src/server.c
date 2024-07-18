
#include <unistd.h>
#include <server.h>
#include <ssr.h>

#include <zmalloc.h>

sever_node *serverNodeNew()
{
    sever_node * node = (sever_node*)zmalloc(sizeof(sever_node));
    if(node)
    {
        node->fd_real_client = -1;
        node->fd_real_server = -1;

        node->ssl = NULL;

        node->buf = sdsCreateEmpty(1024);
        node->req = httpRequestNew();
    }

    return node;
}

void serverNodeFree(sever_node *node)
{
    if(NULL != node) 
    {
        sdsRelease(node->buf);
        node->buf = NULL;

        if(node->fd_real_client > 0)
        {
            close(node->fd_real_client);
            node->fd_real_client = -1;
        }

        if(node->fd_real_server > 0)
        {
            close(node->fd_real_server);
            node->fd_real_server = -1;
        }

        anetSSLClose(node->ssl);

        httpRequestFree(node->req);
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
    node->fd_real_client = fd_client;
    
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

void serverProc_real_Data(struct aeEventLoop *eventLoop, int fd, void *clientData, int mask)
{
    if(mask&AE_READABLE)
    {
        sever_node *node = (sever_node*)clientData;
        char buf[2048] = {0};
        int len = 0;

        len = anetRead(node->fd_real_server,buf,2048);
        if(len > 0)
        {

        }
        else if (0 == len)
        {
            printf("serverProc_real_Data() fd_%d closed\r\n",node->fd_real_server);
        }
    }
}

void serverProc_Data(struct aeEventLoop *eventLoop, int fd, void *clientData, int mask)
{
    char buf[2048] = {0};
    int len = 0;
    sever_node *node = (sever_node*)clientData;
    http_status status = httpRequestStatusGet(node->req);

    if(mask&AE_READABLE)
    {
        len = anetSSLRead(node->ssl,buf,2048);
        if(len > 0)
        {
            if(HTTP_STATUS_HEAD_VERIFY == status ||
                HTTP_STATUS_HEAD_PARSE == status)
            {
                printf("serverProc_Data() http_request_recv{head} ...\r\n");

                sdsCatlen(node->buf,buf,len);
                if(httpHeadersOK(node->buf))
                {
                    printf("serverProc_Data() http_request_recv{head} OK\r\n");

                    httpRequestParse(node->buf,node->req);
                    
                    //httpRequestPrint(node->req);

                    httpRequestStatusSet(node->req,HTTP_STATUS_BODY_RECV);

                    if(httpRequestBodyOK(node->req))
                    {
                        printf("serverProc_Data() http_request_recv{body} OK\r\n");
                        serverProc_fun(node);
                    }
                }
            }
            else if(HTTP_STATUS_BODY_RECV == status)
            {
                printf("serverProc_Data() http_request_recv{body} ...\r\n");
                sdsCatlen(node->req->body,buf,len);
                
                if(httpRequestBodyOK(node->req))
                {
                    printf("serverProc_Data() http_request_recv{body} OK\r\n");
                    serverProc_fun(node);
                }
            }
        }
        else if(0 == len)
        {
            printf("serverProc_Data() fd_%d closed\r\n",node->fd_real_client);
            aeDeleteFileEvent(eventLoop,node->fd_real_client,AE_READABLE|AE_WRITABLE);

            serverNodeFree(node);
        }
    }
    else if(mask&AE_WRITABLE)
    {

    }
}

int _ssr_ask_type(http_request *req)
{
    int ask_type = -1;

    //判断uri
    if(0 != strcasecmp(SSR_URL,sdsPTR(req->uri)))
    {
        return ask_type;
    }

    listNode *node = listFirst(req->header_list);
    while(NULL != node)
    {
        http_header *h = (http_header*)node->value;
        if(0 == strcasecmp(sdsPTR(h->key),SSR_HEADER_TYPE))
        {
            return atoi(sdsPTR(h->value));
        }

        node = listNextNode(node);
    }

    return ask_type;
}

void serverProc_fun(sever_node *node)
{
    int ssr_type = _ssr_ask_type(node->req);

    switch(ssr_type)
    {
        case SSR_TYPE_AUTH:
        {
            printf("serverProc_fun() SSR_TYPE_AUTH\r\n");
            server_Auth(node);
            break;
        }

        case SSR_TYPE_CONNECT:
        {
            printf("serverProc_fun() SSR_TYPE_CONNECT\r\n");
            server_Connect(node);
            break;
        }

        case SSR_TYPE_DATA:
        {
            printf("serverProc_fun() SSR_TYPE_DATA\r\n");
            break;
        }

        default:
        {
            printf("serverProc_fun() hacker\r\n");
            break;
        }
    }
}

void server_Auth(sever_node *node)
{
    char * response_data = "293c7166-1989-475f-b26a-6b589301ca88";

    ssrAuth_Response(node->ssl,response_data);
}

void server_Connect(sever_node *node)
{
    //解析目标主机.
    char host[128] = {0};
    short port = 0;

    ssrConnect_Response(node->ssl,true);
}

void server_Data(sever_node *node)
{
    int nsended = anetWrite(node->fd_real_server,sdsPTR(node->req->body),node->req->body_len);
    printf("server_Data() anetWrite(%d) %d\r\n",node->fd_real_server,nsended);
}
