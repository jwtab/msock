
#include <unistd.h>
#include <server.h>
#include <ssr.h>
#include <mlog.h>

#include <zmalloc.h>

/*
    h=xxx&p=443
*/
static void _server_parse_host(const char *str,int len,char *host,short *port)
{
    int pos = 0;
    char *port_str = NULL;

    if(0 != memcmp("h=",str,2))
    {   
        return;
    }

    while('&' != str[pos])
    {
        pos++;
    }

    //host
    memcpy(host,str + 2,pos - 2);
    port_str = strstr(str,"p=");
    if(NULL != port_str)
    {
        port_str++;
        port_str++;

        *port = atoi(port_str);
    }
}

sever_node *serverNodeNew()
{
    sever_node * node = (sever_node*)zmalloc(sizeof(sever_node));
    if(node)
    {
        node->fd_real_client = -1;
        node->fd_real_server = -1;

        node->ssl = NULL;

        node->buf = sdsCreateEmpty(2048);
        node->req = httpRequestNew();

        node->upstream_byte = 0;
        node->downstream_byte = 0;
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
    
    sever_node *node = serverNodeNew();

    node->fd_real_client = anetTcpAccept(err_str,fd,ip,128,&port);
    if(node->fd_real_client <= 0)
    {
        printf("serverProc_Accept() anetTcpAccept() error %s\r\n",err_str);
        return;
    }

    ///printf("serverProc_Accept() anetTcpAccept() %s:%d \r\n",ip,port);
    
    node->ssl = anetSSLAccept(err_str,node->fd_real_client);
    if(NULL == node->ssl)
    {
        printf("serverProc_Accept() anetSSLAccept() error %s\r\n",err_str);
        return;
    }
    else
    {
        ///printf("serverProc_Accept() anetSSLAccept() OK %s by fd_%d \r\n",SSL_get_cipher(node->ssl),node->fd_real_client);
    }

    anetRecvTimeout(err_str,node->fd_real_client,SOCKET_RECV_TIMEOUT);
    anetSendTimeout(err_str,node->fd_real_client,SOCKET_SEND_TIMEOUT);

    if(AE_OK != aeCreateFileEvent(eventLoop,node->fd_real_client,AE_READABLE,serverProc_Data,node))
    {
        printf("serverProc_Accept() aeCreateFileEvent(%d) errno %d\r\n",node->fd_real_client,errno);
    }
}

void serverProc_real_Data(struct aeEventLoop *eventLoop, int fd, void *clientData, int mask)
{
    if(mask&AE_READABLE)
    {
        sever_node *node = (sever_node*)clientData;
        char buf[8192] = {0};
        int len = 0;
        int ssl_sended = 0;

        len = anetRead(node->fd_real_server,buf,8192);
        if(len > 0)
        {
            ///printf("serverProc_real_Data() anetRead(fd_%d) %d\r\n",node->fd_real_server,len);
            ssl_sended = ssrData_Response(node->ssl,buf,len);
            node->downstream_byte = node->downstream_byte + ssl_sended;
        }
        else if (0 == len)
        {
            printf("serverProc_real_Data() ms_%ld fd_%d closed\r\n",mlogTick_ms(),node->fd_real_server);
            
            aeDeleteFileEvent(eventLoop,node->fd_real_client,AE_READABLE);
            aeDeleteFileEvent(eventLoop,node->fd_real_server,AE_READABLE);

            serverNodeFree(node);
            node = NULL;
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
            node->upstream_byte = node->upstream_byte + len;

            if(HTTP_STATUS_HEAD_VERIFY == status ||
                HTTP_STATUS_HEAD_PARSE == status)
            {
                ///printf("serverProc_Data() http_request_recv{head} ...\r\n");

                sdsCatlen(node->buf,buf,len);
                if(httpHeadersOK(node->buf))
                {
                    ///printf("serverProc_Data() http_request_recv{head} OK\r\n");

                    httpRequestParse(node->buf,node->req);
                    
                    ///httpRequestPrint(node->req);

                    httpRequestStatusSet(node->req,HTTP_STATUS_BODY_RECV);

                    if(httpRequestBodyOK(node->req))
                    {
                        ///printf("serverProc_Data() http_request_recv{body} OK\r\n");
                        serverProc_fun(node,eventLoop);
                    }
                }
            }
            else if(HTTP_STATUS_BODY_RECV == status)
            {
                ///printf("serverProc_Data() http_request_recv{body} ...\r\n");
                sdsCatlen(node->req->body,buf,len);
                
                if(httpRequestBodyOK(node->req))
                {
                    ///printf("serverProc_Data() http_request_recv{body} OK\r\n");
                    serverProc_fun(node,eventLoop);
                }
            }
        }
        else if(0 == len)
        {
            printf("serverProc_Data() ms_%ld fd_%d closed\r\n",mlogTick_ms(),node->fd_real_client);
            
            aeDeleteFileEvent(eventLoop,node->fd_real_client,AE_READABLE);
            aeDeleteFileEvent(eventLoop,node->fd_real_server,AE_READABLE);

            serverNodeFree(node);
            node = NULL;
        }
    }
    else if(mask&AE_WRITABLE)
    {

    }
}

int _ssr_ask_request_type(http_request *req)
{
    int ask_type = -1;
    char * host_name = httpGetHostNameValue(req->header_list);
    
    if(0 != strcasecmp(host_name,SSR_HEAD_HOST))
    {
        return ask_type;
    }

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

void serverProc_fun(sever_node *node,struct aeEventLoop *eventLoop)
{
    int ssr_type = _ssr_ask_request_type(node->req);
    switch(ssr_type)
    {
        case SSR_TYPE_AUTH:
        {
            ///printf("serverProc_fun() SSR_TYPE_AUTH\r\n");
            server_Auth(node);
            break;
        }

        case SSR_TYPE_CONNECT:
        {
            ///printf("serverProc_fun() SSR_TYPE_CONNECT\r\n");
            server_Connect(node,eventLoop);
            break;
        }

        case SSR_TYPE_DATA:
        {
            ///printf("serverProc_fun() SSR_TYPE_DATA\r\n");
            server_Data(node);
            break;
        }

        default:
        {
            ///printf("serverProc_fun() hacker\r\n");
            server_send_fake_html(node->ssl);

            break;
        }
    }

    sdsEmpty(node->buf);
    httpRequestStatusSet(node->req,HTTP_STATUS_HEAD_VERIFY);

    listEmpty(node->req->header_list);

    sdsEmpty(node->req->uri);
    sdsEmpty(node->req->method);
    sdsEmpty(node->req->versions);
}

void server_send_fake_html(SSL *ssl)
{
    char uuid[64] = {0};
    sds *fake_data = sdsCreateEmpty(1024);

    mlogUUID(uuid);

    sdsCatprintf(fake_data,"<h2>The page you are visiting does not exist. Please change other!</h2><br>Reference id:<b>%s</b>",uuid);
    ssrFake_html(ssl,sdsPTR(fake_data),sdsLength(fake_data));

    sdsRelease(fake_data);
    fake_data = NULL;
}

void server_Auth(sever_node *node)
{
    char * response_data = "293c7166-1989-475f-b26a-6b589301ca88";
    int ssl_sended = 0;
    
    ssl_sended = ssrAuth_Response(node->ssl,response_data);
    node->downstream_byte = node->downstream_byte + ssl_sended;
}

void server_Connect(sever_node *node,struct aeEventLoop *eventLoop)
{
    char err_str[ANET_ERR_LEN] = {0};
    bool connected = false;
    int ssl_sended = 0;
    
    //解析目标主机.
    char host[128] = {0};
    short port = 0;

    _server_parse_host(sdsPTR(node->req->body),node->req->body_len,host,&port);

    printf("server_Connect() ms_%ld try to connect %s:%d\r\n",mlogTick_ms(),host,port);
    node->fd_real_server = anetTcpNonBlockConnect(err_str,host,port);
    if(node->fd_real_server > 0)
    {
        anetRecvTimeout(err_str,node->fd_real_server,SOCKET_RECV_TIMEOUT);
        anetSendTimeout(err_str,node->fd_real_server,SOCKET_SEND_TIMEOUT);

        ///printf("server_Connect() real_client_fd %d\r\n",node->fd_real_client);
        ///printf("server_Connect() real_server_fd %d\r\n",node->fd_real_server);

        if(AE_OK == aeCreateFileEvent(eventLoop,node->fd_real_server,AE_READABLE,serverProc_real_Data,node))
        {
            connected = true;
        }
        else
        {
            printf("server_Connect() aeCreateFileEvent(%d) error %d\r\n",node->fd_real_server,errno);
        }
    }
    else
    {
        printf("server_Connect() anetTcpNonBlockConnect(%s:%d) error %s\r\n",host,port,err_str);
    }

    ssl_sended = ssrConnect_Response(node->ssl,connected);
    node->downstream_byte = node->downstream_byte + ssl_sended;
}

void server_Data(sever_node *node)
{
    int nsended = anetWrite(node->fd_real_server,sdsPTR(node->req->body),node->req->body_len);
    ///printf("server_Data() anetWrite(fd_%d) %d\r\n",node->fd_real_server,nsended);
}
