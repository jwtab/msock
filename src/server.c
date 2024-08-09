
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

/*
*/
static void _server_closed_fds(struct aeEventLoop *eventLoop,server_node *node)
{
    mlogDebug((MLOG*)node->ref_log_ptr,"_server_closed_fds() client_fd %d,server_fd %d",node->fd_real_client,node->fd_real_server);

    mlogInfo((MLOG*)node->ref_log_ptr,"_server_closed_fds() upstreams %ld,downstreams %ld",node->upstream_byte,node->downstream_byte);
    
    aeDeleteFileEvent(eventLoop,node->fd_real_client,AE_READABLE);
    aeDeleteFileEvent(eventLoop,node->fd_real_server,AE_READABLE);

    serverNodeFree(node);
    node = NULL;
}

server_node *serverNodeNew()
{
    server_node * node = (server_node*)zmalloc(sizeof(server_node));
    if(node)
    {
        node->fd_real_client = -1;
        node->fd_real_server = -1;

        node->ssl = NULL;

        node->buf = sdsCreateEmpty(2048);
        node->req = httpRequestNew();

        node->upstream_byte = 0;
        node->downstream_byte = 0;

        node->ref_log_ptr = NULL;
    }

    return node;
}

void serverNodeFree(server_node *node)
{
    if(NULL != node) 
    {
        sdsRelease(node->buf);
        node->buf = NULL;

        if(NULL != node->ssl)
        {
            anetSSLClose(node->ssl);
            node->ssl = NULL;
        }
        
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

        httpRequestFree(node->req);
        node->req = NULL;

        zfree(node);
        node = NULL;
    }
}

void serverProc_Accept(struct aeEventLoop *eventLoop, int fd, void *clientData, int mask)
{
    char err_str[ANET_ERR_LEN] = {0};
    char ip[128] = {0};
    int port = 0;
    bool ssl_connected = false;

    MLOG *log = eventLoop->ref_log_ptr;

    server_node *node = serverNodeNew();
    if(NULL == node)
    {
        mlogError(log,"serverProc_Accept() serverNodeNew() error %s",err_str);
        return;
    }

    node->ref_log_ptr = log;

    node->fd_real_client = anetTcpAccept(err_str,fd,ip,128,&port);
    if(node->fd_real_client <= 0)
    {
        mlogError(log,"serverProc_Accept() anetTcpAccept() error %s",err_str);
    }
    else
    {
        mlogDebug(log,"serverProc_Accept() anetTcpAccept() %s:%d",ip,port);
        node->ssl = anetSSLAccept(err_str,node->fd_real_client);
        if(NULL != node->ssl)
        {
            mlogInfo(log,"serverProc_Accept() anetSSLAccept() from fd_(%s:%d) %s",ip,port,SSL_get_cipher(node->ssl));

            anetNonBlock(err_str,node->fd_real_client);
            anetRecvTimeout(err_str,node->fd_real_client,SOCKET_RECV_TIMEOUT);
            anetSendTimeout(err_str,node->fd_real_client,SOCKET_SEND_TIMEOUT);

            if(AE_OK == aeCreateFileEvent(eventLoop,node->fd_real_client,AE_READABLE,serverProc_Data,node))
            {
                ssl_connected = true;
            }
            else
            {
                mlogError(log,"serverProc_Accept() aeCreateFileEvent(%d) errno %d",node->fd_real_client,errno);
            }
        }
        else
        {
            mlogError(log,"serverProc_Accept() anetSSLAccept() error %s",err_str);
        }
    }

    if(!ssl_connected)
    {
        _server_closed_fds(eventLoop,node);
    }
}

void serverProc_real_Data(struct aeEventLoop *eventLoop, int fd, void *clientData, int mask)
{
    if(mask&AE_READABLE)
    {
        server_node *node = (server_node*)clientData;
        char buf[SEVER_BUF_SIZE] = {0};
        int len = 0;
        int ssl_sended = 0;

        len = anetRead(fd,buf,SEVER_BUF_SIZE);
        if(len > 0)
        {
            mlogDebug(node->ref_log_ptr,"serverProc_real_Data() anetRead(fd_%d) %d",fd,len);

            ssl_sended = ssrData_Response(node->ssl,buf,len);
            if(0 == ssl_sended && errno == EPIPE)
            {
                _server_closed_fds(eventLoop,node);
            }
            else
            {
                node->downstream_byte = node->downstream_byte + ssl_sended;
            }
        }
        else if (0 == len)
        {
            _server_closed_fds(eventLoop,node);
        }
    }
}

void serverProc_Data(struct aeEventLoop *eventLoop, int fd, void *clientData, int mask)
{
    char buf[SEVER_BUF_SIZE] = {0};
    int len = 0;
    server_node *node = (server_node*)clientData;
    http_status status = httpRequestStatusGet(node->req);

    if(mask&AE_READABLE)
    {
        len = anetSSLRead(node->ssl,buf,SEVER_BUF_SIZE);
        if(len > 0)
        {
            mlogDebug(node->ref_log_ptr,"serverProc_Data() anetSSLRead() len %d",len);

            node->upstream_byte = node->upstream_byte + len;

            if(HTTP_STATUS_HEAD_VERIFY == status ||
                HTTP_STATUS_HEAD_PARSE == status)
            {
                mlogTrace(node->ref_log_ptr,"serverProc_Data() http_request_recv{head} ...");

                sdsCatlen(node->buf,buf,len);
                if(httpHeadersOK(node->buf))
                {
                    mlogTrace(node->ref_log_ptr,"serverProc_Data() http_request_recv{head} OK");

                    httpRequestParse(node->buf,node->req);
                    
                    ///httpRequestPrint(node->req);

                    httpRequestStatusSet(node->req,HTTP_STATUS_BODY_RECV);

                    if(httpRequestBodyOK(node->req))
                    {
                        mlogTrace(node->ref_log_ptr,"serverProc_Data() http_request_recv{body} OK");

                        serverProc_fun(node,eventLoop);
                    }
                }
            }
            else if(HTTP_STATUS_BODY_RECV == status)
            {
                mlogTrace(node->ref_log_ptr,"serverProc_Data() http_request_recv{body} ...");

                sdsCatlen(node->req->body,buf,len);
                
                if(httpRequestBodyOK(node->req))
                {
                    mlogTrace(node->ref_log_ptr,"serverProc_Data() http_request_recv{body} OK");
                    
                    serverProc_fun(node,eventLoop);
                }
            }
        }
        else if(0 == len)
        {
            _server_closed_fds(eventLoop,node);
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

void serverProc_fun(server_node *node,struct aeEventLoop *eventLoop)
{
    int ssr_type = _ssr_ask_request_type(node->req);
    mlogDebug(node->ref_log_ptr,"serverProc_fun() ssr_type %d",ssr_type);

    switch(ssr_type)
    {
        case SSR_TYPE_AUTH:
        {
            server_Auth(node);
            break;
        }

        case SSR_TYPE_CONNECT:
        {
            server_Connect(node,eventLoop);
            break;
        }

        case SSR_TYPE_DATA:
        {
            server_Data(node);
            break;
        }

        default:
        {
            mlogError(node->ref_log_ptr,"serverProc_fun() hacker uri %s",httpRequestURI(node->req));
            server_send_fake_html(node);

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

void server_send_fake_html(server_node *node)
{
    char uuid[64] = {0};
    sds *fake_data = sdsCreateEmpty(1024);
    int nsened = 0;

    mlogUUID(uuid);

    sdsCatprintf(fake_data,"<h2>The page you are visiting does not exist. Please change other!</h2><br>Reference id:<b>%s</b>",uuid);
    nsened = ssrFake_html(node->ssl,sdsPTR(fake_data),sdsLength(fake_data));

    node->downstream_byte = node->downstream_byte + nsened;

    sdsRelease(fake_data);
    fake_data = NULL;
}

void server_Auth(server_node *node)
{
    char * response_data = "293c7166-1989-475f-b26a-6b589301ca88";
    int ssl_sended = 0;
    
    ssl_sended = ssrAuth_Response(node->ssl,response_data);
    node->downstream_byte = node->downstream_byte + ssl_sended;
}

void server_Connect(server_node *node,struct aeEventLoop *eventLoop)
{
    char err_str[ANET_ERR_LEN] = {0};
    bool connected = false;
    int ssl_sended = 0;
    
    //解析目标主机.
    char host[128] = {0};
    short port = 0;

    _server_parse_host(sdsPTR(node->req->body),node->req->body_len,host,&port);

    mlogInfo(node->ref_log_ptr,"server_Connect() try_to_connect %s:%d",host,port);

    node->fd_real_server = anetTcpNonBlockConnect(err_str,host,port);
    if(node->fd_real_server > 0)
    {
        mlogDebug(node->ref_log_ptr,"server_Connect() real_client_fd %d, real_server_fd %d",node->fd_real_client,node->fd_real_server);

        anetRecvTimeout(err_str,node->fd_real_server,SOCKET_RECV_TIMEOUT);
        anetSendTimeout(err_str,node->fd_real_server,SOCKET_SEND_TIMEOUT);
        
        if(AE_OK == aeCreateFileEvent(eventLoop,node->fd_real_server,AE_READABLE,serverProc_real_Data,node))
        {
            mlogInfo(node->ref_log_ptr,"server_Connect() connected_to %s:%d",host,port);

            connected = true;
        }
        else
        {
            mlogError(node->ref_log_ptr,"server_Connect() aeCreateFileEvent(%d) error %d",node->fd_real_server,errno);
        }
    }
    else
    {
        mlogError(node->ref_log_ptr,"server_Connect() anetTcpNonBlockConnect(%s:%d) error %s",host,port,err_str);
    }

    ssl_sended = ssrConnect_Response(node->ssl,connected);
    if(0 == ssl_sended && errno == EPIPE)
    {
        _server_closed_fds(eventLoop,node);
    }
    else
    {
        node->downstream_byte = node->downstream_byte + ssl_sended;
    }
}

void server_Data(server_node *node)
{
    int nsended = anetWrite(node->fd_real_server,sdsPTR(node->req->body),node->req->body_len);
    ///printf("server_Data() anetWrite(fd_%d) %d\r\n",node->fd_real_server,nsended);
    node->upstream_byte = node->upstream_byte + nsended;
}
