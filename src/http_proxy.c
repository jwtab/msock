
#include <unistd.h>
#include <errno.h>
#include <http_proxy.h>
#include <ssr.h>

#include <zmalloc.h>
#include <net_inc.h>
#include <net_main.h>
#include <mlog.h>

char HTTP_PROXY_STATUS_NAMES[HTTP_PROXY_STATUS_Max][64] = {
    "HTTP_CONNECT",
    "HTTP_RELAY",
};

/*
    CONNECT hostname:port HTTP/1.1 \r\n
*/
static void _httpProxy_real_destination(char * data,int buf_len,char *host,short *port)
{
    int start_pos = 0;
    int end_pos = 0;
    char value[64] = {0};

    start_pos = strlen(HTTP_PROXY_CONNECT);

    do
    {
        if(' ' != data[start_pos])
        {
            break;
        }
        else
        {
            start_pos++;
        }
    } while (1);
        
    end_pos = start_pos;
    do
    {
        if(':' == data[end_pos])
        {
            break;
        }
        else
        {
            end_pos++;
        }
    } while (1);

    memcpy(host,data + start_pos,end_pos - start_pos);

    start_pos = end_pos + 1;
    do
    {
        if(' ' == data[end_pos])
        {
            break;
        }
        else
        {
            end_pos++;
        }
    } while (1);

    memcpy(value,data + start_pos,end_pos - start_pos);

    *port = atoi(value);
}

/*
    ......
    Proxy-Authorization: Basic dXNlcm5hbWU6MTIzNDU2 \r\n
    ......
*/
static void _httpProxy_auth(char * data,int buf_len,char *username,char *password)
{
    int start_pos = 0;
    int end_pos = 0;
    char value[128] = {0};

    char *found = strstr(data,HTTP_HEADER_PROXY_AUTH);
    if(NULL == found)
    {
        ///printf("_httpProxy_auth() NO AUTH DATA\r\n");

        return;
    }

    start_pos = strlen(HTTP_HEADER_PROXY_AUTH) + 1;
    do
    {
        if(' ' != found[start_pos])
        {
            break;
        }
        else
        {
            start_pos++;
        }
    } while (1);
    
    end_pos = start_pos;
    do
    {
        if(' ' == found[end_pos])
        {
            break;
        }
        else
        {
            end_pos++;
        }
    } while (1);

    memcpy(value,found + start_pos,end_pos - start_pos);
    ///printf("_httpProxy_auth() type %s\r\n",value);

    start_pos = end_pos;
    do
    {
        if(' ' != found[start_pos])
        {
            break;
        }
        else
        {
            start_pos++;
        }
    } while (1);
    
    end_pos = start_pos;
    do
    {
        if('\r' == found[end_pos])
        {
            break;
        }
        else
        {
            end_pos++;
        }
    } while (1);

    memcpy(value,found + start_pos,end_pos - start_pos);
    ///printf("_httpProxy_auth() data %s\r\n",value);

    strcpy(username,"username");
    strcpy(password,"123456");
}

static void _httpProxy_closed_fds(struct aeEventLoop *eventLoop,http_fds *fds,bool by_client)
{
    mlogDebug((MLOG*)fds->ref_log_ptr,"_httpProxy_closed_fds() client_fd %d",fds->fd_client);

    if(by_client)
    {
        if(PROXY_TYPE_SSR == fds->proxy_type)
        {
            if(NULL != fds->ssr_conn_ptr)
            {
                ssrClientClose_Request(fds->ssr_conn_ptr->ssl);
                ssrConnectionUsedSet(fds->ssr_conn_ptr,false);
                aeDeleteFileEvent(eventLoop,fds->ssr_conn_ptr->fd_ssr_server,AE_READABLE);
            }
        }

        mlogInfo((MLOG*)fds->ref_log_ptr,"_httpProxy_closed_fds() client_first upstreams %ld,downstreams %ld",fds->upstream_byte,fds->downstream_byte);
    }
    else
    {
        if(PROXY_TYPE_SSR == fds->proxy_type)
        {
            if(NULL != fds->ssr_conn_ptr)
            {
                ssrConnectionUsedSet(fds->ssr_conn_ptr,false);
                aeDeleteFileEvent(eventLoop,fds->ssr_conn_ptr->fd_ssr_server,AE_READABLE);
            }
        }

        mlogInfo((MLOG*)fds->ref_log_ptr,"_httpProxy_closed_fds() server_first upstreams %ld,downstreams %ld",fds->upstream_byte,fds->downstream_byte);
    }
    
    aeDeleteFileEvent(eventLoop,fds->fd_client,AE_READABLE);
    
    if(PROXY_TYPE_LOCAL == fds->proxy_type)
    {
        aeDeleteFileEvent(eventLoop,fds->fd_local_server,AE_READABLE);
    }

    httpFDsFree(fds);
    fds = NULL;
}

char * httpProxyStatusName(int status)
{
    return HTTP_PROXY_STATUS_NAMES[status];
}

http_fds *httpFDsNew()
{
    http_fds *http = zmalloc(sizeof(http_fds));
    if(NULL != http)
    {
        memset(http,0,sizeof(http_fds));

        http->buf = sdsCreateEmpty(HTTP_PROXY_BUF_SIZE);
        http->res = httpResponseNew();

        http->fd_client = -1;
        http->fd_local_server = -1;

        http->ref_log_ptr = NULL;
        http->ssr_conn_ptr = NULL;

        #ifdef HTTP_PROXY_LOCAL
            http->proxy_type = PROXY_TYPE_LOCAL;
        #else
            http->proxy_type = PROXY_TYPE_SSR;
        #endif 
    }

    return http;
}

void httpFDsFree(http_fds *http)
{
    if(NULL != http)
    {
        if(NULL != http->res)
        {
            httpResponseFree(http->res);
            http->res = NULL;
        }

        if(NULL != http->buf)
        {
            sdsRelease(http->buf);
            http->buf = NULL;
        }

        if(http->fd_client > 0)
        {
            close(http->fd_client);
            http->fd_client = -1;
        }

        if(http->fd_local_server > 0)
        {
            close(http->fd_local_server);
            http->fd_local_server = -1;
        }

        zfree(http);
        http = NULL;
    }
}

/*
    CONNECT hostname:port HTTP/1.1 \r\n
    Host:hostname:port\r\n
    User-Agent:{UA}\r\n
    Proxy-Connection:...\r\n
    \r\n
*/
void httpCONNECT_Request(http_fds *http)
{
    if(0 == strncasecmp(HTTP_PROXY_CONNECT,sdsPTR(http->buf),strlen(HTTP_PROXY_CONNECT)))
    {
        _httpProxy_real_destination(sdsPTR(http->buf),sdsLength(http->buf),http->real_host,&http->real_port);
        
        mlogInfo(http->ref_log_ptr,"httpCONNECT_Request() web/app want_connect %s:%d",http->real_host,http->real_port);

        _httpProxy_auth(sdsPTR(http->buf),sdsLength(http->buf),http->username,http->password);
        if(0 != strlen(http->username) || 0 != strlen(http->password))
        {
            mlogError(http->ref_log_ptr,"httpCONNECT_Request() AUTH %s:%s",http->username,http->password);
        }
    }
    else
    {
        http->real_port = 0;

        mlogError(http->ref_log_ptr,"httpCONNECT_Request() NOT_CONNECT_DATA buf %s",sdsPTR(http->buf));
    }
}

/*
    HTTP/1.1 200 Connection Established\r\n\r\n
*/
void httpCONNECT_Response(struct aeEventLoop *eventLoop,http_fds *http)
{
    sdsEmpty(http->buf);

    //判断hostname走ssr还是本地直接连接.

    if(PROXY_TYPE_LOCAL == http->proxy_type)
    {
        HttpCONNECT_Response_local(eventLoop,http);
    }
    else if(PROXY_TYPE_SSR == http->proxy_type)
    {
        HttpCONNECT_Remote_ssr(eventLoop,http);
    }
    else
    {

    }
}

bool HttpCONNECT_Response_local(struct aeEventLoop *eventLoop,http_fds *http)
{
    char err_str[ANET_ERR_LEN] = {0};

    http->fd_local_server = anetTcpNonBlockConnect(err_str,http->real_host,http->real_port);
    if(http->fd_local_server > 0)
    {
        anetNonBlock(err_str,http->fd_local_server);

        anetRecvTimeout(err_str,http->fd_local_server,SOCKET_RECV_TIMEOUT);
        anetSendTimeout(err_str,http->fd_local_server,SOCKET_SEND_TIMEOUT);

        mlogDebug(http->ref_log_ptr,"HttpCONNECT_Response_local() real_client_fd %d,real_server_fd %d",http->fd_local_server,http->fd_local_server);

        if(AE_OK == aeCreateFileEvent(eventLoop,http->fd_local_server,AE_READABLE,httpProxy_proxy,http))
        {
            mlogInfo(http->ref_log_ptr,"HttpCONNECT_Response_local() connected %s:%d",http->real_host,http->real_port);
        }
        else
        {
            mlogError(http->ref_log_ptr,"HttpCONNECT_Response_local() aeCreateFileEvent(%d) error %d",http->fd_local_server,errno);
        }

        sdsCat(http->buf,HTTP_PROXY_RET_200);
        sdsCat(http->buf,HTTP_PROXY_BODY_END);
    }
    else
    {
        sdsCat(http->buf,HTTP_PROXY_RET_502);
        sdsCat(http->buf,HTTP_PROXY_BODY_END);

        mlogError(http->ref_log_ptr,"HttpCONNECT_Response_local() anetTcpNonBlockConnect(%s:%d) error %s",SSR_HOST,SSR_PORT,err_str);
    }
    
    http->status = HTTP_PROXY_STATUS_RELAY;
    anetWrite(http->fd_client,sdsPTR(http->buf),sdsLength(http->buf));

    return true;
}

bool HttpCONNECT_Remote_ssr(struct aeEventLoop *eventLoop,http_fds *http)
{
    char err_str[ANET_ERR_LEN] = {0};
    bool connected_ssr = true;

    http->ssr_conn_ptr = ssrConnectionListGet();
    if(NULL != http->ssr_conn_ptr)
    {
        anetNonBlock(err_str,http->ssr_conn_ptr->fd_ssr_server);
        anetRecvTimeout(err_str,http->ssr_conn_ptr->fd_ssr_server,SOCKET_RECV_TIMEOUT);
        anetSendTimeout(err_str,http->ssr_conn_ptr->fd_ssr_server,SOCKET_SEND_TIMEOUT);

        mlogDebug(http->ref_log_ptr,"HttpCONNECT_Remote_ssr() real_client_fd %d,real_server_fd %d",http->fd_client,http->ssr_conn_ptr->fd_ssr_server);

        if(AE_OK == aeCreateFileEvent(eventLoop,http->ssr_conn_ptr->fd_ssr_server,AE_READABLE,httpProxy_ssr,http))
        {
            mlogInfo(http->ref_log_ptr,"HttpCONNECT_Remote_ssr() use_ssr_conn %d/%d",http->ssr_conn_ptr->seq,ssrConnectionListSize());
            
            ssrConnectionUsedSet(http->ssr_conn_ptr,true);

            ssrConnect_Request(http->ssr_conn_ptr->ssl,http->real_host,http->real_port);
        }
        else
        {
            connected_ssr = false;
        }
    }
    else
    {
        mlogError(http->ref_log_ptr,"HttpCONNECT_Remote_ssr() ssrConnectionListGet() error!");
    }

    if(!connected_ssr)
    {
        sdsEmpty(http->buf);

        sdsCat(http->buf,HTTP_PROXY_RET_502);
        sdsCat(http->buf,HTTP_PROXY_BODY_END);

        http->status = HTTP_PROXY_STATUS_RELAY;
        anetWrite(http->fd_client,sdsPTR(http->buf),sdsLength(http->buf));
    }

    return true;
}

void httpRelay_local(struct aeEventLoop *eventLoop,int fd,http_fds *http)
{
    int fd_read = fd;
    int fd_write = 0;
    int nsended = 0;
    int upstream = 0;
    int len = 0;
    char buf[HTTP_PROXY_BUF_SIZE] = {0};

    if(fd_read == http->fd_client)
    {
        upstream = 1;
        fd_write = http->fd_local_server;
    }
    else
    {
        upstream = 0;
        fd_write = http->fd_client;
    }

    len = anetRead(fd_read,buf,HTTP_PROXY_BUF_SIZE);
    if(len > 0)
    {
        mlogDebug(http->ref_log_ptr,"httpRelay_local() anetRead(fd_[%d]) len %d",fd_read,len);

        nsended = anetWrite(fd_write,buf,len);
        if(len != nsended)
        {
            mlogError(http->ref_log_ptr,"httpRelay_local() anetWrite(fd_[%d]) want_write %d,writed_len %d,errno %d",fd_write,len,nsended,errno);
        }
        else
        {
            ///printf("httpRelay_local() wirte(fd_[%d]) len %d\r\n",fd_write,http->buf_len);
        }

        if(upstream > 0)
        {
            http->upstream_byte = http->upstream_byte + nsended;
        }
        else
        {
            http->downstream_byte = http->downstream_byte + nsended;
        }
    }
    else
    {
        if(0 == len)
        {
            _httpProxy_closed_fds(eventLoop,http,upstream);
        }  
    }
}

void httpRelay_ssr(struct aeEventLoop *eventLoop,http_fds *http)
{
    char buf[HTTP_PROXY_BUF_SIZE] = {0};
    int len = 0;

    len = anetRead(http->fd_client,buf,HTTP_PROXY_BUF_SIZE);
    if(len > 0)
    {
        mlogDebug(http->ref_log_ptr,"httpRelay_ssr() anetRead(fd_[%d]) len %d",http->fd_client,len);

        len = ssrData_Request(http->ssr_conn_ptr->ssl,buf,len);
        http->upstream_byte =  http->upstream_byte + len;
    }
    else if(0 == len)
    {
        _httpProxy_closed_fds(eventLoop,http,true);
    }
}

void httpProxy_accept(struct aeEventLoop *eventLoop, int fd, void *clientData, int mask)
{
    char err_str[ANET_ERR_LEN] = {0};
    char ip[128] = {0};
    int port = 0;
    bool connected = false;
    MLOG *log = (MLOG*)eventLoop->ref_log_ptr;

    //增加数据处理函数.
    http_fds *http = httpFDsNew();
    if(NULL == http)
    {
        mlogError(log,"httpProxy_accept() httpFDsNew() error %d",errno);
        return;
    }
    
    http->ref_log_ptr = log;

    http->fd_client = anetTcpAccept(err_str,fd,ip,128,&port);
    if(http->fd_client <= 0)
    {
        mlogError(log,"httpProxy_accept() anetTcpAccept() error %s",err_str);
        return;
    }
    else
    {
        http->status = HTTP_PROXY_STATUS_CONNECT;

        anetNonBlock(err_str,http->fd_client);
        
        anetRecvTimeout(err_str,http->fd_client,SOCKET_RECV_TIMEOUT);
        anetSendTimeout(err_str,http->fd_client,SOCKET_SEND_TIMEOUT);

        if(AE_OK == aeCreateFileEvent(eventLoop,http->fd_client,AE_READABLE,httpProxy_proxy,http))
        {
            mlogInfo(log,"httpProxy_accept() anetTcpAccept() from fd_(%s:%d) OK",ip,port);

            connected = true;
        }
        else
        {
            mlogError(log,"httpProxy_accept() aeCreateFileEvent(%d) fd_(%s:%d) errno %d",http->fd_client,ip,port,errno);
        }
    }
    
    if(!connected)
    {
        _httpProxy_closed_fds(eventLoop,http,false);
    }
}

void httpProxy_proxy(struct aeEventLoop *eventLoop, int fd, void *clientData, int mask)
{
    char buf[HTTP_PROXY_BUF_SIZE] = {0};
    int len = 0;

    http_fds *http = (http_fds*)clientData;
    if(mask&AE_READABLE)
    {
        if(HTTP_PROXY_STATUS_CONNECT == http->status)
        {
            len = anetRead(fd,buf,HTTP_PROXY_BUF_SIZE);
            if(len >= 2)
            {
                mlogDebug(http->ref_log_ptr,"httpProxy_proxy() HTTP_PROXY_STATUS_CONNECT anetRead(fd_[%d]) len %d",fd,len);

                sdsCatlen(http->buf,buf,len);
                httpCONNECT_Request(http);
                if(0 == http->real_port)
                {
                    http->status = HTTP_PROXY_STATUS_RELAY;
                }
                else
                {
                    httpCONNECT_Response(eventLoop,http);
                }
            }
            else if(0 == len)
            {
                _httpProxy_closed_fds(eventLoop,http,true);
            }
        }
        else if(HTTP_PROXY_STATUS_RELAY == http->status)
        {
            if(PROXY_TYPE_LOCAL == http->proxy_type)
            {
                httpRelay_local(eventLoop,fd,http);
            }
            else if(PROXY_TYPE_SSR == http->proxy_type)
            {
                httpRelay_ssr(eventLoop,http);
            }
            else
            {
                
            }
        }
    }
}

void httpProxy_ssr(struct aeEventLoop *eventLoop, int fd, void *clientData, int mask)
{
    http_fds * http = (http_fds*)clientData;
    http_status status = httpResponseStatusGet(http->res);
    char buf[HTTP_PROXY_BUF_SIZE] = {0};
    int len = 0;

    if(mask&AE_READABLE)
    {
        len = anetSSLRead(http->ssr_conn_ptr->ssl,buf,HTTP_PROXY_BUF_SIZE);
        if(len > 0)
        {
            mlogDebug(http->ref_log_ptr,"httpProxy_ssr() anetSSLRead() %d",len);

            if(HTTP_STATUS_HEAD_VERIFY == status ||
                HTTP_STATUS_HEAD_PARSE == status)
            {
                mlogTrace(http->ref_log_ptr,"httpProxy_ssr() http_response_recv{head} ...");

                sdsCatlen(http->buf,buf,len);
                if(httpHeadersOK(http->buf))
                {
                    mlogTrace(http->ref_log_ptr,"httpProxy_ssr() http_response_recv{head} OK");
                    
                    httpResponseParse(http->buf,http->res);
                    
                    ///httpResponsePrint(http->res);

                    httpResponseStatusSet(http->res,HTTP_STATUS_BODY_RECV);

                    if(httpResponseBodyOK(http->res))
                    {
                        mlogTrace(http->ref_log_ptr,"httpProxy_ssr() http_response_recv{body} OK");

                        proxyProc_fun(http,eventLoop);
                    }
                }
            }
            else if(HTTP_STATUS_BODY_RECV == status)
            {
                mlogTrace(http->ref_log_ptr,"httpProxy_ssr() http_request_recv{body} ...");

                sdsCatlen(http->res->body,buf,len);
                
                if(httpResponseBodyOK(http->res))
                {
                    mlogTrace(http->ref_log_ptr,"httpProxy_ssr() http_response_recv{body} OK");

                    proxyProc_fun(http,eventLoop);
                }
            }
        }
        else if(0 == len)
        {
            _httpProxy_closed_fds(eventLoop,http,false);
        }
    }
}

void proxyProc_fun(http_fds *node,struct aeEventLoop *eventLoop)
{
    int len = 0;

    int ssr_type = ssrResponseType(node->res);
    mlogDebug(node->ref_log_ptr,"proxyProc_fun() ssr_type %d",ssr_type);

    switch(ssr_type)
    {
        case SSR_TYPE_AUTH:
        {
            break;
        }

        case SSR_TYPE_CONNECT:
        {
            sdsEmpty(node->buf);
            sdsCat(node->buf,HTTP_PROXY_RET_200);
            sdsCat(node->buf,HTTP_PROXY_BODY_END);
    
            node->status = HTTP_PROXY_STATUS_RELAY;
            len = anetWrite(node->fd_client,sdsPTR(node->buf),sdsLength(node->buf));
            node->downstream_byte = node->downstream_byte + len;

            break;
        }

        case SSR_TYPE_DATA:
        {
            len = anetWrite(node->fd_client,sdsPTR(node->res->body),sdsLength(node->res->body));
            node->downstream_byte = node->downstream_byte + len;

            break;
        }

        case SSR_TYPE_CLIENT_CLOSE:
        {
            mlogInfo(node->ref_log_ptr,"serverProc_fun() client_close fired_by_remote_server");
            _httpProxy_closed_fds(eventLoop,node,false);

            break;
        }
        
        default:
        {
            mlogError(node->ref_log_ptr,"serverProc_fun() hacker Response");
            break;
        }
    }
    
    sdsEmpty(node->buf);

    httpResponseEmpty(node->res);
    httpResponseStatusSet(node->res,HTTP_STATUS_HEAD_VERIFY);
}
