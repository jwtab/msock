
#include <unistd.h>
#include <errno.h>

#include <zmalloc.h>
#include <net_main.h>

#include <socks.h>
#include <ssr.h>
#include <mlog.h>

char S5_STATUS_NAMES[SOCKS_STATUS_Max][64] = {
    "SOCKS5_HANDSHAKE_1",
    "SOCKS5_HANDSHAKE_2",
    "SOCKS5_REQUEST",
    "SOCKS5_RELAY"
};

char S5_AUTH_NAMES[S5_AUTH_Max][64] = {
    "SOCKS5_AUTH_Empty",
    "SOCKS5_AUTH_GSSAPI",
    "SOCKS5_AUTH_Username/Password"
};

static void _socksProxy_fds_closed(struct aeEventLoop *eventLoop,s5_fds *s5)
{
    mlogDebug((MLOG*)s5->ref_log_ptr,"_server_closed_fds() client_fd %d,server_fd %d",s5->fd_real_client,s5->fd_real_server);

    mlogInfo((MLOG*)s5->ref_log_ptr,"_server_closed_fds() upstreams %ld,downstreams %ld",s5->upstream_byte,s5->downstream_byte);
    
    aeDeleteFileEvent(eventLoop,s5->fd_real_client,AE_READABLE);
    aeDeleteFileEvent(eventLoop,s5->fd_real_server,AE_READABLE);

    s5FDsFree(s5);
    s5 = NULL;
}

s5_fds *s5FDsNew()
{
    s5_fds *s5 = zmalloc(sizeof(s5_fds));
    if(NULL != s5)
    {
        memset(s5,0,sizeof(s5_fds));

        s5->buf = sdsCreateEmpty(2048);

        s5->ssl = NULL;

        s5->res = httpResponseNew();

        #ifdef SOCK_PROXY_LOCAL
            s5->proxy_type = PROXY_TYPE_LOCAL;
        #else
            s5->proxy_type = PROXY_TYPE_SSR;
        #endif
    }
    
    return s5;
}

void s5FDsFree(s5_fds *s5)
{
    if(NULL != s5)
    {
        if(s5->fd_real_client > 0)
        {
            close(s5->fd_real_client);
            s5->fd_real_client = -1;
        }

        if(s5->fd_real_server > 0)
        {
            close(s5->fd_real_server);
            s5->fd_real_server = -1;
        }

        sdsRelease(s5->buf);
        s5->buf = NULL;

        sdsRelease(s5->buf_dup);
        s5->buf_dup = NULL;

        httpResponseFree(s5->res);
        s5->res = NULL;

        zfree(s5);
        s5 = NULL;
    }
}

char * s5StatusName(int status)
{
    return S5_STATUS_NAMES[status];
}

char * s5AuthTypeName(int auth_type)
{
    return S5_AUTH_NAMES[auth_type];
}

/*
    +----+----------+----------+
    |VER | NMETHODS | METHODS  |
    +----+----------+----------+
    | 1  |    1     | 1 to 255 |
    +----+----------+----------+

    +----+--------+
    |VER | METHOD |
    +----+--------+
    | 1  |   1    |
    +----+--------+
*/

void s5ClientMethods_Request(s5_fds *s5)
{
    char * data = sdsPTR(s5->buf);
    int nMethods = 0;
    int pos = 2;

    if(sdsLength(s5->buf) >= 2)
    {
        s5->client_version = data[0];
        mlogTrace(s5->ref_log_ptr,"s5ClientMethods_Request socks_version is %d",(int)s5->client_version);
    }

    if(SOCKS_VERSION_5 == s5->client_version)
    {
        nMethods = data[1];
        mlogDebug(s5->ref_log_ptr,"s5ClientMethods_Request count is %d",nMethods);

        while(nMethods)
        {
            mlogTrace(s5->ref_log_ptr,"s5ClientMethods_Request is %d",(int)data[pos]);

            pos++;
            nMethods--;
        }
    }
}

void s5ClientMethods_Response(s5_fds *s5)
{
    char res_data[3] = {0};

    if(SOCKS_VERSION_5 == (int)s5->client_version)
    {
        /*
        s5->buf[1] = S5_AUTH_USERNAME_PASSWORD;
        s5->auth_type = S5_AUTH_USERNAME_PASSWORD;

        s5->status = S5_STATUS_HANDSHAKE_2;
        */
        res_data[0] = sdsChar(s5->buf,0);
        res_data[1] = S5_AUTH_NONE;
        s5->auth_type = S5_AUTH_NONE;

        s5->status = SOCKS_STATUS_REQUEST;
    }
    else
    {
        res_data[1] = 0xFF;
    }

    anetWrite(s5->fd_real_client,res_data,2);

    mlogDebug(s5->ref_log_ptr,"s5ClientMethods_Response() auth_type %s",s5AuthTypeName(s5->auth_type));
}

/*
    +----+------+----------+------+----------+
    |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
    +----+------+----------+------+----------+
    | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
    +----+------+----------+------+----------+


    +----+--------+
    |VER | STATUS |
    +----+--------+
    | 1  |   1    |
    +----+--------+
*/

void s5ClientAuthUP_Request(s5_fds *s5)
{
    int pos = 0;
    int value_len = 0;
    char *data = sdsPTR(s5->buf);

    //auth version.
    s5->auth_version = data[pos];
    pos++;
    mlogTrace(s5->ref_log_ptr,"s5ClientAuthUP_Request AuthVersion %d",s5->auth_version);

    //username
    value_len = data[pos];
    pos++;

    memcpy(s5->username,data + pos,value_len);
    pos = pos + value_len;

    //password
    value_len = data[pos];
    pos++;

    memcpy(s5->password,data + pos,value_len);
    pos = pos + value_len;

    mlogDebug(s5->ref_log_ptr,"s5ClientAuthUP_Request() username %d,password %s",s5->username,s5->password);
}

void s5ClientAuthUP_Response(s5_fds *s5)
{
    char res_data[3] = {0};

    res_data[0] = sdsChar(s5->buf,0);

    if(S5_AUTH_USERNAME_PASSWORD == (int)s5->auth_type)
    {
        if(0 == strcmp(S5_USER_NAME,s5->username) && 0 == strcmp(S5_PASSWORD,s5->password))
        {
            res_data[1] = SOCKS5_AUTH_OK;
            s5->status = SOCKS_STATUS_REQUEST;
        }
        else
        {
            res_data[1] = SOCKS5_AUTH_ER;
            s5->status = SOCKS_STATUS_RELAY;
        }

        anetWrite(s5->fd_real_client,res_data,2);
    }
}


/*
    +----+-----+-------+------+----------+----------+
    |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    +----+-----+-------+------+----------+----------+
    | 1  |  1  | X'00' |  1   | Variable |    2     |
    +----+-----+-------+------+----------+----------+

    +----+-----+-------+------+----------+----------+
    |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    +----+-----+-------+------+----------+----------+
    | 1  |  1  | X'00' |  1   | Variable |    2     |
    +----+-----+-------+------+----------+----------+
*/
void s5ClientRequest_Request(s5_fds *s5)
{
    int pos = 0;
    short req_type = 0;
    short address_type = 0;
    short data_len = 0;
    char *data = sdsPTR(s5->buf);

    //version
    mlogTrace(s5->ref_log_ptr,"s5ClientRequest_Request() version %d",data[pos]);
    pos++;

    //cmd
    req_type = (short)data[pos];
    pos++;
    mlogDebug(s5->ref_log_ptr,"s5ClientRequest_Request() CMD %d",req_type);

    if(S5_RequestType_CONNECT != req_type)
    {
        mlogError(s5->ref_log_ptr,"NO DEAL return...");
        return;
    }

    //RSV
    pos++;

    //ATYPE
    address_type = (short)data[pos];
    pos++;
    
    if(SOCKS_AddressType_IPv4 == address_type)
    {
        // socks5://127.0.0.1:1080

        snprintf(s5->real_host,256,"%d.%d.%d.%d",
                    data[pos]&0xff,data[pos+1]&0xff,data[pos+2]&0xff,data[pos+3]&0xff);
        
        pos = pos + 4;
    }
    else if(SOCKS_AddressType_DOMAINNAME == address_type)
    {
        // socks5h://127.0.0.1:1080

        data_len = (short)data[pos];
        pos++;

        memcpy(s5->real_host,data + pos,data_len);
        
        pos = pos + data_len;
    }
    else if(SOCKS_AddressType_IPv6 == address_type)
    {

    }

    //ADR.PORT 网络字节序列.
    memcpy(&s5->real_port,data + pos,2);
    s5->real_port = ntohs(s5->real_port);

    pos = pos + 2;
}

void s5ClientRequest_Response(struct aeEventLoop *eventLoop,s5_fds *s5)
{
    mlogInfo(s5->ref_log_ptr,"s5ClientRequest_Response() web/app want_connect %s:%d",s5->real_host,s5->real_port);

    if(PROXY_TYPE_LOCAL == s5->proxy_type)
    {
        socksCONNECT_local(eventLoop,s5);
    }
    else if(PROXY_TYPE_SSR == s5->proxy_type)
    {
        sdsRelease(s5->buf_dup);
        s5->buf_dup = NULL;

        s5->buf_dup = sdsDup(s5->buf);

        socksCONNECT_ssr(eventLoop,s5);
    }
}

/*
    socks4
    +-----+-----+----+----+----+----+----+----+----+----+----+----+
	| VER | CMD | DSTPORT |      DSTIP        | USERID       |NULL|
	+-----+-----+----+----+----+----+----+----+----+----+----+----+
 	| 1   |  1  |     2   |       4           |    variable  |  1 |
    +-----+-----+----+----+----+----+----+----+----+----+----+----+

    sock4a: DSTIP == 0.0.0.x时.
    +-----+-----+----+----+----+----+----+----+----+----+----+----+----+----+----+------+
	| VER | CMD | DSTPORT |      DSTIP        |      USERID  |NULL|  hostname    | NULL |
	+-----+-----+----+----+----+----+----+----+----+----+----+----+----+----+----+------+
 	| 1   |  1  |     2   |       4           |    variable  |  1 |  variable    |  1   |
    +-----+-----+----+----+----+----+----+----+----+----+----+----+----+----+----+------+

    DSTPORT/DSTIP 都可以为0x00.
    +-----+-----+----+----+----+----+----+----+
	| VER | RET | DSTPORT |      DSTIP        |
	+-----+-----+----+----+----+----+----+----+
	|  1  |  1  |     2   |        4          |
    +-----+-----+----+----+----+----+----+----+
*/
void s4ClientRequest_Request(s5_fds *s5)
{
    char *data = sdsPTR(s5->buf);
    int pos = 0;
    short req_type = 0;

    //version
    s5->client_version = data[pos];
    pos++;
    mlogTrace(s5->ref_log_ptr,"s4ClientRequest_Request() socks_version %d",s5->client_version);

    //CMD
    req_type = data[pos];
    pos++;

    mlogDebug(s5->ref_log_ptr,"s4ClientRequest_Request() CMD %d",req_type);

    if(S5_RequestType_CONNECT != req_type)
    {
        mlogError(s5->ref_log_ptr,"NO DEAL return...");
        return;
    }

    //PORT 网络字节序列.
    memcpy(&s5->real_port,data + pos,2);
    pos = pos + 2;
    s5->real_port = ntohs(s5->real_port);

    //IP 
    snprintf(s5->real_host,256,"%d.%d.%d.%d",
                data[pos]&0xff,data[pos+1]&0xff,data[pos+2]&0xff,data[pos+3]&0xff);
    pos = pos + 4;

    //USERID
    if(0x00 != data[pos])
    {
        char * userid = data + pos;
        
        pos = pos + strlen(userid);
    }

    //Change to socks4a.
    if(0 == memcmp("0.0.0.",s5->real_host,6))
    {
        s5->client_version = SOCKS_VERSION_4A;
        mlogDebug(s5->ref_log_ptr,"s4ClientRequest_Request() socks4a");
        pos = pos + 1;

        strcpy(s5->real_host,data + pos);
        mlogDebug(s5->ref_log_ptr,"s4ClientRequest_Request() hostname %s",s5->real_host);
    }
}

void s4ClientRequest_Response(struct aeEventLoop *eventLoop,s5_fds *s5)
{
    mlogInfo(s5->ref_log_ptr,"s4ClientRequest_Response() web/app want_connect %s:%d",s5->real_host,s5->real_port);

    if(PROXY_TYPE_LOCAL == s5->proxy_type)
    {
        socksCONNECT_local(eventLoop,s5);
    }
    else if(PROXY_TYPE_SSR == s5->proxy_type)
    {
        sdsRelease(s5->buf_dup);
        s5->buf_dup = NULL;

        s5->buf_dup = sdsDup(s5->buf);

        socksCONNECT_ssr(eventLoop,s5);
    }
}

bool socksCONNECT_local(struct aeEventLoop *eventLoop,s5_fds *s5)
{
    char err_str[ANET_ERR_LEN] = {0};
    char *res_data = sdsPTR(s5->buf);

    s5->fd_real_server = anetTcpNonBlockConnect(err_str,s5->real_host,s5->real_port);
    if(s5->fd_real_server)
    {
        anetNonBlock(err_str,s5->fd_real_server);

        anetRecvTimeout(err_str,s5->fd_real_server,SOCKET_RECV_TIMEOUT);
        anetSendTimeout(err_str,s5->fd_real_server,SOCKET_SEND_TIMEOUT);

        mlogDebug(s5->ref_log_ptr,"socksCONNECT_local() client_fd %d,server_fd %d",s5->fd_real_client,s5->fd_real_server);

        if(AE_OK != aeCreateFileEvent(eventLoop,s5->fd_real_server,AE_READABLE,sockProxy_data,s5))
        {
            mlogError(s5->ref_log_ptr,"socksCONNECT_local() aeCreateFileEvent(%d) error %d",s5->fd_real_server,errno);

            if(SOCKS_VERSION_4 == s5->client_version ||
                SOCKS_VERSION_4A == s5->client_version)
            {
                res_data[1] = SOCKS4_AUTH_5C;
            }
            else
            {
                res_data[1] = SOCKS5_AUTH_ER;
            }
        }
        else
        {
            mlogInfo(s5->ref_log_ptr,"socksCONNECT_local() connected %s:%d",s5->real_host,s5->real_port);

            if(SOCKS_VERSION_4 == s5->client_version ||
                SOCKS_VERSION_4A == s5->client_version)
            {
                res_data[1] = SOCKS4_AUTH_5A;
            }
            else
            {
                res_data[1] = SOCKS5_AUTH_OK;
            }
            
            //memset(res_data + 4,0,6);
        }
    }
    else
    {
        if(SOCKS_VERSION_4 == s5->client_version ||
                SOCKS_VERSION_4A == s5->client_version)
        {
            res_data[1] = SOCKS4_AUTH_5C;
        }
        else
        {
            res_data[1] = SOCKS5_AUTH_ER;
        }
        
        mlogError(s5->ref_log_ptr,"socksCONNECT_local() anetTcpNonBlockConnect(%s:%d) error %s \r\n",s5->real_host,s5->real_port,err_str);
    }
    
    s5->status = SOCKS_STATUS_RELAY;
    if(SOCKS_VERSION_4 == s5->client_version ||
        SOCKS_VERSION_4A == s5->client_version)
    {
        res_data[0] = 0x00;
        anetWrite(s5->fd_real_client,res_data,8);
    }
    else
    {
        anetWrite(s5->fd_real_client,sdsPTR(s5->buf),sdsLength(s5->buf));
    }
    
    return true;
}

bool socksCONNECT_ssr(struct aeEventLoop *eventLoop,s5_fds *s5)
{
    char err_str[ANET_ERR_LEN] = {0};
    bool connected_ssr = true;
    char * res_data = sdsPTR(s5->buf);

    s5->fd_real_server = anetTcpNonBlockConnect(err_str,SSR_HOST,SSR_PORT);
    if(s5->fd_real_server > 0)
    {
        s5->ssl = anetSSLConnect(err_str,s5->fd_real_server);
        if(NULL != s5->ssl)
        {
            anetNonBlock(err_str,s5->fd_real_server);
            anetRecvTimeout(err_str,s5->fd_real_server,SOCKET_RECV_TIMEOUT);
            anetSendTimeout(err_str,s5->fd_real_server,SOCKET_SEND_TIMEOUT);

            mlogDebug(s5->ref_log_ptr,"socksCONNECT_ssr() client_fd %d,server_fd %d",s5->fd_real_client,s5->fd_real_server);

            if(AE_OK == aeCreateFileEvent(eventLoop,s5->fd_real_server,AE_READABLE,sockProxy_ssr,s5))
            {
                mlogInfo(s5->ref_log_ptr,"socksCONNECT_ssr() connected %s:%d",SSR_HOST,SSR_PORT);
            }
            else
            {
                connected_ssr = false;
                mlogError(s5->ref_log_ptr,"socksCONNECT_ssr() aeCreateFileEvent(%d) error %d",s5->fd_real_server,errno);
            }

            s5->upstream_byte = s5->upstream_byte + ssrConnect_Request(s5->ssl,s5->real_host,s5->real_port);
        }
        else
        {
            connected_ssr = false;
            mlogError(s5->ref_log_ptr,"socksCONNECT_ssr() anetSSLConnect(%s,%d) error %s",SSR_HOST,SSR_PORT,err_str);
        }
    }
    else
    {
        connected_ssr = false;
        mlogError(s5->ref_log_ptr,"socksCONNECT_ssr() anetTcpNonBlockConnect(%s:%d) error %s",SSR_HOST,SSR_PORT,err_str);
    }

    if(!connected_ssr)
    {
        if(SOCKS_VERSION_4 == s5->client_version ||
            SOCKS_VERSION_4A == s5->client_version)
        {
            res_data[0] = 0x00;
            res_data[1] = SOCKS4_AUTH_5C;
        }
        else
        {
            res_data[1] = SOCKS5_AUTH_ER;
        }

        s5->status = SOCKS_STATUS_RELAY;
        anetWrite(s5->fd_real_client,sdsPTR(s5->buf),sdsLength(s5->buf));
    }

    return true;
}

void socksRelay_local(struct aeEventLoop *eventLoop,int fd,s5_fds *s5)
{
    int fd_read = fd;
    int fd_write = 0;
    int nsended = 0;
    int upstream = 0;
    char buf[SOCKS_BUF_SIZE] = {0};

    if(fd_read == s5->fd_real_client)
    {
        upstream = 1;
        fd_write = s5->fd_real_server;
    }
    else
    {
        upstream = 0;
        fd_write = s5->fd_real_client;
    }

    int len = anetRead(fd_read,buf,SOCKS_BUF_SIZE);
    if(len > 0)
    {
        mlogDebug(s5->ref_log_ptr,"socksRelay_local() anetRead(fd_[%d]) len %d",fd_read,len);
        nsended = anetWrite(fd_write,buf,len);
        if(len != nsended)
        {
            mlogError(s5->ref_log_ptr,"socksRelay_local() wirte(fd_[%d]) nwrite_len %d, nsend_len %d,errno %d\r\n",fd_write,len,nsended,errno);
        }
        else
        {
            mlogDebug(s5->ref_log_ptr,"socksRelay_local() wirte(fd_[%d]) len %d\r\n",fd_write,nsended);
        }

        if(upstream > 0)
        {
            s5->upstream_byte = s5->upstream_byte + nsended;
        }
        else
        {
            s5->downstream_byte = s5->downstream_byte + nsended;
        }
    }
    else
    {
        if(0 == len)
        {
            _socksProxy_fds_closed(eventLoop,s5);
        }
    }
}

void socksRelay_ssr(struct aeEventLoop *eventLoop,s5_fds *s5)
{
    char buf[SOCKS_BUF_SIZE] = {0};
    int len = 0;

    len = anetRead(s5->fd_real_client,buf,SOCKS_BUF_SIZE);
    if(len > 0)
    {
        mlogDebug(s5->ref_log_ptr,"socksRelay_ssr() anetRead(fd_%d) %d",s5->fd_real_client,len);
        s5->upstream_byte =  s5->upstream_byte + ssrData_Request(s5->ssl,buf,len);
    }
    else if(0 == len)
    {
        _socksProxy_fds_closed(eventLoop,s5);
    }
}

void socksProcess(struct aeEventLoop *eventLoop,int fd,int mask,s5_fds *s5)
{
    char buf[SOCKS_BUF_SIZE] = {0};
    int len = 0;

    if(mask&AE_READABLE)
    {
        mlogTrace(s5->ref_log_ptr,"socksProcess() socks_status %s",s5StatusName(s5->status));

        if(SOCKS_STATUS_HANDSHAKE_1 == s5->status)
        {
            len = anetRead(fd,buf,SOCKS_BUF_SIZE);
            if(len >= 2)
            {
                s5->client_version = buf[0];
                sdsCatlen(s5->buf,buf,len);

                if(SOCKS_VERSION_5 == s5->client_version)
                {
                    s5ClientMethods_Request(s5);
                    s5ClientMethods_Response(s5);

                    sdsEmpty(s5->buf);
                }
                else
                {
                    s4ClientRequest_Request(s5);
                    s4ClientRequest_Response(eventLoop,s5);

                    sdsEmpty(s5->buf);
                }
            }
        }
        else if(SOCKS_STATUS_HANDSHAKE_2 == s5->status)
        {
            len = anetRead(fd,buf,SOCKS_BUF_SIZE);
            if(len >= 2)
            {
                sdsCatlen(s5->buf,buf,len);

                s5ClientAuthUP_Request(s5);
                s5ClientAuthUP_Response(s5);

                sdsEmpty(s5->buf);
            }
        }
        else if(SOCKS_STATUS_REQUEST == s5->status)
        {
            len = anetRead(fd,buf,SOCKS_BUF_SIZE);
            if(len)
            {
                sdsCatlen(s5->buf,buf,len);

                s5ClientRequest_Request(s5);
                s5ClientRequest_Response(eventLoop,s5);

                sdsEmpty(s5->buf);
            }
        }
        else if(SOCKS_STATUS_RELAY == s5->status)
        {
            if(PROXY_TYPE_LOCAL == s5->proxy_type)
            {
                socksRelay_local(eventLoop,fd,s5);
            }
            else if(PROXY_TYPE_SSR == s5->proxy_type)
            {
                socksRelay_ssr(eventLoop,s5);
            }
        }
    }
    else if(mask|AE_WRITABLE)
    {

    }
}

void sockProxy_accept(struct aeEventLoop *eventLoop, int fd, void *clientData, int mask)
{
    char err_str[ANET_ERR_LEN] = {0};
    char ip[128] = {0};
    int port = 0;
    bool connected = false;
    MLOG *log = eventLoop->ref_log_ptr;

    //增加数据处理函数.
    s5_fds *s5 = s5FDsNew();
    if(NULL == s5)
    {
        mlogError(log,"sockProxy_accept() s5FDsNew() error %s",err_str);
        return;
    }

    s5->ref_log_ptr = log;

    s5->fd_real_client = anetTcpAccept(err_str,fd,ip,128,&port);
    if(s5->fd_real_client <= 0)
    {
        mlogError(log,"sockProxy_accept() anetTcpAccept() error %s",err_str);
    }
    else
    {
        s5->status = SOCKS_STATUS_HANDSHAKE_1;
        s5->auth_type = S5_AUTH_NONE;

        anetNonBlock(err_str,s5->fd_real_client);
        
        anetRecvTimeout(err_str,s5->fd_real_client,SOCKET_RECV_TIMEOUT);
        anetSendTimeout(err_str,s5->fd_real_client,SOCKET_SEND_TIMEOUT);

        if(AE_OK == aeCreateFileEvent(eventLoop,s5->fd_real_client,AE_READABLE,sockProxy_data,s5))
        {
            connected = true;
        }
        else
        {
            mlogError(log,"sockProxy_accept() aeCreateFileEvent(%d) errno %d",s5->fd_real_client,errno);
        }
    }

    if(!connected)
    {
        _socksProxy_fds_closed(eventLoop,s5);
    }
}

void sockProxy_data(struct aeEventLoop *eventLoop, int fd, void *clientData, int mask)
{
    s5_fds *s5 = (s5_fds*)clientData;
    socksProcess(eventLoop,fd,mask,s5);
}

void sockProxy_ssr(struct aeEventLoop *eventLoop, int fd, void *clientData, int mask)
{
    s5_fds * s5 = (s5_fds*)clientData;
    http_status status = httpResponseStatusGet(s5->res);
    char buf[8192] = {0};
    int len = 0;

    if(mask&AE_READABLE)
    {
        len = anetSSLRead(s5->ssl,buf,8192);
        if(len > 0)
        {
            mlogDebug(s5->ref_log_ptr,"sockProxy_ssr() anetSSLRead() %d",len);

            s5->downstream_byte = s5->downstream_byte + len;
            
            if(HTTP_STATUS_HEAD_VERIFY == status ||
                HTTP_STATUS_HEAD_PARSE == status)
            {
                mlogDebug(s5->ref_log_ptr,"sockProxy_ssr() http_response_recv{head} ...");

                sdsCatlen(s5->buf,buf,len);
                if(httpHeadersOK(s5->buf))
                {
                    mlogDebug(s5->ref_log_ptr,"sockProxy_ssr() http_response_recv{head} OK");

                    httpResponseParse(s5->buf,s5->res);
                    
                    ///httpResponsePrint(s5->res);

                    httpResponseStatusSet(s5->res,HTTP_STATUS_BODY_RECV);

                    if(httpResponseBodyOK(s5->res))
                    {
                        mlogDebug(s5->ref_log_ptr,"sockProxy_ssr() http_response_recv{body} OK");
                        msockProc_fun(s5,eventLoop);
                    }
                }
            }
            else if(HTTP_STATUS_BODY_RECV == status)
            {
                mlogDebug(s5->ref_log_ptr,"sockProxy_ssr() http_request_recv{body} ...");
                sdsCatlen(s5->res->body,buf,len);
                
                if(httpResponseBodyOK(s5->res))
                {
                    mlogDebug(s5->ref_log_ptr,"sockProxy_ssr() http_request_recv{body} OK");
                    msockProc_fun(s5,eventLoop);
                }
            }
        }
        else if(0 == len)
        {
            _socksProxy_fds_closed(eventLoop,s5);
        }
    }
}

void msockProc_fun(s5_fds *node,struct aeEventLoop *eventLoop)
{
    int len = 0;
    int ssr_type = ssrResponseType(node->res);
    mlogDebug(node->ref_log_ptr,"msockProc_fun() ssr_type %d",ssr_type);

    switch(ssr_type)
    {
        case SSR_TYPE_AUTH:
        {
            break;
        }

        case SSR_TYPE_CONNECT:
        {
            node->status = SOCKS_STATUS_RELAY;
            char * res_data = sdsPTR(node->buf_dup);
            if(SOCKS_VERSION_4 == node->client_version ||
                SOCKS_VERSION_4A == node->client_version)
            {
                res_data[0] = 0x00;
                res_data[1] = SOCKS4_AUTH_5A;

                len = anetWrite(node->fd_real_client,res_data,8);
            }
            else
            {
                res_data[1] = SOCKS5_AUTH_OK;

                len = anetWrite(node->fd_real_client,sdsPTR(node->buf_dup),sdsLength(node->buf_dup));
            }

            node->downstream_byte = node->downstream_byte + len;
            
            ///printf("msockProc_fun() anetWrite(fd_%d) %d \r\n",node->fd_real_client,len);

            break;
        }

        case SSR_TYPE_DATA:
        {
            len = anetWrite(node->fd_real_client,sdsPTR(node->res->body),sdsLength(node->res->body));
            ///printf("msockProc_fun() anetWrite(fd_%d) %d \r\n",node->fd_real_client,len);
            node->downstream_byte = node->downstream_byte + len;

            break;
        }

        default:
        {
            mlogError(node->ref_log_ptr,"msockProc_fun() hacker");
            break;
        }
    }

    listEmpty(node->res->header_list);

    sdsEmpty(node->buf);
    sdsEmpty(node->res->body);

    httpResponseStatusSet(node->res,HTTP_STATUS_HEAD_VERIFY);

    sdsEmpty(node->res->versions);
    sdsEmpty(node->res->statments);
}
