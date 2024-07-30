
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
        printf("s5ClientMethods_Request socks_version is %d\r\n",(int)s5->client_version);
    }

    if(SOCKS_VERSION_5 == s5->client_version)
    {
        nMethods = data[1];
        printf("s5ClientMethods_Request count is %d\r\n",nMethods);

        while(nMethods)
        {
            printf("s5ClientMethods_Request is %d\r\n",(int)data[pos]);

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

    printf("s5ClientMethods_Response() auth_type %s\r\n",s5AuthTypeName(s5->auth_type));
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
    printf("s5ClientAuthUP_Request AuthVersion %d\r\n",s5->auth_version);

    //username
    value_len = data[pos];
    pos++;

    memcpy(s5->username,data + pos,value_len);
    printf("s5ClientAuthUP_Request UserName %s\r\n",s5->username);
    pos = pos + value_len;

    //password
    value_len = data[pos];
    pos++;

    memcpy(s5->password,data + pos,value_len);
    printf("s5ClientAuthUP_Request PassWord %s\r\n",s5->password);
    pos = pos + value_len;
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
    printf("s5ClientRequest_Request() version %d \r\n",data[pos]);
    pos++;

    //cmd
    req_type = (short)data[pos];
    pos++;
    printf("s5ClientRequest_Request() CMD %d \r\n",req_type);

    if(S5_RequestType_CONNECT != req_type)
    {
        printf("NO DEAL return...");
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
        printf("s5ClientRequest_Request() ipv4 %s \r\n",s5->real_host);

        pos = pos + 4;
    }
    else if(SOCKS_AddressType_DOMAINNAME == address_type)
    {
        // socks5h://127.0.0.1:1080

        data_len = (short)data[pos];
        pos++;

        memcpy(s5->real_host,data + pos,data_len);
        printf("s5ClientRequest_Request() hostname %s \r\n",s5->real_host);
        pos = pos + data_len;
    }
    else if(SOCKS_AddressType_IPv6 == address_type)
    {

    }

    //ADR.PORT 网络字节序列.
    memcpy(&s5->real_port,data + pos,2);
    s5->real_port = ntohs(s5->real_port);
    printf("s5ClientRequest_Request() port %d \r\n",s5->real_port);

    pos = pos + 2;
}

void s5ClientRequest_Response(struct aeEventLoop *eventLoop,s5_fds *s5)
{
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
    printf("s4ClientRequest_Request() socks_version %d \r\n",s5->client_version);

    //CMD
    req_type = data[pos];
    pos++;

    printf("s4ClientRequest_Request() CMD %d \r\n",req_type);

    if(S5_RequestType_CONNECT != req_type)
    {
        printf("NO DEAL return...");
        return;
    }

    //PORT 网络字节序列.
    memcpy(&s5->real_port,data + pos,2);
    pos = pos + 2;
    s5->real_port = ntohs(s5->real_port);
    printf("s4ClientRequest_Request() port %d \r\n",s5->real_port);

    //IP 
    snprintf(s5->real_host,256,"%d.%d.%d.%d",
                data[pos]&0xff,data[pos+1]&0xff,data[pos+2]&0xff,data[pos+3]&0xff);
    pos = pos + 4;
    printf("s4ClientRequest_Request() ipv4 %s \r\n",s5->real_host);

    //USERID
    if(0x00 != data[pos])
    {
        char * userid = data + pos;
        printf("s4ClientRequest_Request() USERID %s \r\n",userid);
        pos = pos + strlen(userid);
    }

    //Change to socks4a.
    if(0 == memcmp("0.0.0.",s5->real_host,6))
    {
        s5->client_version = SOCKS_VERSION_4A;
        printf("s4ClientRequest_Request() socks4a \r\n");
        pos = pos + 1;

        strcpy(s5->real_host,data + pos);
        printf("s4ClientRequest_Request() hostname %s \r\n",s5->real_host);
    }
}

void s4ClientRequest_Response(struct aeEventLoop *eventLoop,s5_fds *s5)
{
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

        printf("socksCONNECT_local() real_client_fd %d\r\n",s5->fd_real_client);
        printf("socksCONNECT_local() real_server_fd %d\r\n",s5->fd_real_server);

        if(AE_OK != aeCreateFileEvent(eventLoop,s5->fd_real_server,AE_READABLE,sockProxy_data,s5))
        {
            printf("socksCONNECT_local() aeCreateFileEvent(%d) error %d\r\n",s5->fd_real_server,errno);

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
        
        printf("socksCONNECT_local() anetTcpNonBlockConnect(%s:%d) error %s \r\n",s5->real_host,s5->real_port,err_str);
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

            printf("socksCONNECT_ssr() real_client_fd %d\r\n",s5->fd_real_client);
            printf("socksCONNECT_ssr() real_server_fd %d\r\n",s5->fd_real_server);

            if(AE_OK != aeCreateFileEvent(eventLoop,s5->fd_real_server,AE_READABLE,sockProxy_ssr,s5))
            {
                printf("socksCONNECT_ssr() aeCreateFileEvent(%d) error %d\r\n",s5->fd_real_server,errno);
            }

            s5->upstream_byte = s5->upstream_byte + ssrConnect_Request(s5->ssl,s5->real_host,s5->real_port);
            ///printf("socksCONNECT_ssr() ssrConnect_Request() \r\n");
        }
        else
        {
            connected_ssr = false;
            printf("socksCONNECT_ssr() anetSSLConnect(%s,%d) error %s\r\n",SSR_HOST,SSR_PORT,err_str);
        }
    }
    else
    {
        connected_ssr = false;
        printf("socksCONNECT_ssr() anetTcpNonBlockConnect(%s:%d) error %s \r\n",SSR_HOST,SSR_PORT,err_str);
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
        printf("socksRelay_local() anetRead(fd_[%d]) len %d\r\n",fd_read,len);
        nsended = anetWrite(fd_write,buf,len);
        if(len != nsended)
        {
            printf("socksRelay_local() wirte(fd_[%d]) len %d,errno %d\r\n",fd_write,nsended,errno);
        }
        else
        {
            printf("socksRelay_local() wirte(fd_[%d]) len %d\r\n",fd_write,nsended);
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
            printf("socksRelay_local() fd_%d closed\r\n",fd);
        }
        else
        {
            printf("socksRelay_local() fd_%d errno %d\r\n",fd,errno);
        }

        printf("socksRelay_local() session upstream_byte %ld,downstream_byte %ld\r\n",s5->upstream_byte,s5->downstream_byte);

        aeDeleteFileEvent(eventLoop,fd_read,AE_READABLE);
        aeDeleteFileEvent(eventLoop,fd_write,AE_READABLE);

        s5FDsFree(s5);
        s5 = NULL;
    }
}

void socksRelay_ssr(struct aeEventLoop *eventLoop,s5_fds *s5)
{
    char buf[SOCKS_BUF_SIZE] = {0};
    int len = 0;

    len = anetRead(s5->fd_real_client,buf,SOCKS_BUF_SIZE);
    if(len > 0)
    {
        printf("socksRelay_ssr() anetRead(fd_%d) %d\r\n",s5->fd_real_client,len);
        s5->upstream_byte =  s5->upstream_byte + ssrData_Request(s5->ssl,buf,len);
    }
    else if(0 == len)
    {
        printf("socksRelay_ssr(ms:%ld) fd_%d closed errno %d.\r\n",mlogTick_ms(),s5->fd_real_client,errno);

        aeDeleteFileEvent(eventLoop,s5->fd_real_client,AE_READABLE);
        aeDeleteFileEvent(eventLoop,s5->fd_real_server,AE_READABLE);

        printf("socksRelay_ssr() session upstream_byte %ld,downstream_byte %ld\r\n",s5->upstream_byte,s5->downstream_byte);

        s5FDsFree(s5);
        s5 = NULL;
    }
}

void socksProcess(struct aeEventLoop *eventLoop,int fd,int mask,s5_fds *s5)
{
    char buf[SOCKS_BUF_SIZE] = {0};
    int len = 0;

    if(mask&AE_READABLE)
    {
        ///printf("\r\nsocksProcess() socks_status %s\r\n",s5StatusName(s5->status));

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
    int fd_client = -1;

    fd_client = anetTcpAccept(err_str,fd,ip,128,&port);
    if(fd_client <= 0)
    {
        printf("sockProxy_accept() anetTcpAccept() error %s\r\n",err_str);
        return;
    }

    printf("sockProxy_accept() anetTcpAccept() OK %s:%d \r\n",ip,port);

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

        if(AE_OK != aeCreateFileEvent(eventLoop,fd_client,AE_READABLE,sockProxy_data,s5))
        {
            printf("sockProxy_accept() aeCreateFileEvent(%d) errno %d\r\n",fd_client,errno);
        }
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
            printf("sockProxy_ssr() anetSSLRead() %d \r\n",len);
            s5->downstream_byte = s5->downstream_byte + len;
            
            if(HTTP_STATUS_HEAD_VERIFY == status ||
                HTTP_STATUS_HEAD_PARSE == status)
            {
                ///printf("sockProxy_ssr() http_response_recv{head} ...\r\n");

                sdsCatlen(s5->buf,buf,len);
                if(httpHeadersOK(s5->buf))
                {
                    ///printf("sockProxy_ssr() http_response_recv{head} OK\r\n");

                    httpResponseParse(s5->buf,s5->res);
                    
                    ///httpResponsePrint(s5->res);

                    httpResponseStatusSet(s5->res,HTTP_STATUS_BODY_RECV);

                    if(httpResponseBodyOK(s5->res))
                    {
                        ///printf("sockProxy_ssr() http_response_recv{body} OK\r\n");
                        msockProc_fun(s5,eventLoop);
                    }
                }
            }
            else if(HTTP_STATUS_BODY_RECV == status)
            {
                ///printf("sockProxy_ssr() http_request_recv{body} ...\r\n");
                sdsCatlen(s5->res->body,buf,len);
                
                if(httpResponseBodyOK(s5->res))
                {
                    ///printf("sockProxy_ssr() http_request_recv{body} OK\r\n");
                    msockProc_fun(s5,eventLoop);
                }
            }
        }
        else if(0 == len)
        {
            printf("sockProxy_ssr() socket(%d) close.",fd);

            aeDeleteFileEvent(eventLoop,s5->fd_real_server,AE_READABLE|AE_WRITABLE);
            aeDeleteFileEvent(eventLoop,s5->fd_real_server,AE_READABLE|AE_WRITABLE);

            s5FDsFree(s5);
            s5 = NULL;
        }
    }
}

void msockProc_fun(s5_fds *node,struct aeEventLoop *eventLoop)
{
    int len = 0;

    int ssr_type = ssrResponseType(node->res);
    switch(ssr_type)
    {
        case SSR_TYPE_AUTH:
        {
            printf("msockProc_fun() SSR_TYPE_AUTH\r\n");
            break;
        }

        case SSR_TYPE_CONNECT:
        {
            printf("msockProc_fun() SSR_TYPE_CONNECT response\r\n");

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
            
            printf("msockProc_fun() anetWrite(fd_%d) %d \r\n",node->fd_real_client,len);

            break;
        }

        case SSR_TYPE_DATA:
        {
            printf("msockProc_fun() SSR_TYPE_DATA\r\n");
            len = anetWrite(node->fd_real_client,sdsPTR(node->res->body),sdsLength(node->res->body));
            printf("msockProc_fun() anetWrite(fd_%d) %d \r\n",node->fd_real_client,len);

            break;
        }

        default:
        {
            printf("msockProc_fun() hacker\r\n");
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
