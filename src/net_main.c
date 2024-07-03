
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <netdb.h>

#include <string.h>
#include <stdarg.h>

#include <net_main.h>

#ifdef __linux__
    #include <net_epoll.h>
#endif

#ifdef __APPLE__
    #include <net_kqueue.h>
#endif 

#include <zmalloc.h>

aeEventLoop *aeCreateEventLoop(int setsize) 
{
    aeEventLoop *eventLoop;
    int i;

    eventLoop = zmalloc(sizeof(*eventLoop));
    if(NULL == eventLoop)
    {
        goto err;
    }
    
    eventLoop->events = zmalloc(sizeof(aeFileEvent)*setsize);
    eventLoop->fired = zmalloc(sizeof(aeFiredEvent)*setsize);
    if(NULL == eventLoop->events || 
        NULL == eventLoop->fired)
    {
        goto err;
    }

    eventLoop->setsize = setsize;
    eventLoop->stop = 0;
    eventLoop->maxfd = -1;
    eventLoop->flags = 0;
    if (-1 == aeApiCreate(eventLoop))
    {
        goto err;
    }
            
    /* Events with mask == AE_NONE are not set. So let's initialize the
     * vector with it. */
    for (i = 0; i < setsize; i++)
    {
        eventLoop->events[i].mask = AE_NONE;
    }
    
    return eventLoop;

err:
    if(eventLoop) 
    {
        zfree(eventLoop->events);
        zfree(eventLoop->fired);
        zfree(eventLoop);
    }

    return NULL;
}

/* Return the current set size. */
int aeGetSetSize(aeEventLoop *eventLoop) 
{
    return eventLoop->setsize;
}

/*
 * Tell the event processing to change the wait timeout as soon as possible.
 *
 * Note: it just means you turn on/off the global AE_DONT_WAIT.
 */
void aeSetDontWait(aeEventLoop *eventLoop, int noWait) 
{
    if (noWait)
        eventLoop->flags |= AE_DONT_WAIT;
    else
        eventLoop->flags &= ~AE_DONT_WAIT;
}

/* Resize the maximum set size of the event loop.
 * If the requested set size is smaller than the current set size, but
 * there is already a file descriptor in use that is >= the requested
 * set size minus one, AE_ERR is returned and the operation is not
 * performed at all.
 *
 * Otherwise AE_OK is returned and the operation is successful. */
int aeResizeSetSize(aeEventLoop *eventLoop, int setsize) 
{
    int i;

    if (setsize == eventLoop->setsize) return AE_OK;
    if (eventLoop->maxfd >= setsize) return AE_ERR;
    if (aeApiResize(eventLoop,setsize) == -1) return AE_ERR;

    eventLoop->events = zrealloc(eventLoop->events,sizeof(aeFileEvent)*setsize);
    eventLoop->fired = zrealloc(eventLoop->fired,sizeof(aeFiredEvent)*setsize);
    eventLoop->setsize = setsize;

    /* Make sure that if we created new slots, they are initialized with
     * an AE_NONE mask. */
    for (i = eventLoop->maxfd+1; i < setsize; i++)
        eventLoop->events[i].mask = AE_NONE;
    
    return AE_OK;
}

void aeDeleteEventLoop(aeEventLoop *eventLoop) 
{
    aeApiFree(eventLoop);
    zfree(eventLoop->events);
    zfree(eventLoop->fired);

    zfree(eventLoop);
}

void aeStop(aeEventLoop *eventLoop) 
{
    eventLoop->stop = 1;
}

int aeCreateFileEvent(aeEventLoop *eventLoop, int fd, int mask,
        aeFileProc *proc, void *clientData)
{
    if (fd >= eventLoop->setsize) 
    {
        errno = ERANGE;
        return AE_ERR;
    }

    aeFileEvent *fe = &eventLoop->events[fd];

    if (-1 == aeApiAddEvent(eventLoop, fd, mask))
    {
        return AE_ERR;
    }

    fe->mask |= mask;

    if (mask & AE_READABLE) fe->rfileProc = proc;
    if (mask & AE_WRITABLE) fe->wfileProc = proc;
    
    fe->clientData = clientData;
    
    if(fd > eventLoop->maxfd)
    {
        eventLoop->maxfd = fd;
    }
    
    return AE_OK;
}

void aeDeleteFileEvent(aeEventLoop *eventLoop, int fd, int mask)
{
    if (fd >= eventLoop->setsize) return;
    aeFileEvent *fe = &eventLoop->events[fd];
    if (fe->mask == AE_NONE) return;

    /* We want to always remove AE_BARRIER if set when AE_WRITABLE
     * is removed. */
    if (mask & AE_WRITABLE) mask |= AE_BARRIER;

    aeApiDelEvent(eventLoop, fd, mask);
    fe->mask = fe->mask & (~mask);
    if (fd == eventLoop->maxfd && fe->mask == AE_NONE) 
    {
        /* Update the max fd */
        int j;

        for (j = eventLoop->maxfd-1; j >= 0; j--)
            if (eventLoop->events[j].mask != AE_NONE) break;
        eventLoop->maxfd = j;
    }
}

void *aeGetFileClientData(aeEventLoop *eventLoop, int fd) {
    if (fd >= eventLoop->setsize) return NULL;
    aeFileEvent *fe = &eventLoop->events[fd];
    if (fe->mask == AE_NONE) return NULL;

    return fe->clientData;
}

int aeGetFileEvents(aeEventLoop *eventLoop, int fd) {
    if (fd >= eventLoop->setsize) 
        return 0;
    
    aeFileEvent *fe = &eventLoop->events[fd];

    return fe->mask;
}


/* Process every pending time event, then every pending file event
 * (that may be registered by time event callbacks just processed).
 * Without special flags the function sleeps until some file event
 * fires, or when the next time event occurs (if any).
 *
 * If flags is 0, the function does nothing and returns.
 * if flags has AE_ALL_EVENTS set, all the kind of events are processed.
 * if flags has AE_FILE_EVENTS set, file events are processed.
 * if flags has AE_TIME_EVENTS set, time events are processed.
 * if flags has AE_DONT_WAIT set, the function returns ASAP once all
 * the events that can be handled without a wait are processed.
 * if flags has AE_CALL_AFTER_SLEEP set, the aftersleep callback is called.
 * if flags has AE_CALL_BEFORE_SLEEP set, the beforesleep callback is called.
 *
 * The function returns the number of events processed. */
int aeProcessEvents(aeEventLoop *eventLoop, int flags)
{
    int processed = 0, numevents;
    if (eventLoop->maxfd != -1) 
    {
        int j;
        struct timeval tv, *tvp = NULL; /* NULL means infinite wait. */
        
        /* The eventLoop->flags may be changed inside beforesleep.
         * So we should check it after beforesleep be called. At the same time,
         * the parameter flags always should have the highest priority.
         * That is to say, once the parameter flag is set to AE_DONT_WAIT,
         * no matter what value eventLoop->flags is set to, we should ignore it. */
        if ((flags & AE_DONT_WAIT) || (eventLoop->flags & AE_DONT_WAIT)) 
        {
            tv.tv_sec = 0;
            tv.tv_usec = 0;
        }
        else 
        {
            tv.tv_sec = 2;
            tv.tv_usec = 0;
        }

        tvp = &tv;
        numevents = aeApiPoll(eventLoop, tvp);
        for (j = 0; j < numevents; j++) 
        {
            int fd = eventLoop->fired[j].fd;
            aeFileEvent *fe = &eventLoop->events[fd];
            int mask = eventLoop->fired[j].mask;
            int fired = 0; /* Number of events fired for current fd. */

            if (fe->mask & mask & AE_READABLE) 
            {
                fe->rfileProc(eventLoop,fd,fe->clientData,mask);
                fired++;
                fe = &eventLoop->events[fd]; /* Refresh in case of resize. */
            }

            /* Fire the writable event. */
            if (fe->mask & mask & AE_WRITABLE) 
            {
                if (!fired || fe->wfileProc != fe->rfileProc) 
                {
                    fe->wfileProc(eventLoop,fd,fe->clientData,mask);
                    fired++;
                }
            }

            processed++;
        }
    }

    return processed; /* return the number of processed file/time events */
}

void aeMain(aeEventLoop *eventLoop) 
{
    eventLoop->stop = 0;

    while (!eventLoop->stop) 
    {
        aeProcessEvents(eventLoop, AE_ALL_EVENTS);
    }
}

char *aeGetApiName(void) 
{
    return aeApiName();
}





static void _anetSetError(char *err, const char *fmt, ...)
{
    va_list ap;

    if(!err)
    {
        return;
    }

    va_start(ap, fmt);
    vsnprintf(err, ANET_ERR_LEN, fmt, ap);
    va_end(ap);
}

static int _anetV6Only(char *err, int s) 
{
    int yes = 1;
    if (setsockopt(s,IPPROTO_IPV6,IPV6_V6ONLY,&yes,sizeof(yes)) == -1) 
    {
        _anetSetError(err, "setsockopt: %s", strerror(errno));
        return ANET_ERR;
    }

    return ANET_OK;
}

static int _anetSetBlock(char *err, int fd, int non_block) 
{
    int flags;

    /* Set the socket blocking (if non_block is zero) or non-blocking.
     * Note that fcntl(2) for F_GETFL and F_SETFL can't be
     * interrupted by a signal. */
    if ((flags = fcntl(fd, F_GETFL)) == -1) 
    {
        _anetSetError(err, "fcntl(F_GETFL): %s", strerror(errno));
        return ANET_ERR;
    }

    /* Check if this flag has been set or unset, if so, 
     * then there is no need to call fcntl to set/unset it again. */
    if (!!(flags & O_NONBLOCK) == !!non_block)
    {
        return ANET_OK;
    }

    if (non_block)
        flags |= O_NONBLOCK;
    else
        flags &= ~O_NONBLOCK;

    if (fcntl(fd, F_SETFL, flags) == -1) 
    {
        _anetSetError(err, "fcntl(F_SETFL,O_NONBLOCK): %s", strerror(errno));
        return ANET_ERR;
    }

    return ANET_OK;
}

/* Accept a connection and also make sure the socket is non-blocking, and CLOEXEC.
 * returns the new socket FD, or -1 on error. */
static int _anetGenericAccept(char *err, int s, struct sockaddr *sa, socklen_t *len) 
{
    int fd;
    do 
    {
        /* Use the accept4() call on linux to simultaneously accept and
         * set a socket as non-blocking. */
#ifdef HAVE_ACCEPT4
        fd = accept4(s, sa, len,  SOCK_NONBLOCK | SOCK_CLOEXEC);
#else
        fd = accept(s,sa,len);
#endif
    }while(fd == -1 && errno == EINTR);

    if (fd == -1) 
    {
        _anetSetError(err, "accept: %s", strerror(errno));
        return ANET_ERR;
    }

#ifndef HAVE_ACCEPT4
    if (anetCloexec(fd) == -1) 
    {
        _anetSetError(err, "anetCloexec: %s", strerror(errno));
        close(fd);
        return ANET_ERR;
    }

    if (anetNonBlock(err, fd) != ANET_OK) 
    {
        close(fd);
        return ANET_ERR;
    }
#endif

    return fd;
}

static int _anetListen(char *err, int s, struct sockaddr *sa, socklen_t len, int backlog, mode_t perm) 
{
    if (bind(s,sa,len) == -1) 
    {
        _anetSetError(err, "bind: %s", strerror(errno));
        close(s);
        return ANET_ERR;
    }

    if (sa->sa_family == AF_LOCAL && perm)
    {
        ///chmod(((struct sockaddr_un *) sa)->sun_path, perm);
    }

    if (listen(s, backlog) == -1) 
    {
        _anetSetError(err, "listen: %s", strerror(errno));
        close(s);
        return ANET_ERR;
    }
    
    return ANET_OK;
}

static int _anetTcpServer(char *err, int port, char *bindaddr, int af, int backlog)
{
    int s = -1, rv;
    char _port[6];  /* strlen("65535") */
    struct addrinfo hints, *servinfo, *p;

    snprintf(_port,6,"%d",port);
    memset(&hints,0,sizeof(hints));
    hints.ai_family = af;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;    /* No effect if bindaddr != NULL */
    if (bindaddr && !strcmp("*", bindaddr))
    {
        bindaddr = NULL;
    }

    if (af == AF_INET6 && bindaddr && !strcmp("::*", bindaddr))
    {
        bindaddr = NULL;
    }

    if ((rv = getaddrinfo(bindaddr,_port,&hints,&servinfo)) != 0) 
    {
        _anetSetError(err, "%s", gai_strerror(rv));
        return ANET_ERR;
    }

    for (p = servinfo; p != NULL; p = p->ai_next) 
    {
        if ((s = socket(p->ai_family,p->ai_socktype,p->ai_protocol)) == -1)
        {
            continue;
        }

        if (af == AF_INET6 && _anetV6Only(err,s) == ANET_ERR) goto error;
        if (anetSetReuseAddr(err,s) == ANET_ERR) goto error;
        if (_anetListen(err,s,p->ai_addr,p->ai_addrlen,backlog,0) == ANET_ERR) s = ANET_ERR;
        goto end;
    }

    if (p == NULL)
    {
        _anetSetError(err, "unable to bind socket, errno: %d", errno);
        goto error;
    }

error:
    if (s != -1) close(s);
    s = ANET_ERR;

end:
    freeaddrinfo(servinfo);

    return s;
}

static int _anetTcpGenericConnect(char *err, const char *addr, int port,
                                 const char *source_addr, int flags)
{
    int s = ANET_ERR, rv;
    char portstr[6];  /* strlen("65535") + 1; */
    struct addrinfo hints, *servinfo, *bservinfo, *p, *b;

    snprintf(portstr,sizeof(portstr),"%d",port);
    memset(&hints,0,sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(addr,portstr,&hints,&servinfo)) != 0) 
    {
        _anetSetError(err, "%s", gai_strerror(rv));
        return ANET_ERR;
    }

    for (p = servinfo; p != NULL; p = p->ai_next) 
    {
        /* Try to create the socket and to connect it.
         * If we fail in the socket() call, or on connect(), we retry with
         * the next entry in servinfo. */
        if ((s = socket(p->ai_family,p->ai_socktype,p->ai_protocol)) == -1)
        {
            continue;
        }

        if (anetSetReuseAddr(err,s) == ANET_ERR)
        {
            goto error;
        }

        if (flags & ANET_CONNECT_NONBLOCK && anetNonBlock(err,s) != ANET_OK)
        {
            goto error;
        }

        if (source_addr) 
        {
            int bound = 0;
            /* Using getaddrinfo saves us from self-determining IPv4 vs IPv6 */
            if ((rv = getaddrinfo(source_addr, NULL, &hints, &bservinfo)) != 0)
            {
                _anetSetError(err, "%s", gai_strerror(rv));
                goto error;
            }

            for (b = bservinfo; b != NULL; b = b->ai_next) 
            {
                if (bind(s,b->ai_addr,b->ai_addrlen) != -1) 
                {
                    bound = 1;
                    break;
                }
            }

            freeaddrinfo(bservinfo);

            if (!bound) 
            {
                _anetSetError(err, "bind: %s", strerror(errno));
                goto error;
            }
        }

        if (connect(s,p->ai_addr,p->ai_addrlen) == -1) 
        {
            /* If the socket is non-blocking, it is ok for connect() to
             * return an EINPROGRESS error here. */
            if (errno == EINPROGRESS && flags & ANET_CONNECT_NONBLOCK)
            {
                goto end;
            }

            close(s);
            s = ANET_ERR;
            continue;
        }

        /* If we ended an iteration of the for loop without errors, we
         * have a connected socket. Let's return to the caller. */
        goto end;
    }

    if (p == NULL)
    {
        _anetSetError(err, "creating socket: %s", strerror(errno));
    }

error:
    if (s != ANET_ERR) {
        close(s);
        s = ANET_ERR;
    }

end:
    freeaddrinfo(servinfo);

    /* Handle best effort binding: if a binding address was used, but it is
     * not possible to create a socket, try again without a binding address. */
    if (s == ANET_ERR && source_addr && (flags & ANET_CONNECT_BE_BINDING)) 
    {
        return _anetTcpGenericConnect(err,addr,port,NULL,flags);
    } 
    else
    {
        return s;
    }
}

int anetCreateSocket(char *err, int domain)
{
    int s;
    s = socket(domain, SOCK_STREAM, 0);
    if(-1 == s)
    {
        _anetSetError(err, "creating socket: %s", strerror(errno));
        return ANET_ERR;
    }

    if (anetSetReuseAddr(err,s) == ANET_ERR) 
    {
        close(s);
        return ANET_ERR;
    }

    return s;
}

int anetCreateSocket_UDP(char *err, int domain)
{
    int s;
    s = socket(domain, SOCK_DGRAM, 0);
    if(-1 == s)
    {
        _anetSetError(err, "creating socket: %s", strerror(errno));
        return ANET_ERR;
    }

    return s;
}

int anetTcpServer(char *err, int port, char *bindaddr, int backlog)
{
    return _anetTcpServer(err, port, bindaddr, AF_INET, backlog);
}

int anetTcp6Server(char *err, int port, char *bindaddr, int backlog)
{
    return _anetTcpServer(err, port, bindaddr, AF_INET6, backlog);
}

int anetTcpAccept(char *err, int serversock, char *ip, size_t ip_len, int *port)
{
    int fd;
    struct sockaddr_storage sa;
    socklen_t salen = sizeof(sa);
    if ((fd = _anetGenericAccept(err,serversock,(struct sockaddr*)&sa,&salen)) == ANET_ERR)
    {
        return ANET_ERR;
    }

    if (sa.ss_family == AF_INET) 
    {
        struct sockaddr_in *s = (struct sockaddr_in *)&sa;
        if (ip) inet_ntop(AF_INET,(void*)&(s->sin_addr),ip,ip_len);
        if (port) *port = ntohs(s->sin_port);
    } 
    else 
    {
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)&sa;
        if (ip) inet_ntop(AF_INET6,(void*)&(s->sin6_addr),ip,ip_len);
        if (port) *port = ntohs(s->sin6_port);
    }

    return fd;
}

int anetTcpNonBlockConnect(char *err, const char *addr, int port)
{
    return _anetTcpGenericConnect(err,addr,port,NULL,ANET_CONNECT_NONBLOCK);
}

int anetSetReuseAddr(char *err, int fd)
{
    int yes = 1;
    /* Make sure connection-intensive things like the redis benchmark
     * will be able to close/open sockets a zillion of times */
    if(-1 == setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes))) 
    {
        _anetSetError(err, "setsockopt SO_REUSEADDR: %s", strerror(errno));
        return ANET_ERR;
    }

    return ANET_OK;
}

int anetNonBlock(char *err, int fd) 
{
    return _anetSetBlock(err,fd,1);
}

int anetBlock(char *err, int fd) 
{
    return _anetSetBlock(err,fd,0);
}

/* Enable the FD_CLOEXEC on the given fd to avoid fd leaks. 
 * This function should be invoked for fd's on specific places 
 * where fork + execve system calls are called. */
int anetCloexec(int fd) 
{
    int r;
    int flags;

    do 
    {
        r = fcntl(fd, F_GETFD);
    } while (r == -1 && errno == EINTR);

    if (r == -1 || (r & FD_CLOEXEC))
        return r;

    flags = r | FD_CLOEXEC;

    do 
    {
        r = fcntl(fd, F_SETFD, flags);
    } while (r == -1 && errno == EINTR);

    return r;
}

int anetWrite(int fd,const char *buf,int write_len)
{
    int nsended = 0;
    int ret = 0;

    do
    {
        ret = write(fd,buf + nsended,write_len - nsended);
        if(ret > 0)
        {
            nsended = nsended + ret;
        }
        else if(0 == ret)
        {
            break;
        }
        else
        {
            if(EAGAIN == errno ||
                EWOULDBLOCK == errno ||
                EINTR == errno ||
                ENOTCONN == errno)
            {
                continue;
            }
            else
            {
                break;
            }
        }

        if(nsended == write_len)
        {
            break;
        }

    } while (1);
    
    return nsended;
}

int anetRead(int fd,char *buf,int read_len)
{
    int nreaded = 0;

    int ret = 0;

    do
    {
        ret = read(fd,buf + nreaded,read_len - nreaded);
        if(ret > 0)
        {
            nreaded = nreaded + ret;
        }
        else if(0 == ret)
        {
            break;
        }
        else
        {
            if(EAGAIN == errno ||
                EWOULDBLOCK == errno ||
                EINTR == errno)
            {
                continue;
            }
            else
            {
                break;
            }
        }

        ///if(nreaded == read_len)
        {
            break;
        }

    } while (1);
    
    return nreaded;
}

int anetSendTimeout(char *err, int fd, long long ms)
{
    struct timeval tv;

    tv.tv_sec = ms/1000;
    tv.tv_usec = (ms%1000)*1000;

    if(-1 == setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)))
    {
        _anetSetError(err, "setsockopt SO_SNDTIMEO: %s", strerror(errno));
        return ANET_ERR;
    }

    return ANET_OK;
}

int anetRecvTimeout(char *err, int fd, long long ms)
{
    struct timeval tv;

    tv.tv_sec = ms/1000;
    tv.tv_usec = (ms%1000)*1000;

    if(-1 == setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv))) 
    {
        _anetSetError(err, "setsockopt SO_RCVTIMEO: %s", strerror(errno));
        return ANET_ERR;
    }
    
    return ANET_OK;
}
