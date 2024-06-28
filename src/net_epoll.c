
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <string.h>

#include <stdlib.h>
#include <stdio.h>

#include <net_epoll.h>
#include <zmalloc.h>

#ifdef __linux__

int aeApiCreate(aeEventLoop *eventLoop) 
{
    aeApiState *state = zmalloc(sizeof(aeApiState));
    if (NULL == state) 
    {
        return -1;
    }

    state->events = zmalloc(sizeof(struct epoll_event)*eventLoop->setsize);
    if (NULL == state->events) 
    {
        zfree(state);

        return -1;
    }

    state->epfd = epoll_create(1024); /* 1024 is just a hint for the kernel */
    if (-1 == state->epfd)
    {
        zfree(state->events);
        zfree(state);

        return -1;
    }

    //anetCloexec(state->epfd);
    eventLoop->apidata = state;

    return 0;
}

int aeApiResize(aeEventLoop *eventLoop, int setsize) 
{
    aeApiState *state = eventLoop->apidata;
    if(state)
    {
        state->events = zrealloc(state->events, sizeof(struct epoll_event)*setsize);
    }

    return 0;
}

void aeApiFree(aeEventLoop *eventLoop) 
{
    aeApiState *state = eventLoop->apidata;
    if(state)
    {
        close(state->epfd);
        state->epfd = -1;

        zfree(state->events);
        state->events = NULL;

        zfree(state);
        state = NULL;
    }
}

int aeApiAddEvent(aeEventLoop *eventLoop, int fd, int mask) 
{
    aeApiState *state = eventLoop->apidata;
    struct epoll_event ee = {0}; /* avoid valgrind warning */
    /* If the fd was already monitored for some event, we need a MOD
     * operation. Otherwise we need an ADD operation. */
    int op = eventLoop->events[fd].mask == AE_NONE ?
            EPOLL_CTL_ADD : EPOLL_CTL_MOD;

    ee.events = 0;
    mask |= eventLoop->events[fd].mask; /* Merge old events */
    if (mask & AE_READABLE)
    {
        ee.events |= EPOLLIN;
    }

    if (mask & AE_WRITABLE)
    {
        ee.events |= EPOLLOUT;
    }

    ee.data.fd = fd;

    if(-1 == epoll_ctl(state->epfd,op,fd,&ee)) 
    {
        return -1;
    }

    return 0;
}

void aeApiDelEvent(aeEventLoop *eventLoop, int fd, int delmask) 
{
    aeApiState *state = eventLoop->apidata;
    struct epoll_event ee = {0}; /* avoid valgrind warning */
    int mask = eventLoop->events[fd].mask & (~delmask);

    ee.events = 0;
    if (mask & AE_READABLE) ee.events |= EPOLLIN;
    if (mask & AE_WRITABLE) ee.events |= EPOLLOUT;
    ee.data.fd = fd;

    if (mask != AE_NONE) 
    {
        epoll_ctl(state->epfd,EPOLL_CTL_MOD,fd,&ee);
    } 
    else
    {
        /* Note, Kernel < 2.6.9 requires a non null event pointer even for
         * EPOLL_CTL_DEL. */
        epoll_ctl(state->epfd,EPOLL_CTL_DEL,fd,&ee);
    }
}

int aeApiPoll(aeEventLoop *eventLoop, struct timeval *tvp) 
{
    aeApiState *state = eventLoop->apidata;
    int retval, numevents = 0;

    retval = epoll_wait(state->epfd,state->events,eventLoop->setsize,
            tvp ? (tvp->tv_sec*1000 + (tvp->tv_usec + 999)/1000) : -1);
    if (retval > 0) 
    {
        int j;

        numevents = retval;
        for (j = 0; j < numevents; j++) 
        {
            int mask = 0;
            struct epoll_event *e = state->events+j;

            if (e->events & EPOLLIN) mask |= AE_READABLE;
            if (e->events & EPOLLOUT) mask |= AE_WRITABLE;
            if (e->events & EPOLLERR) mask |= AE_WRITABLE|AE_READABLE;
            if (e->events & EPOLLHUP) mask |= AE_WRITABLE|AE_READABLE;
            eventLoop->fired[j].fd = e->data.fd;
            eventLoop->fired[j].mask = mask;
        }
    } 
    else if (retval == -1 && errno != EINTR) 
    {
        //panic("aeApiPoll: epoll_wait, %s", strerror(errno));
        printf("aeApiPoll: epoll_wait, %s \r\n", strerror(errno));
    }

    return numevents;
}

char *aeApiName(void) 
{
    return "epoll";
}

#endif //__linux__