
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <errno.h>
#include <net_inc.h>
#include <zmalloc.h>

/**
#ifdef __APPLE__

#include <net_select.h>

int aeApiCreate(aeEventLoop *eventLoop) 
{
    aeApiState *state = zmalloc(sizeof(aeApiState));
    if(NULL == state)
    {
        return -1;
    }

    FD_ZERO(&state->rfds);
    FD_ZERO(&state->wfds);
    eventLoop->apidata = state;

    return 0;
}

int aeApiResize(aeEventLoop *eventLoop, int setsize) 
{
    //AE_NOTUSED(eventLoop);

    if (setsize >= FD_SETSIZE) 
    {
        return -1;
    }

    return 0;
}

void aeApiFree(aeEventLoop *eventLoop) 
{
    zfree(eventLoop->apidata);
}

int aeApiAddEvent(aeEventLoop *eventLoop, int fd, int mask) 
{
    aeApiState *state = eventLoop->apidata;

    if (mask & AE_READABLE) FD_SET(fd,&state->rfds);
    if (mask & AE_WRITABLE) FD_SET(fd,&state->wfds);

    return 0;
}

void aeApiDelEvent(aeEventLoop *eventLoop, int fd, int mask) 
{
    aeApiState *state = eventLoop->apidata;

    if (mask & AE_READABLE) FD_CLR(fd,&state->rfds);
    if (mask & AE_WRITABLE) FD_CLR(fd,&state->wfds);
}

int aeApiPoll(aeEventLoop *eventLoop, struct timeval *tvp) 
{
    aeApiState *state = eventLoop->apidata;
    int retval, j, numevents = 0;

    memcpy(&state->_rfds,&state->rfds,sizeof(fd_set));
    memcpy(&state->_wfds,&state->wfds,sizeof(fd_set));

    retval = select(eventLoop->maxfd+1,&state->_rfds,&state->_wfds,NULL,tvp);
    if (retval > 0) 
    {
        for (j = 0; j <= eventLoop->maxfd; j++) 
        {
            int mask = 0;
            aeFileEvent *fe = &eventLoop->events[j];

            if (fe->mask == AE_NONE) continue;
            if (fe->mask & AE_READABLE && FD_ISSET(j,&state->_rfds))
                mask |= AE_READABLE;
            if (fe->mask & AE_WRITABLE && FD_ISSET(j,&state->_wfds))
                mask |= AE_WRITABLE;
            eventLoop->fired[numevents].fd = j;
            eventLoop->fired[numevents].mask = mask;
            numevents++;
        }
    } 
    else if (retval == -1 && errno != EINTR) 
    {
        //panic("aeApiPoll: select, %s", strerror(errno));
        printf("aeApiPoll: select, %s \r\n", strerror(errno));
    }

    return numevents;
}

char *aeApiName(void) 
{
    return "select";
}

#endif //__APPLE__
*/