
#ifndef __NET_KQUEUE_H__
#define __NET_KQUEUE_H__

#include <net_inc.h>

#ifdef __APPLE__

typedef struct aeApiState 
{
    int kqfd;
    struct kevent *events;

    /* Events mask for merge read and write event.
     * To reduce memory consumption, we use 2 bits to store the mask
     * of an event, so that 1 byte will store the mask of 4 events. */
    char *eventsMask; 
} aeApiState;

int aeApiCreate(aeEventLoop *eventLoop);
int aeApiResize(aeEventLoop *eventLoop, int setsize);
void aeApiFree(aeEventLoop *eventLoop);
int aeApiAddEvent(aeEventLoop *eventLoop, int fd, int mask);
void aeApiDelEvent(aeEventLoop *eventLoop, int fd, int delmask);
int aeApiPoll(aeEventLoop *eventLoop, struct timeval *tvp);
char *aeApiName(void);

#endif //__APPLE__

#endif //__NET_KQUEUE_H__
