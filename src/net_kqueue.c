
#include <unistd.h>
#include <errno.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef __APPLE__

#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>

#include <zmalloc.h>
#include <net_kqueue.h>

#define EVENT_MASK_MALLOC_SIZE(sz) (((sz) + 3) / 4)
#define EVENT_MASK_OFFSET(fd) ((fd) % 4 * 2)
#define EVENT_MASK_ENCODE(fd, mask) (((mask) & 0x3) << EVENT_MASK_OFFSET(fd))

static inline int getEventMask(const char *eventsMask, int fd) {
    return (eventsMask[fd/4] >> EVENT_MASK_OFFSET(fd)) & 0x3;
}

static inline void addEventMask(char *eventsMask, int fd, int mask) {
    eventsMask[fd/4] |= EVENT_MASK_ENCODE(fd, mask);
}

static inline void resetEventMask(char *eventsMask, int fd) {
    eventsMask[fd/4] &= ~EVENT_MASK_ENCODE(fd, 0x3);
}

int aeApiCreate(aeEventLoop *eventLoop) 
{
    aeApiState *state = zmalloc(sizeof(aeApiState));
    if(NULL == state) 
    {
        return -1;
    }

    state->events = zmalloc(sizeof(struct kevent)*eventLoop->setsize);
    if(NULL == state->events) 
    {
        zfree(state);
        return -1;
    }

    state->kqfd = kqueue();
    if(-1 == state->kqfd) 
    {
        zfree(state->events);
        zfree(state);
        return -1;
    }

    //anetCloexec(state->kqfd);
    state->eventsMask = zmalloc(EVENT_MASK_MALLOC_SIZE(eventLoop->setsize));
    memset(state->eventsMask, 0, EVENT_MASK_MALLOC_SIZE(eventLoop->setsize));
    eventLoop->apidata = state;

    return 0;
}

int aeApiResize(aeEventLoop *eventLoop, int setsize) 
{
    aeApiState *state = eventLoop->apidata;

    state->events = zrealloc(state->events, sizeof(struct kevent)*setsize);
    state->eventsMask = zrealloc(state->eventsMask, EVENT_MASK_MALLOC_SIZE(setsize));
    memset(state->eventsMask, 0, EVENT_MASK_MALLOC_SIZE(setsize));

    return 0;
}

void aeApiFree(aeEventLoop *eventLoop) 
{
    aeApiState *state = eventLoop->apidata;

    close(state->kqfd);

    zfree(state->events);
    zfree(state->eventsMask);

    zfree(state);
}

int aeApiAddEvent(aeEventLoop *eventLoop, int fd, int mask) 
{
    aeApiState *state = eventLoop->apidata;
    struct kevent ke;

    if (mask & AE_READABLE) 
    {
        EV_SET(&ke, fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
        if (-1 == kevent(state->kqfd, &ke, 1, NULL, 0, NULL)) 
        {
            return -1;
        }
    }

    if (mask & AE_WRITABLE) 
    {
        EV_SET(&ke, fd, EVFILT_WRITE, EV_ADD, 0, 0, NULL);
        if (-1 == kevent(state->kqfd, &ke, 1, NULL, 0, NULL)) 
        {
            return -1;
        }
    }

    return 0;
}

void aeApiDelEvent(aeEventLoop *eventLoop, int fd, int mask) 
{
    aeApiState *state = eventLoop->apidata;
    struct kevent ke;

    if (mask & AE_READABLE) 
    {
        EV_SET(&ke, fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
        kevent(state->kqfd, &ke, 1, NULL, 0, NULL);
    }

    if (mask & AE_WRITABLE) 
    {
        EV_SET(&ke, fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
        kevent(state->kqfd, &ke, 1, NULL, 0, NULL);
    }
}

int aeApiPoll(aeEventLoop *eventLoop, struct timeval *tvp) 
{
    aeApiState *state = eventLoop->apidata;
    int retval, numevents = 0;

    if (NULL != tvp) 
    {
        struct timespec timeout;
        timeout.tv_sec = tvp->tv_sec;
        timeout.tv_nsec = tvp->tv_usec * 1000;
        retval = kevent(state->kqfd, NULL, 0, state->events, eventLoop->setsize,&timeout);
    } 
    else 
    {
        retval = kevent(state->kqfd, NULL, 0, state->events, eventLoop->setsize,NULL);
    }

    if (retval > 0) 
    {
        int j;

        /* Normally we execute the read event first and then the write event.
         * When the barrier is set, we will do it reverse.
         * 
         * However, under kqueue, read and write events would be separate
         * events, which would make it impossible to control the order of
         * reads and writes. So we store the event's mask we've got and merge
         * the same fd events later. */
        for (j = 0; j < retval; j++) 
        {
            struct kevent *e = state->events+j;
            int fd = e->ident;
            int mask = 0; 

            if (e->filter == EVFILT_READ) 
            {
                mask = AE_READABLE;
            }
            else if (e->filter == EVFILT_WRITE) 
            {
                mask = AE_WRITABLE;
            }
            
            addEventMask(state->eventsMask, fd, mask);
        }

        /* Re-traversal to merge read and write events, and set the fd's mask to
         * 0 so that events are not added again when the fd is encountered again. */
        numevents = 0;
        for (j = 0; j < retval; j++) 
        {
            struct kevent *e = state->events+j;
            int fd = e->ident;
            int mask = getEventMask(state->eventsMask, fd);

            if (mask) 
            {
                eventLoop->fired[numevents].fd = fd;
                eventLoop->fired[numevents].mask = mask;
                resetEventMask(state->eventsMask, fd);
                numevents++;
            }
        }
    } 
    else if (retval == -1 && errno != EINTR) 
    {
        //panic("aeApiPoll: kevent, %s", strerror(errno));
        printf("aeApiPoll: kevent, %s", strerror(errno));
    }

    return numevents;
}

char *aeApiName(void) 
{
    return "kqueue";
}

#endif //__APPLE__
