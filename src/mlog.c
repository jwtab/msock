
#include <mlog.h>

#include <sys/time.h>

long mlogTick()
{
    long ret = 0;
    struct timeval tm;

    gettimeofday(&tm,NULL);

    ret = 1000*tm.tv_sec + tm.tv_usec;

    return ret;
}
