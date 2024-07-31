
#include <mlog.h>
#include <zmalloc.h>

#include <sys/time.h>

static MLOG * g_mlog = NULL;

MLOG * mlogNew(const char *log_path)
{
    if(NULL == g_mlog)
    {
        g_mlog = (MLOG*)zmalloc(sizeof(MLOG));
        if(NULL != g_mlog)
        {
            g_mlog->ref_count = 0;
            strcpy(g_mlog->log_path,log_path);
            
            g_mlog->file = fopen(g_mlog->log_path,"a+");
            if(NULL != g_mlog->file)
            {
                g_mlog->ref_count = 1;
            }
        }
    }
    else
    {
        return g_mlog;
    }

    return g_mlog;
}

void mlogRelease(MLOG *log)
{
    if(NULL != log)
    {
        log->ref_count--;

        if(log->ref_count <= 0)
        {
            fclose(log->file);
            log->file = NULL;

            zfree(log);
            log = NULL;
        }
    }
}

MLOG * mlogGet()
{
    if(NULL != g_mlog)
    {
        g_mlog->ref_count++;
    }
    
    return g_mlog;
}

void mlogUUID(char *uuid)
{
    char uuidgen_buf[1024] = {0};

    FILE * fp = popen("uuidgen -t","r");
    if(NULL != fp)
    {
        if(NULL != fgets(uuidgen_buf, sizeof(uuidgen_buf), fp))
        {
            strncpy(uuid,uuidgen_buf,36);
        }

        pclose(fp);
        fp = NULL;
    }
}

long mlogTick_ms()
{
    long ret = 0;
    struct timeval tm;

    gettimeofday(&tm,NULL);

    ret = 1000*tm.tv_sec + tm.tv_usec;

    return ret;
}

void mlogTick_gmt(char *gmt_str,int size)
{
    time_t now = time(NULL);
    struct tm *gmt = gmtime(&now);

    strftime(gmt_str,size,"%a,%d %b %Y %H:%M:%S GMT",gmt);
}
