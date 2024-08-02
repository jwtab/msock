
#include <mlog.h>
#include <zmalloc.h>

#include <sys/time.h>

static MLOG * g_mlog = NULL;

static void _mlog_write_to_files(MLOG *log)
{
    listNode *node = listFirst(log->logs);
    while(NULL != node)
    {
        sds *tmp = node->value;
        if(NULL != tmp)
        {
            fwrite(sdsPTR(tmp),sdsLength(tmp),1,log->file);
        }
        
        node = node->next;
    }
}

void _mlog_free_one_line(void *ptr)
{
    sds *line = (sds*)ptr;
    sdsRelease(line);
    line = NULL;
}

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

                g_mlog->logs = listCreate();
                if(NULL != g_mlog->logs)
                {
                    listSetFreeMethod(g_mlog->logs,_mlog_free_one_line);
                }
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
            _mlog_write_to_files(log);
            listRelease(log->logs);

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

int mlogPrintf(MLOG *log, char const *fmt, ...)
{
    if(NULL == log)
    {
        return -1;
    }
    
    sds * one = sdsCreateEmpty(1024);
    int size = 0;
    va_list ap;

    va_start(ap, fmt);
    sdsCatvprintf(one,fmt,ap);
    va_end(ap);

    listAddNodeTail(log->logs,one);

    size = listLength(log->logs);
    if(size > MLOG_FLUSH_LINE_COUNT)
    {
        _mlog_write_to_files(log);
        listEmpty(log->logs);
    }

    size = listLength(log->logs);
    return size;
}
