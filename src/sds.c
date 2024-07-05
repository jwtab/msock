
#include <sds.h>

#include <zmalloc.h>

static sds *_sdsMakeRoomFor(sds *s, size_t addlen)
{
    uint32_t len = sdsLength(s);
    uint32_t avail = sdsAvail(s);

    // 判断剩余空间是否足够.
    if(avail > addlen)
    {
        return s;
    }

    // 追加新空间.
    uint32_t new_alloc_len = s->alloc + addlen + 1;
    char * new_data = zmalloc(new_alloc_len);
    if(NULL == new_data)
    {
        return NULL;
    }

    char *old_data = s->data;

    s->data = new_data;
    memcpy(s->data,old_data,len);
    s->alloc = new_alloc_len;

    zfree(old_data);
    old_data = NULL;

    return s;
}

static sds * _sds_new(const void *init,uint32_t initlen)
{
    sds * s = (sds*)zmalloc(sizeof(sds));
    if(NULL == s)
    {
        return s;
    }

    s->alloc = 2*initlen;
    s->data = zmalloc(s->alloc);
    if(s->data)
    {
        s->len = initlen;

        memcpy(s->data,init,initlen);
        s->data[initlen] = '\0';
    }
    
    return s;
}

sds *sdsCreateEmpty(uint32_t initsize)
{
    sds * s = (sds*)zmalloc(sizeof(sds));
    if(NULL == s)
    {
        return s;
    }

    s->alloc = initsize;
    s->data = zmalloc(s->alloc);
    if(s->data)
    {
        s->len = 0;
        s->data[0] = '\0';
    }
    
    return s;
}

sds *sdsCreateL(const void *init, uint32_t initlen)
{
    return _sds_new(init,initlen);
}

sds *sdsCreate(const char *init)
{
    return _sds_new(init,strlen(init));
}

sds *sdsDup(const sds *s)
{
    return _sds_new(sdsString(s,0),sdsLength(s));
}

void sdsRelease(sds *s)
{
    if(NULL == s)
    {
        return;
    }

    if(NULL != s->data)
    {
        zfree(s->data);
        s->data = NULL;
    }
    
    zfree(s);
    s = NULL;
}

void sdsEmpty(sds *s)
{
    if(s)
    {
        s->len = 0;
        s->data[0] = '\0';
    }
}

uint32_t sdsLength(const sds *s)
{
    return s->len;
}

uint32_t sdsAvail(const sds *s)
{
    return s->alloc - s->len;
}

const char * sdsString(const sds *s,uint32_t pos)
{
    return s->data + pos;
}

sds *sdsCatsds(sds *s, const sds t)
{
    return s;
}

sds *sdsCatlen(sds *s, const void *t, size_t len)
{
    uint32_t curlen = sdsLength(s);

    s = _sdsMakeRoomFor(s,len);
    if (NULL == s) 
    {
        return NULL;
    }

    memcpy(s->data + curlen, t, len);
    s->len = curlen + len;
    s->data[curlen + len] = '\0';

    return s;
}

sds *sdsCat(sds *s, const char *t)
{
    return sdsCatlen(s, t, strlen(t));
}

sds *sdsCpylen(sds *s, const char *t, size_t len)
{
    if (s->alloc < len) 
    {
        s = _sdsMakeRoomFor(s,len);
        if (NULL == s)
        {
            return NULL;
        }
    }

    memcpy(s->data, t, len);
    s->len = len;
    s->data[len] = '\0';
    
    return s;
}

sds *sdsCpy(sds *s, const char *t)
{
    return sdsCpylen(s,t,strlen(t));
}

sds *sdsCatvprintf(sds *s, const char *fmt, va_list ap)
{
    va_list cpy;
    char staticbuf[1024];
    char *buf = staticbuf;
    sds *t = NULL;

    size_t buflen = strlen(fmt)*2;
    int bufstrlen = 0;

    if (buflen > sizeof(staticbuf)) 
    {
        buf = zmalloc(buflen);
        if (buf == NULL) 
        {
            return NULL;
        }
    } 
    else 
    {
        buflen = sizeof(staticbuf);
    }

    /* Alloc enough space for buffer and \0 after failing to
     * fit the string in the current buffer size. */
    while(1) 
    {
        va_copy(cpy,ap);
        bufstrlen = vsnprintf(buf, buflen, fmt, cpy);
        va_end(cpy);
        if (bufstrlen < 0) 
        {
            if (buf != staticbuf) 
            {
                zfree(buf);
            }

            return NULL;
        }

        if (((size_t)bufstrlen) >= buflen) 
        {
            if (buf != staticbuf)
            {
                zfree(buf);
            }

            buflen = ((size_t)bufstrlen) + 1;
            buf = zmalloc(buflen);
            if (NULL == buf) 
            {
                return NULL;
            }

            continue;
        }

        break;
    }

    /* Finally concat the obtained string to the SDS string and return it. */
    t = sdsCatlen(s, buf, bufstrlen);
    if (buf != staticbuf) 
    {
        zfree(buf);
    }

    return t;
}

sds *sdsCatprintf(sds *s, char const *fmt, ...)
{
    va_list ap;

    sds *t;
    va_start(ap, fmt);
    t = sdsCatvprintf(s,fmt,ap);
    va_end(ap);

    return t;
}

char sdsChar(sds *s,uint32_t index)
{
    if(index >= sdsLength(s))
    {
        return 0;
    }

    return s->data[index];
}
