
#include "adlist.h"

/*
 * Add a node that has already been allocated to the head of list
 */
static void _listLinkNodeHead(list* list, listNode *node) 
{
    if (list->len == 0) 
    {
        list->head = list->tail = node;
        node->prev = node->next = NULL;
    } 
    else 
    {
        node->prev = NULL;
        node->next = list->head;

        list->head->prev = node;
        list->head = node;
    }

    list->len++;
}

/*
 * Add a node that has already been allocated to the tail of list
 */
static void _listLinkNodeTail(list *list, listNode *node) 
{
    if (list->len == 0) 
    {
        list->head = list->tail = node;
        node->prev = node->next = NULL;
    } 
    else 
    {
        node->prev = list->tail;
        node->next = NULL;
        
        list->tail->next = node;
        list->tail = node;
    }

    list->len++;
}

list *listCreate()
{
    list *list = malloc(sizeof(struct list));

    if (NULL == list)
    {
        return NULL;
    }

    list->head = list->tail = NULL;
    list->len = 0;

    list->dup = NULL;
    list->free = NULL;
    list->match = NULL;

    return list;
}

void listRelease(list *list)
{
    listEmpty(list);
    free(list);
    list = NULL;
}

void listEmpty(list *list)
{
    unsigned long len = list->len;
    listNode *current, *next;

    current = list->head;
    while(len--) 
    {
        next = current->next;
        if (list->free) 
        {
            list->free(current->value);
        }

        free(current);
        current = next;
    }

    list->head = list->tail = NULL;
    list->len = 0;
}

list *listAddNodeHead(list *list, void *value)
{
    listNode *node = malloc(sizeof(struct listNode));
    if(NULL == node)
    {
        return NULL;
    }

    node->value = value;
    _listLinkNodeHead(list, node);
    
    return list;
}

list *listAddNodeTail(list *list, void *value)
{
    listNode *node = malloc(sizeof(struct listNode));
    if(NULL == node)
    {
        return NULL;
    }

    node->value = value;
    _listLinkNodeTail(list, node);
    
    return list;
}
