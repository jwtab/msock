
#ifndef __S5_UDP_H__
#define __S5_UDP_H__

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int s5udp_running();
int s5udp_start(const char *host,short port);
void s5udp_stop();

void s5udp_process(void *arg);

#endif //__S5_UDP_H__
