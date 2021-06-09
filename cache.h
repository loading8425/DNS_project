//
//  helper.h
//  Comp30023_P2
//
//  Created by Mingyang on 27/4/21.

#ifndef cache_h
#define cache_h

#include <stdio.h>
#include <time.h>
#include "helper1.h"

typedef struct cache{
    unsigned char response[256];
    DNS_packet_t *packet_info;
    time_t time_receive;
    time_t time_expire;
    struct cache *next;
    
}cache_t;

cache_t* check_cache(cache_t *cache, DNS_packet_t *packet);
cache_t* create_cache(DNS_packet_t packet, unsigned char *buffer, cache_t *cache, int *num_cache, FILE *fp);
void replace_cache(DNS_packet_t packet, unsigned char *buffer, cache_t *old, FILE *fp);
void refresh_cache(cache_t * cache_find);
#endif /* cache_h */
