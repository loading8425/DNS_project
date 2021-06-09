#include "cache.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

cache_t * check_cache(cache_t *cache, DNS_packet_t *packet){
    cache_t *p;
    p = cache;
    
    if(cache == NULL){
        return NULL;
    }
    
    //check if it is in cache
    while(p!=NULL){
        if(strncmp(p->packet_info->label, packet->label, 255) == 0){
            return p;
        }
        p = p->next;
    }
    return NULL;
}

cache_t * create_cache(DNS_packet_t packet, unsigned char *buffer, cache_t *cache, int *num_cache, FILE *fp){
    //create a cache info
    time_t current;
    time(&current);
    
    cache_t *cache_tmp = (cache_t*)malloc(sizeof(cache_t));
    DNS_packet_t *pac = (DNS_packet_t*)malloc(sizeof(DNS_packet_t));
    strcpy(pac->label, packet.label);
    pac->TTL = packet.TTL;
    pac->TTL_index = packet.TTL_index;
    strcpy(pac->ipv6, packet.ipv6);
    
    memcpy(cache_tmp->response, buffer, 256);
    cache_tmp->packet_info = pac;
    cache_tmp->time_receive = current;
    cache_tmp->time_expire = current + packet.TTL;
    cache_tmp->next = NULL;
    
    if(cache == NULL){
        *num_cache += 1;
        return cache_tmp;
    }else{
        if(*num_cache >= 5){
            char domain1[256];
            char domain2[256];
            char t[80];
            strcpy(domain1 ,cache_tmp->packet_info->label);
            cache_tmp->next = cache;
            cache = cache_tmp;
            // free last one
            cache_t *p = cache;
            for(int i=0; i<4; i++){
                p = p->next;
            }
            strcpy(domain2 ,p->packet_info->label);
            free(p->next->packet_info);
            free(p->next);
            p->next = NULL;
            time(&current);
            get_time(current, t);
            fprintf(fp,"%s replacing %s by %s\n", t, domain2, domain1);
            
        }else{
            cache_tmp->next = cache;
            cache = cache_tmp;
            *num_cache += 1;
        }
    }
    return cache;
}

void replace_cache(DNS_packet_t packet, unsigned char *buffer, cache_t *old, FILE *fp){
    //free old cache dns packet
    free(old->packet_info);
    memset(old->response, 0, 256);
    
    //copy new cache info
    time_t current;
    time(&current);
    DNS_packet_t *pac = (DNS_packet_t*)malloc(sizeof(DNS_packet_t));
    strcpy(pac->label, packet.label);
    pac->TTL = packet.TTL;
    pac->TTL_index = packet.TTL_index;
    strcpy(pac->ipv6, packet.ipv6);
    
    memcpy(old->response, buffer, 256);
    old->packet_info = pac;
    old->time_receive = current;
    old->time_expire = current + packet.TTL;
    
    // Log info
    char t[80];
    char domain[256];
    strcpy(domain, old->packet_info->label);
    get_time(current, t);
    fprintf(fp,"%s replacing %s by %s\n", t, domain, domain);
}

void refresh_cache(cache_t * cache_find){
    int index = cache_find->packet_info->TTL_index;
    int new_TTL;
    int tmp;
    unsigned char TTL[4];
    memset(TTL,0,4);
    time_t current;
    time(&current);
    new_TTL = (int)(cache_find->time_expire - current);
    if(new_TTL>=16777216){
        tmp = new_TTL/16777216;
        new_TTL = new_TTL - tmp*16777216;
        TTL[0] = tmp;
    }
    if(new_TTL>=65536){
        tmp = new_TTL/65536;
        new_TTL = new_TTL - tmp*65536;
        TTL[1] = tmp;
    }
    if(new_TTL>=256){
        tmp = new_TTL/256;
        new_TTL = new_TTL - tmp*256;
        TTL[2] = tmp;
    }
    
    tmp = new_TTL/1;
    TTL[3] = tmp;
    cache_find->response[index] = TTL[0];
    cache_find->response[index+1] = TTL[1];
    cache_find->response[index+2] = TTL[2];
    cache_find->response[index+3] = TTL[3];
}
 
