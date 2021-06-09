//
//  helper.h
//  Comp30023_P2
//
//  Created by Mingyang on 27/4/21.

#ifndef helper1_h
#define helper1_h

#include <stdio.h>
#include <time.h>

typedef struct DNS_packet{
    
    int size;
    int ID;
    int QR;
    int RCODE;
    char label[256];
    int req_type;
    int res_type;
    int RDLENGTH;
    char ipv6[30];
    int TTL;
    int TTL_index;
    
}DNS_packet_t;

// interfaces
int log_packet(unsigned char* buffer, FILE *fp, struct DNS_packet *packet);
void get_time(time_t rawtime, char *buffer);

#endif /* helper1_h */
