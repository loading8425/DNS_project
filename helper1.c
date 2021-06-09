//  Comp30023_P2
//
//  Created by Mingyang on 27/4/21.
#include "helper1.h"
#include "cache.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>

int log_packet(unsigned char* message, FILE *fp, struct DNS_packet *packet){
    unsigned char buf[2];
    unsigned char dns[256];
    
    time_t rawtime;
    char buffer[80];
    
    memcpy(dns, message, 256);
    
    /* --------- process DNS request header --------- */
    memset(packet->label, 0, sizeof(packet->label));
    
    // read from stdin to get size first
    memcpy(buf, dns, 2);
    packet->size = (buf[0]<<8) + buf[1];
    
    //read all
    unsigned char buff[packet->size];
    unsigned char *p = dns;
    p += 2;
    memcpy(buff, p, packet->size);
    
    //read headers
    packet->QR = buff[2]>>7;
    
    //read label
    int len = buff[12];
    int i = 0;
    while(buff[i+12] != 0 && buff[i+1+12] != 0){
        if(i == len){
            i++;
            packet->label[i-1] = '.';
            len = len + buff[i+12] + 1;
            continue;
        }
        i++;
        packet->label[i-1] = buff[i+12];
    }
    
    // read type
    i = i+14;
    packet->req_type = (buff[i]<<8) + buff[i+1];

    // read ipv6 addr
    char ipv6_str[INET6_ADDRSTRLEN];
    if(packet->QR == 1){
        // read type
        packet->res_type = (buff[i+6]<<8) + buff[i+7];
        //read TTL
        packet->TTL_index = i+10+2;
        packet->TTL = (buff[i+10]<<24)+(buff[i+11]<<16)+(buff[i+12]<<8)+buff[i+13];
        if(packet->res_type != 28){
            return 4;
        }
        // read RD length
        i = i+14;
        packet->RDLENGTH = (buff[i]<<8) + buff[i+1];
        i+=2;

        for(int x=0; x<packet->RDLENGTH; x++){
            packet->ipv6[x] = buff[i++];
        }
        inet_ntop(AF_INET6, packet->ipv6, ipv6_str, INET6_ADDRSTRLEN);
        strcpy(packet->ipv6, ipv6_str);
    }
    
    // get current timestamp
    time(&rawtime);
    get_time(rawtime, buffer);
    
    /* -------------------- Log --------------------  */
    //request
    if(packet->QR == 0){
        fprintf(fp,"%s ", buffer);
        fprintf(fp,"requested %s\n", packet->label);
        
        // Not a AAAA type
        if( packet->req_type != 28){
            fprintf(fp,"%s ", buffer);
            fprintf(fp,"unimplemented request\n");
            return 4;
        }
        
    }else{
        //response
        if(packet->res_type != 28){
            return 4;
        }else{
            return 0;
        }
    }
    return 0;
}

void get_time(time_t rawtime, char *buffer){
    memset(buffer, 0, 80);
    struct tm *info = localtime(&rawtime);
    strftime(buffer, 80, "%FT%T%z", info);
}
