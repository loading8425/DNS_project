#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "helper1.h"
#include "cache.h"

#define CACHE
#define PORT "8053"

int main(int argc, char** argv) {
    int sockfd, dns_sock,n, re, s, response_size, rcode;
    unsigned char buffer[512];
    struct addrinfo hints, *res, *servinfo, *rp;
    struct sockaddr_storage client_addr;
    socklen_t client_addr_size;
    
    DNS_packet_t packet;
    cache_t *cache = NULL;
    cache_t *cache_find = NULL;
    int cache_expire_flag = 0;
    int num_cache = 0;
    
    //set time variable
    time_t current;
    char tmp[80];
    
    // Create a log file
    FILE *fp;
    fp = fopen("./dns_svr.log", "w");
    if(!fp){
        perror("Failed to create log file");
        exit(1);
    }

    if (argc < 3) {
        fprintf(stderr, "ERROR, no port provided\n");
        exit(EXIT_FAILURE);
    }
    
    // Create address we're going to listen on (with given port number)
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;       // IPv4
    hints.ai_socktype = SOCK_STREAM; // TCP
    hints.ai_flags = AI_PASSIVE;     // for bind, listen, accept
    
    s = getaddrinfo(NULL, PORT, &hints, &res);
    if (s != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
        exit(EXIT_FAILURE);
    }
    
    // Create socket
    sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sockfd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    
    // Reuse port if possible
    re = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &re, sizeof(int)) < 0) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    
    // Bind address to the socket
    if (bind(sockfd, res->ai_addr, res->ai_addrlen) < 0) {
        perror("bind");
        exit(EXIT_FAILURE);
    }
    freeaddrinfo(res);

    // Get addrinfo of server
    if ((getaddrinfo(argv[1], argv[2], &hints, &servinfo)) < 0) {
        perror("getaddrinfo");
        exit(EXIT_FAILURE);
    }
    
    // Connect to first valid result
    for (rp = servinfo; rp != NULL; rp = rp->ai_next) {
        dns_sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sockfd == -1)
            continue;

        if (connect(dns_sock, rp->ai_addr, rp->ai_addrlen) != -1)
            break; // success

        close(dns_sock);
    }
    if (rp == NULL) {
        fprintf(stderr, "dns_server: failed to connect\n");
        exit(EXIT_FAILURE);
    }

    while(1){
        
        int newsockfd;
        // Listen on socket - means we're ready to accept connections,
 
        if (listen(sockfd, 10) < 0) {
            perror("listen");
            exit(EXIT_FAILURE);
        }
        printf("waiting client to send message.....\n");
        // Accept a connection - blocks until a connection is ready to be accepted
        client_addr_size = sizeof client_addr;
        
        newsockfd = accept(sockfd, (struct sockaddr*)&client_addr, &client_addr_size);
        if (newsockfd < 0) {
            perror("accept");
            exit(EXIT_FAILURE);
        }
        printf("client socket accpeted....\n");
        
/*----------------- read from client socket ------------------*/
        n = read(newsockfd, buffer, 512);
        if (n < 0) {
            perror("read");
            exit(EXIT_FAILURE);
        }
        response_size = (buffer[0]<<8)+buffer[1] + 2;
        
        while(n < response_size){
            unsigned char tmp[256];
            unsigned char *p = buffer;
            int len;
            memset(tmp, 0 ,256);
            p += n;
            len = read(newsockfd, tmp, 256);
            memcpy(p, tmp, len);
            n = n + len;
        }
        memset(&packet, 0, sizeof(packet));
        rcode = log_packet(buffer, fp, &packet);
        printf("Rcode= %d\n", rcode);
        fflush(fp);
        
        //check in cache
        cache_find = check_cache(cache, &packet);
        
        //check if cache found is expire
        if(cache_find!=NULL){
            time(&current);
            if(cache_find->time_expire < current){
                cache_expire_flag = 1;
            }
        }

        //Log cache find
        if(cache_find!=NULL && cache_expire_flag == 0 && rcode == 0){
            time(&current);
            get_time(current, tmp);
            fprintf(fp,"%s %s expires at ",tmp,cache_find->packet_info->label);
            get_time(cache_find->time_expire, tmp);
            fprintf(fp,"%s\n", tmp);
            time(&current);
            get_time(current, tmp);
            fprintf(fp, "%s %s is at %s\n", tmp, cache_find->packet_info->label, cache_find->packet_info->ipv6);
            
            fflush(fp);
            //set response ID
            (cache_find->response)[2] = buffer[2];
            (cache_find->response)[3] = buffer[3];
            
            //TTL decremented by the amount of time
            refresh_cache(cache_find);
            int len = (((cache_find->response)[0])<<8) + ((cache_find->response)[1]) + 2;
            n = write(newsockfd, cache_find->response, len);
            if (n < 0) {
                perror("write");
                exit(EXIT_FAILURE);
            }
            close(newsockfd);
            continue;
        }

/*----------------- forward to a dns server ------------------*/
        if(rcode != 4){
            // Send dns packet to server
            n = write(dns_sock, buffer, n);
            if (n < 0) {
                perror("socket");
                exit(EXIT_FAILURE);
            }
            
            // Read message from server
            memset(buffer, 0, 512);
            n = read(dns_sock, buffer, 512);
            
            if (n < 0) {
                perror("read");
                exit(EXIT_FAILURE);
            }
            
            response_size = (buffer[0]<<8)+buffer[1] + 2;
            
            if(n != response_size){
                perror("read");
                exit(EXIT_FAILURE);
            }
            
            memset(&packet, 0, sizeof(packet));
            rcode = log_packet(buffer, fp, &packet);
            //store into cache
            cache = create_cache(packet, buffer, cache, &num_cache, fp);
 
            if(cache_expire_flag == 1 && cache_find!=NULL){
                replace_cache(packet, buffer, cache_find, fp);
            }
            if(rcode==0){
                time(&current);
                get_time(current, tmp);
                fprintf(fp,"%s ", tmp);
                fprintf(fp,"%s is at %s\n", packet.label, packet.ipv6);
            }
            fflush(fp);
        
/*----------------- send back to client ------------------*/
        
            n = write(newsockfd, buffer, n);
            if (n < 0) {
                perror("write");
                exit(EXIT_FAILURE);
            }
            close(newsockfd);
        }else{
            buffer[4] = 128;
            buffer[5] = 4;
            n = write(newsockfd, buffer, n);
            if (n < 0) {
                perror("write");
                exit(EXIT_FAILURE);
            }
            close(newsockfd);
        }
    }
    close(sockfd);
    freeaddrinfo(servinfo);
    fclose(fp);
    return 0;
}
