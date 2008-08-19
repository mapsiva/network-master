#ifndef IP_C_
#define IP_C_
#include "Types.h"
#include "Ip.h"	
#include "Util.h"	
#include <stdio.h>
#include <netdb.h>
CHAR_T*
trace_ip( IP_HEADER * pkg)
{
    CHAR_T source[16];
    printf("IP: ----- IP Header -----\n");
    printf("IP:\n");
    printf("IP: Version = %u, header length = %u bytes\n", IP_VER(pkg), IP_IHL(pkg));
    printf("IP: Type of service = 0x%X \n", pkg->type_service);
    
    printf("IP: .... ....  \n");
    printf("IP: .... ....  \n");
    printf("IP: .... ....  \n");
    printf("IP: .... ....  \n");
    
    printf("IP: Total length =  %u bytes\n", ntohs(pkg->total_length));
    printf("IP: Identification =  %u \n", ntohs(pkg->identification));
    printf("IP: Flags =  0x%02X \n", IP_FLAGS(pkg));
    printf("IP: \t.%d.. .... \n", (ntohs(pkg->fragment) & 0x4FFF) >> 14);
    printf("IP: \t..%d. .... \n", (ntohs(pkg->fragment) & 0x2FFF) >> 13);
    printf("IP: Fragment offset =  %u bytes \n", IP_OFFSET(pkg));
    printf("IP: Time to alive =  %u seconds/hops \n", (pkg->time_alive));
    printf("IP: Protocol =  %u (%s)\n", (pkg->protocol), ((pkg->protocol==1)?"ICMP":(pkg->protocol==6)?"TCP":"UDP"));
    printf("IP: Header ckecksum =  %X \n", ntohs(pkg->checksum));
        
    resolve_address(ntohl(pkg->source_address), &source[0]);
    
    printf("IP: Source address =  %s \n",  source);
    
    resolve_address(ntohl(pkg->destination_address), &source[0]);
    printf("IP: Destination address =  %s \n",  source);
    
    return 0;
}


/*Ainda nao estah pronto*/
int
resolve_address(WORD  address, CHAR_T *ip) 
{
     CHAR_T * IP = (CHAR_T *) &address;
     WORD w_ip;
     
     sprintf(ip, "%u.%u.%u.%u", *IP, *IP+2, *IP+2, *IP+3);
     
     struct in_addr addr;
     
     inet_aton(ip, &addr);
     
     struct hostent *resolved = gethostbyaddr(&addr,  sizeof (addr), AF_INET);
     
     if(resolved)
        printf("%s", resolved->h_name);
        
     return 0;
}

#endif 
