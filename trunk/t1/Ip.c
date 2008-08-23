#ifndef IP_C_
#define IP_C_
#include "Types.h"
#include "Ip.h"	
#include "Util.h"	
#include <stdio.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

CHAR_T*
trace_ip( IP_HEADER * pkg)
{
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
        

    
    printf("IP: Source address =  %s",  format_address(pkg->source_address));
    resolve_address(pkg->source_address);
    printf("IP: Destination address =  %s",  format_address(pkg->destination_address));
    resolve_address(pkg->destination_address);
    return 0;
}


/*Fun*/
CHAR_T*
resolve_address(WORD  address) 
{   
     resolved = gethostbyaddr((unsigned char*)&address,  sizeof (address), AF_INET);
     
     if(resolved)
        printf(", %s\n", resolved->h_name);
     else   
        printf("\n");
        
     return 0;
}

CHAR_T*
format_address(WORD  address) 
{
    CHAR_T * IP = (CHAR_T *) &address,  name[100];
     
    sprintf(name, "%u.%u.%u.%u", *IP, *IP+2, *IP+2, *IP+3);
    
    return name;
}

#endif 
