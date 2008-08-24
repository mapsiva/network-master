#ifndef TCP_C_
#define TCP_C_
#include "Tcp.h"
#include "Types.h"
#include <netdb.h>
#include <stdio.h>

CHAR_T*
trace_tcp( TCP_HEADER * pkg )
{
    printf("TCP: ----- TCP Header -----\n");
    printf("TCP:\n");
    printf("TCP: Source Port = %u", ntohs(pkg->src_port));
    view_service (pkg->src_port);
    printf("TCP: Destination Port = %u", ntohs(pkg->dest_port));
    view_service (pkg->dest_port);
    printf("TCP: Sequence Number = \n");    
    return 0;
}

void
view_service( SWORD port)
{
    struct servent *serv = getservbyport( port ,"tcp"); 
    
    if((serv != NULL && ntohs( port )<=1024))
	    printf(" (%s)\n", serv->s_name);
	else
	    printf("\n");
}
#endif
