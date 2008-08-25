#ifndef UDP_C_
#define UDP_C_
#include "Udp.h"
#include "Tcp.h"
#include "Types.h"
#include <netdb.h>
#include <stdio.h>

CHAR_T*
trace_udp( UDP_HEADER * pkg, int modo)
{
	if (modo == VERB_EXT)
	{
		printf("UDP: ----- UDP Header -----\n");
		printf("UDP:\n");
		printf("UDP: Source Port = %u\n", ntohs(pkg->src_port));
		printf("UDP: Destination Port = %u\n", ntohs(pkg->dest_port));
		printf("UDP: Length = %u\n", ntohs(pkg->length));
		printf("UDP: Cheksum = %u\n", ntohs(pkg->checksum));
		
		view_data_udp ( pkg );
		
		printf ("UDP:\n");
    }
    else if(modo == VERB)
	{
		view_service (pkg->src_port, modo);
		printf("sourceport=%u ", ntohs(pkg->src_port));
		printf("destport=%u", ntohs(pkg->dest_port));
		printf("\n");
	}
    return 0;
}

void
view_data_udp ( UDP_HEADER * pkg)
{
    BYTE *byteEX = &pkg->fisrt_data;
    BYTE *byteCHAR = &pkg->fisrt_data;
    int i, j;
    printf ("UDP: Data: First 64 bytes\n");
    
    for (i=0; i< 4; i++)
    {
        printf("UDP: ");
        
        for(j = 0; j< 8; j++ )            
            printf ("%04X ", *(byteEX++));
        
        printf("\"");
        for(j = 0; j< 16; j++ )
        {
            if((int)(*byteCHAR) <=20)
                printf(".");
            else
                printf("%c", (char)(*(byteCHAR)));
            
            byteCHAR++;
        }
        printf("\"\n");
    }
}
#endif
