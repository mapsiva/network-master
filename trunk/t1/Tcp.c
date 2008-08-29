/**
	Universidade Federal de Mato Grosso do Sul
	Mestrado em Ciência da Computação DCT - UFMS
	Redes de Computadores 2008
	
	Márcio Aparecido Inacio da Silva
	Maxwell Sampaio dos Santos
	
	Xnoop - Analizador de Pacotes [Trabalho 1]
*/
#ifndef TCP_C_
#define TCP_C_
#include "Tcp.h"
#include "Types.h"
#include <netdb.h>
#include <stdio.h>
#include <string.h>


CHAR_T*
trace_tcp( TCP_HEADER * pkg, int modo)
{
	if (modo == VERB_EXT)
	{
		printf("TCP: ----- TCP Header -----\n");
		printf("TCP:\n");
		printf("TCP: Source Port = %u", ntohs(pkg->src_port));
		
		view_service (pkg->src_port, modo);
		
		printf("TCP: Destination Port = %u", ntohs(pkg->dest_port));
		
		view_service (pkg->dest_port, modo);
		
		printf("TCP: Sequence Number = %u\n", ntohl(pkg->seq_number_port));    
		printf("TCP: Acknowledgement number = %u\n", ntohl(pkg->ack));
		printf("TCP: Data offset = %u bytes\n", (unsigned int) ((pkg->offset >> 12)& 0x000F)<< 2); /* x4*/
		
		view_flags ( pkg );
		
		printf("TCP: Window = %u\n", ntohs(pkg->window));
		printf("TCP: Cheksum = 0%04X\n", ntohs(pkg->checksum));
		printf("TCP: Urgent Pointer = %u\n", ntohs(pkg->urgent_pointer));
	   
		if ((((pkg->offset >> 12)& 0x000F)<< 2) == sizeof (WORD))
		    printf ("TCP: No options\n");
		else
		    printf ("TCP: With options\n");
		  
		view_data ( pkg );
		
		printf ("TCP:\n\n");
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
view_service( SWORD port, int modo)
{
    struct servent *serv = getservbyport(port ,"tcp");
    
    if (modo == VERB_EXT)
   	{
		if((serv != NULL && ntohs( port )<=1024))
			printf(" (%s)", serv->s_name);
    	printf("\n");
    }
    else if (modo == VERB)
    {
    	if(serv != NULL && ntohs( port )<=1024)
			printf("%s ", serv->s_name);
    }
}

void
view_flags ( TCP_HEADER * pkg)
{  
    printf ("TCP: Flags = 0x%02X\n", pkg->offset & 0x003F);
    printf ("TCP: \t ..%d. .... = %s\n", (pkg->offset & BIN32) >> 5, ((pkg->offset & BIN32) >> 5)?"Urgent Pointer":"No Urgent Pointer");
    printf ("TCP: \t ...%d .... = %s\n", (pkg->offset & BIN16) >> 4, ((pkg->offset & BIN16) >> 4)?"Acknowledgement":"No Acknowledgement");
    printf ("TCP: \t .... %d... = %s\n", (pkg->offset & BIN8) >> 3, ((pkg->offset & BIN8) >> 3)?"Push":"No Push");
    printf ("TCP: \t .... .%d.. = %s\n", (pkg->offset & BIN4) >> 2, ((pkg->offset & BIN4) >> 2)?"Reset":"No Reset");
    printf ("TCP: \t .... ..%d. = %s\n", (pkg->offset & BIN2) >> 1, ((pkg->offset & BIN2) >> 1)?"Syn":"No Syn");
    printf ("TCP: \t .... ...%d = %s\n", (pkg->offset & BIN1), ((pkg->offset & BIN1))?"Fin":"No Fin");
}

void
view_data ( TCP_HEADER * pkg)
{
    BYTE *byteEX = &pkg->fisrt_data;
    BYTE *byteCHAR = &pkg->fisrt_data;
    int i, j;
    printf ("TCP: Data: First 64 bytes\n");
    
    for (i=0; i< 4; i++)
    {
        printf("TCP: ");
        
        for(j = 0; j< 8; j++ )            
            printf ("%04X ", *(byteEX++));
        
        printf("\"");
        for(j = 0; j< 16; j++ )
        {
            if((int)(*byteCHAR) <=32)
                printf(".");
            else
                printf("%c", (char)(*byteCHAR));
            
            byteCHAR++;
        }
        printf("\"\n");
    }
}
#endif
