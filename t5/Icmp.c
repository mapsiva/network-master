/**
	Universidade Federal de Mato Grosso do Sul
	Mestrado em Ciência da Computação DCT - UFMS
	Redes de Computadores 2008
	
	Márcio Aparecido Inacio da Silva
	Maxwell Sampaio dos Santos
	
	Subnet
*/
#ifndef ICMP_C_
#define ICMP_C_
#include "Icmp.h"
#include "Types.h"
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
* Imprime o conteúdo de um cabeçalho ICMP
* @param pkg é o cabeçalho ICMP
* @param translation indica que haverá tradução de nomes ou não
* @param modo indica qual modo de execução do XNOOP (Modo verboso, verboso extendido, modo simples)
* @return CHAR_T* para uso futuro
*/

CHAR_T*
trace_icmp( ICMP_HEADER * pkg, int translation, int modo)
{
	if (modo == VERB_EXT)
	{
		printf("ICMP: ----- ICMP Header -----\n");
		printf("ICMP:\n");
		view_type_icmp ( pkg, modo);
		printf("ICMP: code = %u\n", pkg->code);
		printf("ICMP: Cheksum = 0%04X\n", ntohs(pkg->checksum));
		printf("ICMP:\n\n");
	}
	else if (modo == VERB)
		view_type_icmp ( pkg, modo);
	return 0;
}

/*
* Imprime o conteúdo de um cabeçalho ICMP
* @param pkg é o cabeçalho ICMP
* @param translation indica que haverá tradução de nomes ou não
* @return void
*/
void
view_type_icmp ( ICMP_HEADER * pkg, int modo)
{
	CHAR_T * text;
    text = (CHAR_T*) malloc (100);
     
    if (modo==VERB_EXT)
    	printf("ICMP: Type = %u ", pkg->type);
    
    switch (pkg->type)
    {
        case ECHO_REPLAY:
        	sprintf((char *)text, "Echo Reply");
            break;
        case DESTINATION_UN:
        	sprintf((char *)text, "Destination Unreachable");
            break;
        case SOURCE_QUENCH:
        	sprintf((char *)text, "Source Quench");
            break;
        case REDIRECT:
        	sprintf((char *)text, "Redirect");
            break;
        case ECHO_REQUEST:
        	sprintf((char *)text, "Echo Request");
            break;
        case ROUTER_AD:
        	sprintf((char *)text, "Router advertisement");
            break;
        case ROUTER_SOL:
        	sprintf((char *)text, "Router Solicitation");
            break;
        case TTL:
        	sprintf((char *)text, "TTL exceeded");
            break;
        case PP:
        	sprintf((char *)text, "Parameter Problem");
            break;
        case TIMESTAMP_REQUEST:
        	sprintf((char *)text, "Timestamp Request");
            break;
        case TIMESTAMP_REPLY:
        	sprintf((char *)text, "Timestamp Reply");
            break;
        case INFO_REQUEST:
        	sprintf((char *)text, "Information Request");
            break;
        case INFO_REPLY:
        	sprintf((char *)text, "Information Reply");
            break;
        case ADDRESS_MASK_REQUEST:
        	sprintf((char *)text, "Address Mask Request");
            break;
        case ADDRESS_MASK_REPLY:
        	sprintf((char *)text, "Address Mask Reply");
            break;
        default:
        	sprintf((char *)text, "Unknow code");
    }
    if (modo == VERB_EXT)    
    	printf("(%s)", text);
    else if(modo == VERB)
    	printf("%s", text);
    free(text);
    printf("\n");    	
}

#endif
