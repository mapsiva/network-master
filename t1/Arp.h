/**
	Universidade Federal de Mato Grosso do Sul
	Mestrado em Ciência da Computação DCT - UFMS
	Redes de Computadores 2008
	
	Márcio Aparecido Inacio da Silva
	Maxwell Sampaio dos Santos
	
	Xnoop - Analizador de Pacotes [Trabalho 1]
*/
#ifndef ARP_H_
#define ARP_H_
#include "Types.h"
#include <netdb.h>

typedef struct  
{
    SWORD hardware_type;
    SWORD protocol_type;
    BYTE hardware_len;
    BYTE protocol_len;
    SWORD operation;
    BYTE sender_hardware_addr[6];
    WORD sender_ip_addr;
    BYTE target_hardware_addr[6];
    WORD target_ip_addr;
} ARP_HEADER;

CHAR_T*
trace_arp( ARP_HEADER *, int, int, int);

void 
view_type_arp ( ARP_HEADER *);

#endif /*ARP_H_*/
