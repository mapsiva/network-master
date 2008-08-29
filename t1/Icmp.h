/**
	Universidade Federal de Mato Grosso do Sul
	Mestrado em Ciência da Computação DCT - UFMS
	Redes de Computadores 2008
	
	Márcio Aparecido Inacio da Silva
	Maxwell Sampaio dos Santos
	
	Xnoop - Analizador de Pacotes [Trabalho 1]
*/
#ifndef ICMP_H_
#define ICMP_H_
#include "Types.h"
#include <netdb.h>

typedef struct
{
	BYTE type;
 	BYTE code;
	SWORD checksum;
}ICMP_HEADER;		

CHAR_T*
trace_icmp( ICMP_HEADER *, int, int);

void 
view_type_icmp ( ICMP_HEADER *, int);

#endif /*ICMP_H_*/
