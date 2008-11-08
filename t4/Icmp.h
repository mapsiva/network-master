/**
	Universidade Federal de Mato Grosso do Sul
	Mestrado em Cincia da Computao DCT - UFMS
	Redes de Computadores 2008
	
	Mrcio Aparecido Inacio da Silva
	Maxwell Sampaio dos Santos
	
	Subnet
*/
#ifndef ICMP_H_
#define ICMP_H_
#include "Types.h"
#include <netdb.h>
/*
* Estrutura que representa o cabealho ICMP
*/
typedef struct
{
	BYTE type;
 	BYTE code;
	SWORD checksum;
}ICMP_HEADER;

/*
* Imprime o contedo de um cabealho ICMP
*/
CHAR_T*
trace_icmp( ICMP_HEADER *, int, int);

/*
* Mostra o tipo
*/
void 
view_type_icmp ( ICMP_HEADER *, int);

#endif /*ICMP_H_*/
