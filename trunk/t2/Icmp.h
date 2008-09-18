/**
	Universidade Federal de Mato Grosso do Sul
	Mestrado em Ci�ncia da Computa��o DCT - UFMS
	Redes de Computadores 2008
	
	M�rcio Aparecido Inacio da Silva
	Maxwell Sampaio dos Santos
	
	Subnet
*/
#ifndef ICMP_H_
#define ICMP_H_
#include "Types.h"
#include <netdb.h>
/*
* Estrutura que representa o cabe�alho ICMP
*/
typedef struct
{
	BYTE type;
 	BYTE code;
	SWORD checksum;
}ICMP_HEADER;		

/*
* Imprime o conte�do de um cabe�alho ICMP
*/
CHAR_T*
trace_icmp( ICMP_HEADER *, int, int);

/*
* Mostra o tipo
*/
void 
view_type_icmp ( ICMP_HEADER *, int);

#endif /*ICMP_H_*/
