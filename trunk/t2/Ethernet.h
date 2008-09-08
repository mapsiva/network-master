/**
	Universidade Federal de Mato Grosso do Sul
	Mestrado em Ci�ncia da Computa��o DCT - UFMS
	Redes de Computadores 2008
	
	M�rcio Aparecido Inacio da Silva
	Maxwell Sampaio dos Santos
	
	Xnoop - Analizador de Pacotes [Trabalho 1]
*/
#ifndef ETHERNET_H_
#define ETHERNET_H_
#include "Types.h"
#include "PackageHeader.h"

typedef struct
{
	BYTE receiver[6];
	BYTE sender[6];
	SWORD type;
}ETHERNET_HEADER;		

CHAR_T*
trace_ethernet(ETHERNET_HEADER *, int,  FRAME_HEADER *, int, int*, int*); 

int is_broadcast(BYTE *);

#endif 
