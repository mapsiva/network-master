/**
	Universidade Federal de Mato Grosso do Sul
	Mestrado em Ciência da Computação DCT - UFMS
	Redes de Computadores 2008
	
	Márcio Aparecido Inacio da Silva
	Maxwell Sampaio dos Santos
	
	Xnoop - Analizador de Pacotes [Trabalho 1]
*/
#ifndef ETHERNET_H_
#define ETHERNET_H_
#include "Types.h"
#include "PackageHeader.h"

typedef struct
{
    BYTE net;
	BYTE receiver[6];
	BYTE sender[6];
	SWORD type;
} ETHERNET_HEADER;

/* Estrutura usada para manipulação dos dados do arquivo TRACE*/
typedef struct
{
    //BYTE net;
	BYTE receiver[6];
	BYTE sender[6];
	SWORD type;
} ETHER_HEADER;

typedef struct 
{
    u_short len;
    u_char  iface;
    u_char  net;
    u_char  da[6];
    u_char  sa[6];
    u_short type;
} ETHERNET_PKT;

CHAR_T*
trace_ethernet(ETHERNET_HEADER *, int,   int, int*, int*); 

int is_broadcast(BYTE *);

#endif 
