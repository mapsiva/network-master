/**
	Universidade Federal de Mato Grosso do Sul
	Mestrado em Ci�ncia da Computa��o DCT - UFMS
	Redes de Computadores 2008
	
	M�rcio Aparecido Inacio da Silva
	Maxwell Sampaio dos Santos
	
	Subnet
*/
#ifndef ETHERNET_H_
#define ETHERNET_H_
#include "Types.h"
#include "PackageHeader.h"

/*
* Estrutura para o cabeçalho ethernet, utilizando no trabalho do subnet
*/
typedef struct
{
    BYTE net;
	BYTE receiver[6];
	BYTE sender[6];
	SWORD type;
} ETHERNET_HEADER;

/* Estrutura usada para manipula��o dos dados do arquivo TRACE*/
typedef struct
{
    //BYTE net;
	BYTE receiver[6];
	BYTE sender[6];
	SWORD type;
} ETHER_HEADER;

/*
* Estrutura para o cabeçalho ethernet, utilizando no trabalho do subnet
*/
typedef struct 
{
    SWORD len;
    BYTE  iface;
    BYTE  net;
    BYTE  da[6];
    BYTE  sa[6];
    SWORD type;
} ETHERNET_PKT;

/*
* Impressão do cabeçalho ethernet
*/
CHAR_T*
trace_ethernet(ETHERNET_HEADER *, int,   int, int*, int*); 

/*
* Retorna se o mac passado como parámetro é de broadcast
*/
int is_broadcast(BYTE *);

#endif 
