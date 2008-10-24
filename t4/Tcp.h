/**
	Universidade Federal de Mato Grosso do Sul
	Mestrado em Ci�ncia da Computa��o DCT - UFMS
	Redes de Computadores 2008
	
	M�rcio Aparecido Inacio da Silva
	Maxwell Sampaio dos Santos
	
	Subnet
*/
#ifndef TCP_H_
#define TCP_H_
#include "Types.h"
#include <netdb.h>

/*
* Estrutura do cabe�alho TCP
*/
typedef struct
{
	SWORD src_port;
 	SWORD dest_port;
	WORD seq_number_port;
	WORD ack;
	SWORD offset;
	SWORD window;
	SWORD checksum;
	SWORD urgent_pointer;
	BYTE fisrt_data;
}TCP_HEADER;		

/*
* Mostra campo service do cabe�alho TCP
*/
void
view_service( SWORD , int);

/*
*Imprime o cabe�alho TCP
*/	
CHAR_T*
trace_tcp( TCP_HEADER *, int);

/*
* Mostra campo flags do cabe�alho TCP
*/
void
view_flags ( TCP_HEADER * );

/*
* Mostra campo dados do cabe�alho TCP
*/
void
view_data ( TCP_HEADER * );

#endif /*TCP_H_*/
