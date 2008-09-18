/**
	Universidade Federal de Mato Grosso do Sul
	Mestrado em Ciência da Computação DCT - UFMS
	Redes de Computadores 2008
	
	Márcio Aparecido Inacio da Silva
	Maxwell Sampaio dos Santos
	
	Subnet
*/
#ifndef TCP_H_
#define TCP_H_
#include "Types.h"
#include <netdb.h>

/*
* Estrutura do cabeçalho TCP
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
* Mostra campo service do cabeçalho TCP
*/
void
view_service( SWORD , int);

/*
*Imprime o cabeçalho TCP
*/	
CHAR_T*
trace_tcp( TCP_HEADER *, int);

/*
* Mostra campo flags do cabeçalho TCP
*/
void
view_flags ( TCP_HEADER * );

/*
* Mostra campo dados do cabeçalho TCP
*/
void
view_data ( TCP_HEADER * );

#endif /*TCP_H_*/
