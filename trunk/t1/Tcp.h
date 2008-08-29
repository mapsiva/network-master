/**
	Universidade Federal de Mato Grosso do Sul
	Mestrado em Ciência da Computação DCT - UFMS
	Redes de Computadores 2008
	
	Márcio Aparecido Inacio da Silva
	Maxwell Sampaio dos Santos
	
	Xnoop - Analizador de Pacotes [Trabalho 1]
*/
#ifndef TCP_H_
#define TCP_H_
#include "Types.h"
#include <netdb.h>

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

void
view_service( SWORD , int);

	
CHAR_T*
trace_tcp( TCP_HEADER *, int);

void
view_flags ( TCP_HEADER * );

void
view_data ( TCP_HEADER * );

#endif /*TCP_H_*/
