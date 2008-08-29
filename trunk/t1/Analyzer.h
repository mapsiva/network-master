/**
	Universidade Federal de Mato Grosso do Sul
	Mestrado em Ciência da Computação DCT - UFMS
	Redes de Computadores 2008
	
	Márcio Aparecido Inacio da Silva
	Maxwell Sampaio dos Santos
	
	Xnoop - Analizador de Pacotes [Trabalho 1]
*/
#ifndef ANALYZER_H_
#define ANALYZER_H_
#include "Types.h"
#include <arpa/inet.h> 

char * _current;



Token *
Advance( CHAR_T* argv);

int
is_ip( CHAR_T * );

int
is_hexa ( CHAR_T * );

int 
is_mac_address( const CHAR_T * );

DWORD *
to_mac_byte ( const CHAR_T * );

int
is_decimal ( CHAR_T *);

int
is_operator ( CHAR_T *);

int
is_binary_operator( CHAR_T *);


DWORD *
to_ip_byte( CHAR_T * );


#endif 
