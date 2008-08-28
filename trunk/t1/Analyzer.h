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

int
is_keyword( CHAR_T * );
#endif 
