#ifndef ANALYZER_C_
#define ANALYZER_C_
#include "Types.h"
#include "Analyzer.h"
#include <ctype.h>
#include <wctype.h>
#include <stdlib.h>

Token *
token( CHAR_T* argv)
{
    Token * token = (Token *)malloc (sizeof(Token));
    if(is_ip(argv))
    {
        token->value = (DWORD *) to_ip_byte (argv);
        token->code = _IP;
        return token;
    }
    
    
    return 0;
}

int
is_ip( CHAR_T * ip){return 0;}

int
is_hexa ( CHAR_T * hex ){return 0;}

DWORD *
to_ip_byte( CHAR_T * ip){return 0;}

int
is_key_word( CHAR_T * keyword){return 0;}
#endif 
