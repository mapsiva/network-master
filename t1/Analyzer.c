#ifndef ANALYZER_C_
#define ANALYZER_C_
#include "Types.h"
#include "Analyzer.h"

#include <ctype.h>
#include <wctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>


Token *
Advance( CHAR_T* argv)
{
    Token * token = (Token *)malloc (sizeof(Token));
    if(is_ip(argv))
    {
        token->value = (DWORD *) to_ip_byte (argv);
        token->code = _IP;
        
         printf ("IP %d\n", is_ip(argv));
         
        return token;
    }
    
    if(is_hexa(argv))
    {
        token->value = (DWORD *) to_mac_byte (argv);
        token->code = _HEXA;
        printf ("hexa\n");
        return token;
    }
    
    if(is_decimal(argv))
    {
        token->value = (WORD *) atoi ((const char *)argv);
        token->code = _NUMBER;
        printf ("decimal\n");
        return token;
    }
    
    if(is_operator(argv))
    {
        token->value =  (CHAR_T *) argv;
        token->code = _OPERATOR;
        
        printf ("operador\n");
        return token;
    }
    
    printf ("Unknow Format\n");
    return 0;
}

int
is_ip( CHAR_T * ip)
{
    char * b, copy[16];
    
    strcpy ( (char *)copy, (char *)ip);
    
    int count = 0 ;
    b = strtok ((char *)copy,".");
    while (b)
    {
        count ++;
        if((int)atoi((const char *)b) < 0 || atoi((const char *)b) > 255)
            return 0;
        b = strtok (NULL, ".");
    }
    return (count < 4)?0:1;
}


DWORD *
to_ip_byte( CHAR_T * ip)
{
    return 0;
}

int
is_hexa ( CHAR_T * hex )
{
    if (( *hex=='0' && toupper(*(hex + 1))=='X') && strtoul((const char *)hex, NULL, 16))
        return 1;
    return 0;
}

int
is_decimal ( CHAR_T * dec )
{
     if (strtoul((const char *)dec, NULL, 10) && !strpbrk(".",(char *)dec))
        return 1;
    return 0;
}
int
is_operator ( CHAR_T * op )
{
     if (*op == '*' || *op == '+' || *op == '-' || *op == '%' || *op == '/')
        return 1;
    return 0;
}

DWORD *
to_mac_byte ( CHAR_T * hex ){return 0;}



int
is_key_word( CHAR_T * keyword){return 0;}
#endif 
