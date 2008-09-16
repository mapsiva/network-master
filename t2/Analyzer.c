/**
	Universidade Federal de Mato Grosso do Sul
	Mestrado em Ci�ncia da Computa��o DCT - UFMS
	Redes de Computadores 2008
	
	M�rcio Aparecido Inacio da Silva
	Maxwell Sampaio dos Santos
	
	Xnoop - Analizador de Pacotes [Trabalho 1]
*/
#ifndef ANALYZER_C_
#define ANALYZER_C_
#include "Types.h"
#include "Analyzer.h"
#include "Ip.h"

#include <ctype.h>
#include <wctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>


Token *
Advance( CHAR_T* argv)
{
    Token * token = (Token *)malloc (sizeof(Token));
    tKeywordTableEntry *key_word;
    
    int aux;   
   
    if(is_ip(argv))
    {
        token->value = (*to_ip_byte (argv));
        token->code = _ADDRESS_IP;
        token->name = argv;
    }
    else if(is_hexa(argv))
    {
        token->value = strtoul((const char *)argv, NULL, 16);
        token->code = _HEXA;
        token->name = argv;
    }
    else if(is_mac_address(argv))
    {
        token->value = (*to_mac_byte (argv));
        token->code = _MAC;
        token->name = argv;
    }
    else if(is_decimal(argv))
    {
        token->value = (WORD) atoi ((const char *)argv);
        token->code = _NUMBER;       
    }
    else if((aux = is_operator(argv)))
    {
        token->value = (WORD) aux;
        token->code = _OPERATOR;
        token->name = argv;
    }  
    else if((key_word = FindKeyword ((const char *)argv)))
    {        
        token->name = key_word->Name;
        token->value = (WORD) key_word->Token;
        token->code = key_word->Code;
    }
    else
    {
		token->code = 0;
		token->name = argv;
		token->value = 0;
    }
    
    return token;
}




#endif 
