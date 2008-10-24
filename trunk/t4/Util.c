/**
	Universidade Federal de Mato Grosso do Sul
	Mestrado em Ci�ncia da Computa��o DCT - UFMS
	Redes de Computadores 2008
	
	M�rcio Aparecido Inacio da Silva
	Maxwell Sampaio dos Santos
	
	Xnoop - Analizador de Pacotes [Trabalho 1]
*/
#ifndef UTIL_H_
#define UTIL_H_
#include "Types.h"
#include "Util.h"
#include "Ip.h"

#include <ctype.h>
#include <wctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>


int
is_ip( CHAR_T * ip)
{
    if(strpbrk(":",(char *)ip))
       return 0; 
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
    char * b,  copy[16];
    DWORD *_ip = (DWORD *) malloc(sizeof(DWORD));
    
    BYTE *j;
    
    (*_ip) &= 0xF;
   
    j = (BYTE *)_ip;
    
    strcpy ( (char *)copy, (char *)ip);
  
    b = strtok ((char *)copy,".");
    while (b)
    {
        if((int)atoi((const char *)b) < 0 || atoi((const char *)b) > 255)
            return 0;
        
        *j = atoi((char *)b);
        
        j++;
        
        b = strtok (NULL, ".");
    }
    return _ip;
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
    int i;
    
    for (i = 0; i < strlen ((char *)dec); i++)
    {
        if(!isdigit(*(dec+i)))          
           return 0;
    }
    return 1;
}

int 
is_mac_address( const CHAR_T * mac)
{
    char * b, copy[50];
    
    strcpy ( (char *)copy, (char *)mac);
    
    int count = 0 ;
    b = strtok ((char *)copy,":");
    
    while (b)
    {
        count ++;
        
        if(!strtoul((const char *)b, NULL, 16) && (toupper(*b) != '0' || toupper(*(b+1)) != '0'))
            return 0;
     
        b = strtok (NULL, ":");
         
    }
     
    return (count < 6)?0:1;
}

DWORD *
to_mac_byte ( const CHAR_T * mac )
{
    char * b,  copy[50];
    DWORD *_mac = (DWORD *) malloc(sizeof(DWORD));
    
    BYTE *j;
    
    (*_mac) &= 0xF;
   
    j = (BYTE *)_mac;
    
    strcpy ( (char *)copy, (char *)mac);
  
    b = strtok ((char *)copy,":");
    while (b)
    {   
        *j = strtoul((const char *)b, NULL, 16);
        
        j++;
        
        b = strtok (NULL, ":");
    }
    return _mac;
}


int
is_operator ( CHAR_T * op )
{
     
     if (strlen((const char *)op)  > 1)
        return 0;
     
     if ((*op == '*'))
        return _MULT;
     
     if (( *op == '+'))
        return _SUM;
     
     if ((*op == '-'))
        return _MINUS;
     
     if ((*op == '%'))
        return _MOD;
        
     if ((*op == '/'))
        return _DIV;
        
     if ((*op == '='))
        return _EQ;
    return 0;
}

int
is_binary_operator( CHAR_T * operator){
	
	char *op = (char *) operator;

	if (!strcasecmp (op, "AND"))
		return _AND;	
	else if (!strcasecmp (op, "EQ"))
		return _EQ;
	else if (!strcasecmp (op, "OR"))
		return _OR;
	else if (!strcasecmp (op, "NOT"))
		return _NOT;
	else
		return 0;
}

CHAR_T*
format_mac_address(DWORD  address) 
{
    CHAR_T * end_mac = (CHAR_T *) &address,  *e_mac;
    
    e_mac = (CHAR_T*) malloc (17);
    
    sprintf((char *)e_mac, "%02X:%02X:%02X:%02X:%02X:%02X", *end_mac, *(end_mac+1), *(end_mac+2), *(end_mac+3), *(end_mac+4), *(end_mac+5));
    
    return e_mac;
}

#endif 
