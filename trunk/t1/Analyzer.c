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
    int aux;
    if(is_ip(argv))
    {
        token->value = (DWORD *) to_ip_byte (argv);
        token->code = _IP;
        DWORD *t = to_ip_byte (argv);
         printf ("IP %u\n", (int)(*t));
         
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
        printf ("decimal %d\n", _IP);
        return token;
    }
    
    if((aux = is_operator(argv)))
    {
        token->value =  (WORD *) aux;
        token->code = _OPERATOR;
        
        printf ("operador\n");
        return token;
    }
    
    if((aux = is_binary_operator(argv)))
    {
        token->value = (WORD *) aux;
        token->code = _BIN_OPERATOR;
        
        printf ("bin operador\n");
        return token;
    }
    
    if((aux = is_keyword(argv)))
    {
        token->value = (WORD *) aux;
        token->code = _KEYWORD;
        
        printf ("keyword\n");
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
     if (strtoul((const char *)dec, NULL, 10) && !strpbrk(".",(char *)dec))
        return 1;
    return 0;
}

int
is_operator ( CHAR_T * op )
{
     
     if (strlen((const char *)op) == 1 && (*op == '*' || *op == '+' || *op == '-' || *op == '%' || *op == '/'))
        return 1;
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

int
is_keyword( CHAR_T * keyword){
	
	char *keyw = (char *) keyword;
	
	if (toupper(*keyw) == 'I') /* IP */
	{
		if (toupper(*(keyw+1)) == 'P')
		{
			if (!strcasecmp (keyw, "IP"))
				return _IP;
			else if (!strcasecmp (keyw, "IPTO"))
				return _IPTO;
			else if (!strcasecmp (keyw, "IPFROM"))
				return _IPFROM;
			else if (!strcasecmp (keyw, "IPPROTO"))
				return _IPPROTO;
		}
		else 
		{
			if (!strcasecmp (keyw, "ICMP"))
				return _ICMP;			
			else if (!strcasecmp (keyw, "ICMPTYPE"))
				return _ICMPTYPE;
			else
				return 0;
		}			
	}
	else if (toupper(*keyw) == 'T')  /* TCP */
	{
		if (!strcasecmp (keyw, "TCP"))
			return _TCP;
		else if (!strcasecmp (keyw, "TCPTOPORT"))
			return _TCPTOPORT;	
		else if (!strcasecmp (keyw, "TCPFROMPORT"))
			return _TCPFROMPORT;
		else 
			return 0;
	}	
	else if (toupper(*keyw) == 'E') /* ETHERNET */
	{
		if (!strcasecmp (keyw, "ETHERNET"))
			return _ETHERNET;		
		else if (!strcasecmp (keyw, "ETHERTYPE"))
			return _ETHERTYPE;
		else
			return 0;
	}
	else if (toupper(*keyw) == 'A') /* ARP */
	{
		if (!strcasecmp (keyw, "ARP"))
			return _ARP;			
		else
			return 0;
	}
	else if (toupper(*keyw) == 'U') /* UDP */
	{
		if (!strcasecmp (keyw, "UDP"))
			return _UDP;
		else if (!strcasecmp (keyw, "UDPTOPORT"))
			return _UDPTOPORT;
		else if (!strcasecmp (keyw, "UDPFROMPORT"))
			return _UDPFROMPORT;
		else 
			return 0;
	}	
	return 0;
}

DWORD *
to_mac_byte ( CHAR_T * hex )
{
    return 0;
}


#endif 
