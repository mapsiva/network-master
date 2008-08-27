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
    int aux;
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

int
is_binary_operator( CHAR_T * operator){
	
	char *op = (char *) operator;

	if (!strcmp(op, "AND") || !strcmp(op, "and"))
		return _AND;	
	else if (!strcmp(op, "EQ") || !strcmp(op, "eq"))
		return _EQ;
	else if (!strcmp(op, "OR") || !strcmp(op, "or"))
		return _OR;
	else if (!strcmp(op, "NOT") || !strcmp(op, "not"))
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
			if (!strcmp (keyw, "IP") || !strcmp (keyw, "ip"))
				return _IP;
			else if (!strcmp (keyw, "IPTO") || !strcmp (keyw, "ipto"))
				return _IPTO;
			else if (!strcmp (keyw, "IPFROM") || !strcmp (keyw, "ipfrom"))
				return _IPFROM;
			else if (!strcmp (keyw, "IPPROTO") || !strcmp (keyw, "ipproto"))
				return _IPPROTO;
		}
		else 
		{
			if (!strcmp(keyw, "ICMP") || !strcmp(keyw, "icmp"))
				return _ICMP;			
			else if (!strcmp(keyw, "ICMPTYPE") || !strcmp(keyw, "icmptype"))
				return _ICMPTYPE;
			else
				return 0;
		}			
	}
	else if (toupper(*keyw) == 'T')  /* TCP */
	{
		if (!strcmp(keyw, "TCP") || !strcmp(keyw, "tcp"))
			return _TCP;
		else if (!strcmp(keyw, "TCPTOPORT") || !strcmp(keyw, "tcptoport"))
			return _TCPTOPORT;	
		else if (!strcmp(keyw, "TCPFROMPORT") || !strcmp(keyw, "tcpfromport"))
			return _TCPFROMPORT;
		else 
			return 0;
	}	
	else if (toupper(*keyw) == 'E') /* ETHERNET */
	{
		if (!strcmp(keyw, "ETHERNET") || !strcmp(keyw, "ethernet"))
			return _ETHERNET;		
		else if (!strcmp(keyw, "ETHERTYPE") || !strcmp(keyw, "ethertype"))
			return _ETHERTYPE;
		else
			return 0;
	}
	else if (toupper(*keyw) == 'A') /* ARP */
	{
		if (!strcmp(keyw, "ARP") || !strcmp(keyw, "arp"))
			return _ARP;			
		else
			return 0;
	}
	else if (toupper(*keyw) == 'U') /* UDP */
	{
		if (!strcmp(keyw, "UDP") || !strcmp(keyw, "udp"))
			return _UDP;
		else if (!strcmp(keyw, "UDPTOPORT") || !strcmp(keyw, "udptoport"))
			return _UDPTOPORT;
		else if (!strcmp(keyw, "UDPFROMPORT") || !strcmp(keyw, "udpfromport"))
			return _UDPFROMPORT;
		else 
			return 0;
	}	
	return 0;
}

DWORD *
to_mac_byte ( CHAR_T * hex ){return 0;}


#endif 
