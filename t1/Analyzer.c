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
        token->code = _ADDRESS_IP;
        
        return token;
    }
     
    if(is_hexa(argv))
    {
        token->value = (DWORD *) to_mac_byte (argv);
        token->code = _HEXA;
        
        return token;
    }
     
    if(is_mac_address(argv))
    {
        token->value = (DWORD *) to_mac_byte (argv);
        token->code = _MAC;
        
        return token;
    }
    
    if(is_decimal(argv))
    {
        token->value = (WORD *) atoi ((const char *)argv);
        token->code = _NUMBER;
       
        return token;
    }
    
    if((aux = is_operator(argv)))
    {
        token->value = (WORD *) aux;
        token->code = _OPERATOR;
      
        return token;
    }
    
    if((aux = is_binary_operator(argv)))
    {
        token->value = (WORD *) aux;
        token->code = _BIN_OPERATOR;
       
        return token;
    }
    
    if((aux = is_keyword(argv)))
    {
        token->value = (WORD *) aux;
        token->code = _KEYWORD;
        
        return token;
    }
    
    return 0;
}

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
     if (strtoul((const char *)dec, NULL, 10) && !strpbrk(".",(char *)dec) && !strpbrk(":",(char *)dec))
        return 1;
    return 0;
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
     
     if (( *op == '+') )
        return _SUM;
     
     if ((*op == '-'))
        return _MINUS;
     
     if ((*op == '%'))
        return _MOD;
        
     if ((*op == '/'))
        return _DIV;
        
     if ((*op == '/'))
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
#endif 
