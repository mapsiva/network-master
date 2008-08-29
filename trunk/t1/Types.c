#ifndef TYPES_C_
#define TYPE_C_
#include "Types.h"
#include "strings.h"

WORD to_word(void * value)
{
	return (WORD) ((void*)value); 
}

tKeywordTableEntry*
SearchKeyword(tKeywordTableEntry* k, const char * name)
{
    while (k->Name)
    {
		if (!strcasecmp((const char *)k->Name, (const char*)name))
			return k;
		k++;
	}
	return 0;
}

DECLARE_KEYWORD_TABLE();


DEFINE_KEYWORD_TABLE()
	KEYWORD( (CHAR_T*)"IP" 			, _IP, 			_KEYWORD),
	KEYWORD( (CHAR_T*)"IPTO" 		, _IPTO, 		_KEYWORD),
	KEYWORD( (CHAR_T*)"IPFROM" 		, _IPFROM, 		_KEYWORD),
	KEYWORD( (CHAR_T*)"IPPROTO"   	, _IPPROTO, 	_KEYWORD),
	KEYWORD( (CHAR_T*)"ICMP"   		, _ICMP, 		_KEYWORD),
	KEYWORD( (CHAR_T*)"ICMPTYPE"   	, _ICMPTYPE, 	_KEYWORD),
	KEYWORD( (CHAR_T*)"TCP"   		, _TCP, 		_KEYWORD),
	KEYWORD( (CHAR_T*)"TCPTOPORT"   , _TCPTOPORT, 	_KEYWORD),
	KEYWORD( (CHAR_T*)"TCPFROMPORT" , _TCPFROMPORT, _KEYWORD),
	KEYWORD( (CHAR_T*)"ETHERTO"   	, _ETHERTO, 	_KEYWORD),
	KEYWORD( (CHAR_T*)"ETHERFROM"  	, _ETHERFROM, 	_KEYWORD),
	KEYWORD( (CHAR_T*)"ETHERTYPE"   , _ETHERTYPE, 	_KEYWORD),
	KEYWORD( (CHAR_T*)"ARP"   		, _ARP, 		_KEYWORD),	
	KEYWORD( (CHAR_T*)"UDP"   		, _UDP, 		_KEYWORD),
	KEYWORD( (CHAR_T*)"UDPTOPORT"   , _UDPTOPORT, 	_KEYWORD),
	KEYWORD( (CHAR_T*)"UDPFROMPORT" , _UDPFROMPORT, _KEYWORD),
	KEYWORD( (CHAR_T*)"OR"   		, _OR, 			_BIN_OPERATOR),
	KEYWORD( (CHAR_T*)"AND"   		, _AND, 		_BIN_OPERATOR),
	KEYWORD( (CHAR_T*)"EQ"   		, _EQ, 			_BIN_OPERATOR),
	KEYWORD( (CHAR_T*)"NOT"   		, _NOT, 		_BIN_OPERATOR),
END_KEYWORD_TABLE;


#endif 
