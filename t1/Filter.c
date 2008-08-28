#ifndef FILTER_H_
#define FILTER_H_

#include "PackageHeader.h"
#include "Ethernet.h"
#include "Tcp.h"
#include "Ip.h"
#include "Udp.h"
#include "Icmp.h"
#include "Arp.h"
#include "Analyzer.h"
#include "Stack.h"
#include "Types.h"

#include "Filter.h"

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
	KEYWORD( (CHAR_T*)"ETHERNET"   	, _ETHERNET, 	_KEYWORD),
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


int
filter (ETHERNET_HEADER * pkg, int argc, char *argv[], int position)
{
    Stack *stack = make_stack();
    int i;
    tKeywordTableEntry *key_word;
    Token *token;
    Node *op1, *op2;
    int data;
    DWORD ddata;
    
    for (i = position; i < argc; i++)
	{   
         printf("[%s][%d] ", argv[i], position);
        token = Advance ((CHAR_T *)argv[i]);
         printf("DATA_> %d\n", (int)token->value);
        switch (token->code)
        {
            case _NUMBER:
            case _HEXA:
                push(stack, (WORD *)token->value);
                break;
            case _ADDRESS_IP:
            case _MAC:
                push(stack, (DWORD *)token->value);
                break;
             case _OPERATOR:
                if( stack->length < 2 )
                    error_exit ("no data for operation");
                
                op1 = pop( stack );
                op2 = pop( stack );
                
                switch ((int)token->value)
                {
                    case _SUM:
                        data = ((WORD)(op1->value))+((WORD)(op2->value));
                        
                        break;
                    case _MULT:
                         data = ((WORD)(op1->value)*(WORD)(op2->value));
                         break;
                    case _MINUS:
                         data = ((WORD)(op1->value)-(WORD)(op2->value));
                         break;
                    case _MOD:
                         data = ((WORD)(op1->value)%(WORD)(op2->value));
                         break;
                    case _DIV:
                        data = ((WORD)(op1->value)/(WORD)(op2->value));
                        break;
                    
                   
                    
                    
                }
                
                push (stack, &data);
               
                break;
               
            case _KEYWORD:
                if((key_word = FindKeyword ((const char *)token->name)))
                {
                    switch (key_word->Token)
                    {
                        case _EQ:
                            if( stack->length < 2 )
                                error_exit ("no data for operation [EQ]");
                            op1 = pop( stack );
                            op2 = pop( stack );
                            
                            if((DWORD)(op1->value) == (DWORD)(op2->value))
                                 push (stack, 1);
                            else
                                 push (stack, 0);
                           
                            break;
                        case _AND:
                            if( stack->length < 2 )
                                error_exit ("no data for operation [EQ]");
                                
                            op1 = pop( stack );
                            op2 = pop( stack );
                            
                           data = ((DWORD)(op1->value) & (DWORD)(op2->value));
                            push (stack, &data);
                            
                            break;
                        case _OR:
                            if( stack->length < 2 )
                                error_exit ("no data for operation [EQ]");
                                
                            op1 = pop( stack );
                            op2 = pop( stack );
                            
                           // data = ((DWORD *)(op1->value) | (DWORD *)(op2->value));
                            push (stack, &data);
                            
                            break;
                        case _NOT:
                            op1 = pop( stack );
                            break;
                        case _ETHERNET:
                        case _IP:
                        case _UDP:
                        case _TCP:
                        case _ICMP:
                        case _ARP:
                        case _ETHERTO:
                        case _ETHERFROM:
                        case _ETHERTYPE:
                        case _IPTO:
                        case _IPFROM:
                        case _IPPROTO:
                        case _UDPTOPORT:
                        case _UDPFROMPORT:
                        case _TCPTOPORT:
                        case _TCPFROMPORT:
                        case _ICMPTYPE:
                            break;
                    }
                }
                break;
        }
	}
    
    return 0;
}

#endif
