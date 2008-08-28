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
    IP_HEADER * pkg_ip;
    TCP_HEADER * pkg_tcp;
    UDP_HEADER * pkg_udp;
    ICMP_HEADER * pkg_icmp;
    
   	pkg_ip = (IP_HEADER *)( pkg + 1 );
   	pkg_tcp = (TCP_HEADER *)(pkg_ip + 1);
   	pkg_udp = (UDP_HEADER *)(pkg_ip + 1);
    pkg_icmp = (ICMP_HEADER *)(pkg_ip + 1);
    
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
                        	if( stack->length < 2 )
                                error_exit ("no data for operation [NOT]");
                            
                            op1 = pop( stack );
                                                        
                            push(stack, !op1->value);
                            
                            break;                        
                        case _IP:
                        	if (ntohs(pkg->type) == IP)
                        		push (stack, 1);
                        	else
                        		push (stack, 0);
                        	break;
                        case _ARP:
                        	if (ntohs(pkg->type) == ARP)
                        		push (stack, 1);
                        	else
                        		push (stack, 0);
                        	break;
                        case _UDP:
                        	if (pkg_ip->protocol == UDP)
                        		push (stack, 1);
                        	else
                        		push (stack, 0);
                        	break;                        
                        case _TCP:
							if (pkg_ip->protocol == TCP)
                        		push (stack, 1);
                        	else
                        		push (stack, 0);
                        	break; 
                        case _ICMP: 
                        	if (pkg_ip->protocol == ICMP)
                        		push (stack, 1);
                        	else
                        		push (stack, 0);
                        	break;
                        case _ETHERTO:
                        	push (stack, pkg->pkg->receiver);
                        	break;
                        case _ETHERFROM:
                        	push (stack, pkg->pkg->sender);
                        	break;
                        case _ETHERTYPE:
                        	push ((unsigned int) ntohs(pkg->type));
                        	break;
                        case _IPTO:
                        	if (ntohs(pkg->type) == IP)
                        		push (stack, pkg_ip->destination_address);
                        	else
                        		push (stack, 0);
                        	break;
                        case _IPFROM:
                        	if (ntohs(pkg->type) == IP)
                        		push (stack, pkg_ip->source_address);
                        	else
                        		push (stack, 0);
                        	break;
                        case _IPPROTO:
                        	if (ntohs(pkg->type) == IP)
                        		push (stack, pkg_ip->protocol);
                        	else
                        		push (stack, 0);
                        	break;
                        case _UDPTOPORT:
                        	if (pkg_ip->protocol == UDP)
                        		push (stack, ntohs(pkg_udp->dest_port));
                        	else
                        		push (stack, 0);
                        	break;
                        case _UDPFROMPORT:
                        	if (pkg_ip->protocol == UDP)
                        		push (stack, ntohs(pkg_udp->src_port));
                        	else
                        		push (stack, 0);
                        	break;
                        case _TCPTOPORT:
                        	if (pkg_ip->protocol == TCP)
                        		push (stack, ntohs(pkg_tcp->dest_port));
                        	else
                        		push (stack, 0);
                        	break;
                        case _TCPFROMPORT:
                        	if (pkg_ip->protocol == TCP)
                        		push (stack, ntohs(pkg_tcp->dest_port));
                        	else
                        		push (stack, 0);
                        	break;
                        case _ICMPTYPE:
                        	if (pkg_ip->protocol == ICMP)
                        		push (stack, ntohs(pkg_icmp->type));
                        	else
                        		push (stack, 0);
                            break;
                    }
                }
                break;
        }
	}
    
    return 0;
}

#endif
