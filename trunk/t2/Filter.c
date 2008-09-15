/**
	Universidade Federal de Mato Grosso do Sul
	Mestrado em Ciência da Computação DCT - UFMS
	Redes de Computadores 2008
	
	Márcio Aparecido Inacio da Silva
	Maxwell Sampaio dos Santos
	
	Xnoop - Analizador de Pacotes [Trabalho 1]
*/

#ifndef FILTER_H_
#define FILTER_H_

#include "Types.h"
#include "PackageHeader.h"
#include "Ethernet.h"
#include "Tcp.h"
#include "Ip.h"
#include "Udp.h"
#include "Icmp.h"
#include "Arp.h"
#include "Analyzer.h"
#include "Stack.h"
#include "Filter.h"
//#include <typeinfo.h>

int
filter (ETHERNET_HEADER * pkg, int argc, char *argv[], int position)
{
    Stack *stack = make_stack();
    int i;
    Token *token;
    Node *op1, *op2;
    int data;
    DWORD a, b;
    DWORD *_mac;
    BYTE *j;
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
        token = Advance ((CHAR_T *)argv[i]);  
        
        //printf("\n%s\n", argv[i]);
            
        switch (token->code)
        {
            case _NUMBER:
            case _HEXA:
                push(stack, token->value);
                break;
            case _ADDRESS_IP:
            case _MAC:
                push(stack, token->value);
                break;
             case _OPERATOR:
                if( stack->length < 2 )
                {
                    printf ("Error: Incorrect Filter. No data for operation [%s].\n", token->name);
                 	return 0;  
                }
                                
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
                    	if (op2->value == 0)
                    	{
                    		printf("Error: Division by zero!\n");
                    		return 0;
                    	}
                        data = ((WORD)(op1->value)/(WORD)(op2->value));                        
                    case _EQ:
                        data = ((DWORD)(op1->value)==(DWORD)(op2->value));
                        break;
                }            
                push (stack, data);               
                break;
            case _BIN_OPERATOR:
            case _KEYWORD:                       
                switch ((int)token->value)
                {
                    case _EQ:
                        if( stack->length < 2 )
                        {
                            printf ("Error: Incorrect Filter. No data for operation [EQ].\n");
                            return 0;
                        }
                        op1 = pop( stack );
                        op2 = pop( stack );
                       
                        a = op1->value;
                        b = op2->value;
                       
                        if(a == b)
                             push (stack, 1);
                        else
                             push (stack, 0);
                      
                        break;
                    case _AND:
                        if( stack->length < 2 )
                        {
                            printf ("Error: Incorrect Filter. No data for operation [AND].\n");
                            return 0;
                        }
                            
                        op1 = pop( stack );
                        op2 = pop( stack );
                        
                        a = op1->value;
                        b = op2->value;
                        
                       	data = a & b;

                        push (stack, data);
                        
                        break;
                    case _OR:
                        if( stack->length < 2 )
                        {
                            printf ("Error: Incorrect Filter. No data for operation [OR].\n");
                            return 0;
                        }                        
                        
                        op1 = pop( stack );
                        op2 = pop( stack );
                        
                        a = op1->value;
                        b = op2->value;
                   
                        
                        push (stack,  (a | b));
                      
                        break;
                    case _NOT:
                    	if( stack->length < 1 )
                    	{
                            printf ("Error: Incorrect Filter. No data for operation [NOT].\n");                            
                            return 0;
                        }
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
                    	if ((unsigned int)ntohs(pkg->type) == ARP)
                    		push (stack, 1);
                    	else                  		
                    		push (stack, 0);
                    	break;
                    case _UDP:
                    	if ((unsigned int)ntohs(pkg->type) == IP && pkg_ip->protocol == UDP)
                    		push (stack, 1);
                    	else
                    		push (stack, 0);
                    	break;                        
                    case _TCP:
						if ((unsigned int)ntohs(pkg->type) == IP && pkg_ip->protocol == TCP)
                    		push (stack, 1);
                    	else
                    		push (stack, 0);
                    	break; 
                    case _ICMP: 
                    	if ((unsigned int)ntohs(pkg->type) == IP && pkg_ip->protocol == ICMP)
                    		push (stack, 1);
                    	else
                    		push (stack, 0);
                    	break;
                    case _ETHERTO:
                    case _ETHERFROM:
                    	_mac = (DWORD *) malloc(sizeof(DWORD));
                    	
                    	(*_mac) &= 0xF;
                    	
                    	j = (BYTE *)_mac;
                    	
                    	int k;
                    	for (k=0; k<6; k++)
                    	{
                    		if((int)token->value == _ETHERTO)
                    		    *(j + k) = *(pkg->receiver + k);
                    		else
                    		    *(j + k) = *(pkg->sender + k);
                    		
                    	}
                    	push (stack, (*_mac));  	
                    	break;
                    case _ETHERTYPE:
                        if((unsigned int)ntohs(pkg->type) == IP)
                    	    push (stack, IP );
                    	else
                    	    push (stack, ARP );
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
                    		push (stack, (unsigned int)pkg_ip->protocol);
                    	else
                    		push (stack, 0);
                    	break;
                    case _UDPTOPORT:
                    	if ((unsigned int)ntohs(pkg->type) == IP && pkg_ip->protocol == UDP)
                    		push (stack, (unsigned int)ntohs(pkg_udp->dest_port));
                    	else
                    		push (stack, 0);
                    	break;
                    	
                    case _UDPFROMPORT:
                    	if ((unsigned int)ntohs(pkg->type) == IP && pkg_ip->protocol == UDP)
                    		push (stack, (unsigned int)ntohs(pkg_udp->src_port));
                    	else
                    		push (stack, 0);
                    	break;
                    	
                    case _TCPTOPORT:
                    	if ((unsigned int)ntohs(pkg->type) == IP && pkg_ip->protocol == TCP)
                    		push (stack, (unsigned int)ntohs(pkg_tcp->dest_port));
                    	else
                    		push (stack, 0);
                    	break;
                    	
                    case _TCPFROMPORT:
                    	if ((unsigned int)ntohs(pkg->type) == IP && pkg_ip->protocol == TCP)
                    		push (stack, (unsigned int)ntohs(pkg_tcp->src_port));
                    	else
                    		push (stack, 0);
                    	break;
             
                    case _ICMPTYPE:
                    	if ((unsigned int)ntohs(pkg->type) == IP && pkg_ip->protocol == ICMP)
                    		push (stack, (WORD)(pkg_icmp->type));
                    	else
                    		push (stack, -1);
                        break;
                }
                break;
        	default:
        		printf("Error: [%s] unknow\n", token->name);
        		return 0;
        }
	}
	
	if (stack->length == 1 && ((stack->top)->value == 1))
	{
		flush(stack);
		
		return 1;
	}
	else if (stack->length > 1)
	    printf ("Error: Incorrect Filter\n");
	
	flush(stack);
    return 0;
}

#endif
