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
         //printf("[%s][%d] ", argv[i], position);
        token = Advance ((CHAR_T *)argv[i]);
         //printf("DATA_> %d\n", (int)token->code);
        switch (token->code)
        {
            case _NUMBER:
            case _HEXA:
            	//printf("%llu ", token->value);
                push(stack, token->value);
                break;
            case _ADDRESS_IP:
            case _MAC:
                push(stack, token->value);
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
                push (stack, data);               
                break;
            case _BIN_OPERATOR:
            case _KEYWORD:
                //printf ("keyword\n");                                
                switch ((int)token->value)
                {
                    case _EQ:
                    	//printf("eq ");
                        if( stack->length < 2 )
                            error_exit ("no data for operation [EQ]");
                        op1 = pop( stack );
                        op2 = pop( stack );
                       
                        a = op1->value;
                        b = op1->value;
                        
                        //printf("[[[ %llu %llu ]]]\n", a, b);
                        data = (a == b);
                       
                        if(a == b)
                             push (stack, 1);
                        else
                             push (stack, 0);
                        //printf("LAGLL\n");
                        break;
                    case _AND:
                        if( stack->length < 2 )
                            error_exit ("no data for operation [AND]");
                            
                        op1 = pop( stack );
                        op2 = pop( stack );
                        
                        a = op1->value;
                        b = op1->value;
                        
                       	data = a & b;

                        push (stack, data);
                        
                        break;
                    case _OR:
                        if( stack->length < 2 )
                            error_exit ("no data for operation [OR]");
                            
                        op1 = pop( stack );
                        op2 = pop( stack );
                        
                        a = op1->value;
                        b = op1->value;
                       
                        data = a | b;
                       
                        push (stack, data);
                        
                        break;
                    case _NOT:
                    	if( stack->length < 1 )
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
                    	//printf("arp\n");   
                    	//printf("%d", typeid(ntohs(pkg->type)).name());    
                    	//printf("\n%d\nasas", (int)pkg);
                    	if ((unsigned int)ntohs(pkg->type) == ARP)
                    	{
                    		//printf("pkg = arp");                    		
                    		push (stack, 1);
                    	}
                    	else
                    	{
                    		//printf("pkg != arp");                    		
                    		push (stack, 0);
                    	}
                    	break;
                    case _UDP:
                    	//printf("udp\n");
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
                    	push (stack, (*pkg->receiver));
                    	break;
                    case _ETHERFROM:
                    	push (stack, (*pkg->sender));
                    	break;
                    case _ETHERTYPE:
                    	push (stack, (unsigned int)ntohs(pkg->type));
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
                    	if (pkg_ip->protocol == UDP)
                    		push (stack, (unsigned int)ntohs(pkg_udp->dest_port));
                    	else
                    		push (stack, 0);
                    	break;
                    case _UDPFROMPORT:
                    	if (pkg_ip->protocol == UDP)
                    		push (stack, (unsigned int)ntohs(pkg_udp->src_port));
                    	else
                    		push (stack, 0);
                    	break;
                    case _TCPTOPORT:
                    	if (pkg_ip->protocol == TCP)
                    		push (stack, (unsigned int)ntohs(pkg_tcp->dest_port));
                    	else
                    		push (stack, 0);
                    	break;
                    case _TCPFROMPORT:
                    	if (pkg_ip->protocol == TCP)
                    		push (stack, (unsigned int)ntohs(pkg_tcp->src_port));
                    	else
                    		push (stack, 0);
                    	break;
                    case _ICMPTYPE:
                    	if (pkg_ip->protocol == ICMP)
                    		push (stack, (unsigned int)ntohs(pkg_icmp->type));
                    	else
                    		push (stack, 0);
                        break;
                }
                break;
        	default:
        		printf("unknow");
        }
	}
	
	if (stack->length == 1 && (stack->top)->value == 1)
	{
		flush(stack);
		return 1;
	}
	flush(stack);
    return 0;
}

#endif
