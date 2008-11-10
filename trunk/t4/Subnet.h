/**
	Universidade Federal de Mato Grosso do Sul
	Mestrado em Ci�ncia da Computa��o DCT - UFMS
	Redes de Computadores 2008
	
	M�rcio Aparecido Inacio da Silva
	Maxwell Sampaio dos Santos
	
	Xnoop - Analizador de Pacotes [Trabalho 1]
*/

#ifndef SUBNET_H_
#define SUBNET_H_
#include "Ethernet.h"
#include "Types.h"
#include "Arp.h"
#include "Ip.h"
#include <stdlib.h>
#include <stdio.h>
/* */
#define MAX_PKT_SZ		65536
#define MAC_ADDR_LEN	6
#define IP_ADDR_LEN		4
#define MAX_IFACES		5
#define MAX_NETWORKS	20
#define MAX_PARAMETERS	256
#define MAX_SIZE_PARAMETER	20
#define TIMEOUT				2

/* */
BYTE net2iface[MAX_NETWORKS];

/* */
typedef struct _pq {
    ETHERNET_PKT  *pkt;
    struct _pq *next;
} PKT_QUEUE;

/* */
PKT_QUEUE *queue_head;
PKT_QUEUE *queue_tail;

/* */
sem_t sem_data_ready;
sem_t sem_queue;
sem_t sem_xnoop;
sem_t sem_main;
sem_t sem_arp_res;
sem_t sem_ping;

/* */
INTERFACE ifaces[MAX_IFACES];	/* Interfaces of the host/router */

/* */
unsigned nifaces;		/* Number of interfaces */

/* */
unsigned my_ip;
u_short  my_port;

/* */
BYTE broad_eth[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

/* */
char in_buf[MAX_PKT_SZ];

/* Definitions for XNOOP */
int qtd_parameters, run_xnoop, qtd_pkgs, sending_packets, arp_resolving;

char *parameters[MAX_PARAMETERS];

_XNOOP _xnoop;

unsigned int ARP_TTL_DEF = 60;

/* functions*/

int passive_UDP_socket(u_short);

void *subnet_rcv(void *);

void send_pkt(u_short, BYTE , BYTE *, u_short , BYTE *);

void xnoop_send_pkt(u_short, u_short, BYTE *);

void *subnet_send(void *);

void str2eth(char *, BYTE[]);

char *ip2str(char *, unsigned);

int read_net_cfg(char *, u_short, u_short);

void print_if_info(int);

void sub_xnoop(char *);

int sub_ifconfig( char* );

int sub_if( char* );

int sub_arp_del( void* );

int sub_arp_res( void* , int);

int sub_arp_add( void* );

int sub_route_add( void* );

int sub_route_del( void* );

int sub_traceroute( void* );

int sub_ping( void* );

void send_icmp_pkt ( BYTE , BYTE , BYTE , WORD, WORD, WORD, BYTE, WORD);

int sub_arp( char* );

int sub_get_parameters( char**, char*);

int sub_send_trace(char* b);

void control_xnoop();

void * update_arp_table(void *p);

void * update_route_table(void *p);

void buildArpHeader (DWORD *, WORD , WORD );

int Route2Interface(WORD);

SWORD calc_check_sum(void *, int tipo);

#endif 
