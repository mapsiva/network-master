/**
	Universidade Federal de Mato Grosso do Sul
	Mestrado em Ciência da Computação DCT - UFMS
	Redes de Computadores 2008
	
	Márcio Aparecido Inacio da Silva
	Maxwell Sampaio dos Santos
	
	Xnoop - Analizador de Pacotes [Trabalho 1]
*/
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <semaphore.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include "Subnet.h"
#include "Xnoop.h"
#include "Analyzer.h"
#include "PackageHeader.h"
#include "Ethernet.h"
#include "Arp.h"
#include "Ip.h"
#include "Tcp.h"
#include "Udp.h"
#include "Icmp.h"
#include "Rip.h"

ArpTable   *arpTable;
RouteTable *routeTable;
 int ping_running = 0;
 int trace_running = 0;
 int rip_running = 0;
 int print_resolving = 0;
 int qtd_pkg_du = 0;
 
 int RIP_PORT = 520;
 
 WORD traceroute_ip;

struct timeval start_time;
struct timeval stop_time;

/* Verifica para qual interface deve ser direcionado
 * @param _t Target Address no formato decimal com pontos
 * @param _g Gateway Address no formato decimal com pontos
 * @param _t Netmask Address no formato decimal com pontos
 * 
 * @since           2.0
 */
int Route2Interface(WORD _g)
{
	int i;
	
	for (i=0; i<nifaces;i++)
	{
		if ((_g & ifaces[i].mask) == (ifaces[i].ip & ifaces[i].mask))
			return i;
	}
	return -1;
}


/*
 * Envia pacotes ARP do tipo type_op e com endereço MAC _dmac e endereço IP _dip 
* @param _dmac ponteiro para o endereço MAC de destino do pacote ARP
* @param _dip endereço IP de destino do pacote ARP
* @param _type_op tipo do pacote ARP: ARP_REQUEST ou ARP_REPLY
* 
* @since           2.0
*/
void send_arp_pkt (DWORD *_dmac, WORD _dip, WORD type_op )
{
	ARP_HEADER *arp;
	ETHERNET_HEADER * eth;
	
	eth =  malloc(sizeof(ETHERNET_HEADER) + sizeof(ARP_HEADER));
	int k;
	/*
	 * Procura a interface que deve ser mandado o arp para descobrir
	 * o enederćo mac a ser descoberto
	 * */
	for (k = 0; k < nifaces && ifaces[k].up && (Route2Interface (_dip) != -1); k++)
	{
		eth->net = ifaces[k].net;
		memcpy(&eth->sender[0], ifaces[k].mac, MAC_ADDR_LEN);
		memcpy(&eth->receiver[0], _dmac, MAC_ADDR_LEN);
		eth->type = htons(ARP);
		
		arp = ( ARP_HEADER * )(eth + 1);
		
		arp->protocol_type = htons(IP);
		arp->hardware_len = MAC_ADDR_LEN;
		arp->protocol_len = IP_ADDR_LEN;
		arp->operation = htons(type_op);
		memcpy(&arp->sender_hardware_addr[0], ifaces[k].mac, MAC_ADDR_LEN);
		arp->sender_ip_addr = ifaces[k].ip;
		memcpy(&arp->target_hardware_addr[0], _dmac, MAC_ADDR_LEN);
		arp->target_ip_addr = _dip;
		
		send_pkt(sizeof(ETHERNET_HEADER) + sizeof(ARP_HEADER), k, &arp->target_hardware_addr[0], ARP, (BYTE*)eth);	
	}
}

/*
 * Open a passive UDP socket. port must be in net-byte order.
 * @param port 
 * 
 * @since           2.0
 */
int passive_UDP_socket(u_short port)
{
    int sockd;		    /* socket descriptor	*/
    struct sockaddr_in sin; /* server address		*/
    
    bzero((char *)&sin, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = my_ip;
    sin.sin_port = port;    
    if ((sockd = socket(PF_INET, SOCK_DGRAM, 0)) < 0) 
		error_exit("Can't create socket: %s\n", strerror(errno)); 
    if (bind(sockd, (struct sockaddr *)&sin, sizeof(sin)) < 0) 
		error_exit("Can't bind to port %d: %s\n", ntohs(port), strerror(errno));
    return sockd;
}

/*
* @param buf String com os comandos digitados na shell
* 
* @since           2.0
*/
void sub_xnoop(char *buf)
{
	unsigned int i = 0, j = 0;
	unsigned int tam;
	
	char *aux1 = NULL;
	char *aux2;
	
	//Capturando os [options] e [filters] do analisador de pacotes (XNOOP)
	tam = strlen(buf);
	buf[tam-1] = ' ';
	aux2 = strtok_r(buf," ", &aux1);
	for (j=0; j<strlen(aux2); j++)
		*(parameters[i] + j) = aux2[j];
	*(parameters[i] + j) = '\0';
	i++;
	while ((aux2 = strtok_r(NULL, " ", &aux1)) != NULL)
	{
		for (j=0; j<strlen(aux2); j++)
			*(parameters[i] + j) = aux2[j];
		*(parameters[i] + j) = '\0';
		i++;
	}
	
	qtd_parameters = i;
	
	//Ajustando as opções padrões do XNOOP
	_xnoop.translation = 1;
	_xnoop.npkgs_max = 400000000;
	_xnoop.position = 1;
	_xnoop.modo = BASIC;
	
	//Verifica se os [options] e [filters] estão corretos
	if (check_parameters(i, parameters, &_xnoop))
	{
		//Habilita a execução do XNOOP 
		run_xnoop = 1;
		
		sem_wait(&sem_main);
	}
}

/*
 * @param ptr
 * 
 * @since           2.0
 */
void *subnet_send(void *ptr)
{
    int sockd, aux, i, hosts;
    struct sockaddr_in sin;
    PKT_QUEUE *pkt;
    NET_HOSTS *phost;
    
    if ((sockd = socket(PF_INET, SOCK_DGRAM, 0)) < 0) 
		error_exit("Can't create socket: %s\n", strerror(errno)); 
    while (1) {
		sem_wait(&sem_data_ready);
		while (1) {
			sem_wait(&sem_queue);
			if (queue_head == NULL) {
				sem_post(&sem_queue);
				break;
			}
			pkt = queue_head;
			queue_head = queue_head->next;
			sem_post(&sem_queue);
			hosts = ifaces[pkt->pkt->iface].nhosts;
			phost = ifaces[pkt->pkt->iface].hosts;
			for (i = 0; i < hosts; i++) {
				bzero((char *)&sin, sizeof(sin));
				sin.sin_family = AF_INET;
				sin.sin_port = phost[i].port;
				sin.sin_addr.s_addr = phost[i].ip;
				
			 	aux = sendto(sockd, &pkt->pkt->len, pkt->pkt->len, 0,
			 	(struct sockaddr *)&sin, sizeof(sin));
			}
			ifaces[pkt->pkt->iface].pkt_tx++;
			free(pkt->pkt);
			free(pkt);
		}
    }
}

/* Lê dados de um arquivo (CFG) que representa a configuração da rede virtual
 * @param fname Nome do arquivo (CFG) de entrada
 * @param port
 * @param iface 
 * 
 * @since           2.0
 */
int read_net_cfg(char *fname, u_short port, u_short iface)
{
    FILE *cfg_file;
    char line[100];
    char aux[100];
    NET_HOSTS *p;
    int first;
    int find = 0;
    
    cfg_file = fopen(fname, "r");
    if (!cfg_file)
		error_exit("Could not open configuration file: %s\n", fname);
    p = ifaces[iface].hosts;
    first = 1;
    while (fgets(line, 100, cfg_file)) 
    {
        char *s;
		if (line[0] != '#') {
			if (first) { /* First line != # has the network number */
				int net = atoi(line);
				net2iface[net]    = iface;
				ifaces[iface].net = net;
				first = 0;
			}
			else 
			{
				s = strtok(line, ",");						//Port Number
				p->port = ntohs(atoi(s));
				s = strtok(NULL, ",");						//Real IP Address
				p->ip   = inet_addr(s);
				if (p->port == port) {
					find = 1;
					my_ip  = p->ip;
					ifaces[iface].ip = p->ip;
					s = strtok(NULL, ",");					//MTU
					ifaces[iface].mtu = atoi(s);
					s = strtok(NULL, ",");					//MAC Address
					strcpy(aux, s);
					if ((s = strtok(NULL, ",")))			//Virtual IP Address
						ifaces[iface].ip = inet_addr(s);
					if ((s = strtok(NULL, ",")))			//Virtual Netmask Address
						ifaces[iface].mask = inet_addr(s);
					if ((s = strtok(NULL, ",")))			//UP (1) or DOWN (0)
						ifaces[iface].up = (BYTE)atoi(s);
					
					str2eth(aux, ifaces[iface].mac);
					
					ifaces[iface].ip_bcast = getBroadcast(ifaces[iface].ip, ifaces[iface].mask);
				}
				ifaces[iface].nhosts++;
				p++;
			}
		}
    }
    return find;
}

/* Tratamento do comando ifconfig <interface> <EndIP> <EndMAC>
 * @param b String com os comandos digitados na shell
 * 
 * @return 1 qdo não detectou problemas no comando ou 0, caso contrário
 * 
 * @since           2.0
 */
int sub_ifconfig(char *b)
{
	unsigned int id_iface = -1, i, find=0;
	unsigned int tam;
	
	DWORD* end_ip = 0;
	DWORD* end_mask = 0;
	
	char *aux1 = NULL;
	char *aux2 = NULL;
	
	//Capturando os parâmetros passados juntamente com o ifconfig
	tam = strlen(b);
	b[tam-1] = ' ';
	aux2 = strtok_r(b," ", &aux1);	/*Desconsidera o ifconfig*/
	
	/*Capturando o id da interface*/
	if ((aux2 = strtok_r(NULL, " ", &aux1)) != NULL)	
	{
		if (!is_decimal ((CHAR_T *)aux2))
		{
			printf("Incorret Interface.");
			return 0;			
		}
		
		id_iface = strtoul((const char *)aux2, NULL, 10);
		
		for (i=0; i<nifaces && !find; i++)
		{
			if (ifaces[i].interface == id_iface)
				find = 1;
		}
		
		i--;	//Indica o indice onde foi encontrado a interface correspondente a id_iface
		
		if (!find)
		{
			printf("Interface not found.");
			return 0;
		}
		
		/*Capturando o end IP da interface*/
		if ((aux2 = strtok_r(NULL, " ", &aux1)) != NULL)	
		{
			end_ip = to_ip_byte((CHAR_T *)aux2);
			
			if (!end_ip)
			{
				printf("Incorrect IP Address.");
				return 0;
			}
			
			/*Capturando a MASK da interface*/
			if ((aux2 = strtok_r(NULL, " ", &aux1)) != NULL)	
			{
				end_mask = to_ip_byte((CHAR_T *)aux2);
				
				if (!end_mask || !is_netmask((char *)aux2))
				{
					printf("Incorrect Netmask Address.");
					return 0;
				}
								
				ifaces[i].mask = (unsigned) (*end_mask);				
			}
			ifaces[i].ip = (unsigned) (*end_ip);
			
			//Descobrindo o Endereço de Broadcast
			ifaces[i].ip_bcast = getBroadcast(ifaces[i].ip, ifaces[i].mask);
			
			printf ("\nInterface  IP Address\t    Netmask\t     Broadcast\t      MAC Address\t  MTU\t  UP\n");
			print_if_info(i);	//Exibir informacoes de apenas uma interface
		}
		else
			printf("Usage: ifconfig <interface> <IP_Addres> <Netmask_Address>");
	}
	else
	{
		printf("Usage:  ifconfig <interface> <IP_Addres> <Netmask_Address>");
		printf("\n\tifconfig show");
	}
		
	return 1;
}

/* Tratamento do comando if <interface> [down|up]
 * @param b String com os comandos digitados na shell
 * 
 * @return 1 qdo não detectou problemas no comando ou 0, caso contrário
 * 
 * @since           2.0
 */
int sub_if( char* b)
{
	unsigned int id_iface = -1, i, find = 0;
	unsigned int tam;
	
	char *aux1 = NULL;
	char *aux2;
	
	//Capturando os parâmetros passados juntamente com o if
	tam = strlen(b);
	b[tam-1] = ' ';
	aux2 = strtok_r(b," ", &aux1);	/*Desconsidera o if*/
	
	/*Capturando o id da interface*/
	if ((aux2 = strtok_r(NULL, " ", &aux1)) != NULL)	
	{
		if (!is_decimal ((CHAR_T *)aux2))
		{
			printf("Incorret Interface.");
			return 0;			
		}
		
		id_iface = strtoul((const char *)aux2, NULL, 10);
		
		for (i=0; i<nifaces && !find; i++)
		{
			if (ifaces[i].interface == id_iface)
				find = 1;			
		}
		
		i--;
		
		if (!find)
		{
			printf("Interface not found.");
			return 0;
		}
		
		/*Capturando a opção escolhida para a interface (down ou up)*/
		if ((aux2 = strtok_r(NULL, " ", &aux1)) != NULL)	
		{
			if (!strncasecmp(aux2, "DOWN", 4) || !strncasecmp(aux2, "UP", 2))
			{
				if (!strncasecmp(aux2, "DOWN", 4))
					ifaces[i].up = 0;
				else
					ifaces[i].up = 1;
			}
			else
			{
				printf("Usage: if <interface> [down|up]");
				return 0;
			}
			printf ("\nInterface  IP Address\t    Netmask\t     Broadcast\t      MAC Address\t  MTU\t  UP\n");
			print_if_info(i);
		}
		else
			printf("Usage: if <interface> [down|up]");	
	}
	else
	{
		printf("Usage:  if <interface> [down|up]");
		printf("\n\tifconfig <interface> <IP_Addres> <Netmask_Address>");
		printf("\n\tifconfig show");
	}
	
	return 1;
}

/* Imprime informações da interface id_iface
 * @param id_iface Representa o id da interface
 * 
 * @since           2.0
 */
void print_if_info(int id_iface)
{
    char ip_s[16], mask_s[16], broad_s[16];
	
	printf ("%-10d %-16s %-16s %-16s %02X:%02X:%02X:%02X:%02X:%02X   %-7d %d\n", 
			id_iface, 
			ip2str(ip_s, ifaces[id_iface].ip), 
			ip2str(mask_s, ifaces[id_iface].mask), 
			ip2str(broad_s, ifaces[id_iface].ip_bcast), 
			ifaces[id_iface].mac[0],
			ifaces[id_iface].mac[1],
			ifaces[id_iface].mac[2],
			ifaces[id_iface].mac[3],
			ifaces[id_iface].mac[4],
			ifaces[id_iface].mac[5],
			ifaces[id_iface].mtu, 
			ifaces[id_iface].up );
}

/* Responsável por capturar os pacotes transmitidos na rede e 
 * exibi-los quando necessário, além disso trata os pacotes ARP
 * do tipo REQUEST e REPLY recebidos pelo host fazendo os ajustes
 * necessários 
 * 
 * @param ptr representa a porta de escuta dos pacotes
 * 
 * @since           2.0
 */
void *subnet_rcv(void *ptr)
{
    unsigned port = *((unsigned *)ptr);
    int      sockd;		/* socket descriptor		*/
    unsigned alen;		/* from-address length		*/
    struct sockaddr_in fsin;	/* address of a client		*/
    ETHERNET_HEADER *eth_h;
    ARP_HEADER *arp_h;
    IP_HEADER *ip_h;
    ICMP_HEADER *icmp_h;
    UDP_HEADER *udp_h;
    ICMP_DATA *icmp_data;
    ETHERNET_PKT *ppkt;
    
    sockd = passive_UDP_socket(port);
    ppkt = (ETHERNET_PKT*)&in_buf[0];
    
    RouteTableEntry * entry, *entry_aux;   
    WORD next_ip, next_ip_aux; 
    
    char resolve_arp[100], resolve_arp_aux[100] ;
    
    eth_h = (ETHERNET_HEADER *) (ppkt + 1);
    while(1)
    {
		int rv, riface;
		alen = sizeof (fsin);
		rv = recvfrom(sockd, in_buf, MAX_PKT_SZ, 0, (struct sockaddr *)&fsin, &alen);	
		if (rv < 0) 
			error_exit("error - recvfrom: %s\n", strerror(errno));
		
		riface = net2iface[eth_h->net];
		
		if (riface < 0) 
			error_exit("Packet received from unknown interface\n");
		else 
		{
			qtd_pkgs++;
			
			if (!memcmp(eth_h->receiver, broad_eth,6) || !memcmp(eth_h->receiver, ifaces[riface].mac, 6))
			{
				ifaces[riface].pkt_rx++; /* The packet must be processed */
					
				if (ntohs(eth_h->type) == ARP)
				{
					arp_h = (ARP_HEADER *) (eth_h + 1);
					
					if (arp_h->target_ip_addr == ifaces[riface].ip)
					{
						if (ntohs(arp_h->operation) == ARP_REPLY)
						{
							CHAR_T * _ip = format_address(arp_h->sender_ip_addr);
							CHAR_T * _mac = malloc(17);
							sprintf(
								(char*)_mac,
								"%02X:%02X:%02X:%02X:%02X:%02X",
								arp_h->sender_hardware_addr[0], 
								arp_h->sender_hardware_addr[1], 
								arp_h->sender_hardware_addr[2], 
								arp_h->sender_hardware_addr[3], 
								arp_h->sender_hardware_addr[4], 
								arp_h->sender_hardware_addr[5]
							);
								
							char *cmd_arp_add = malloc(45);
							sprintf(
								cmd_arp_add, 
								"arp add %s %s %d\n",
								(char*)_ip,
								(char*)_mac,
								ARP_TTL_DEF
							);
							
							sub_arp_add((void *)cmd_arp_add);
							
							if (arp_resolving)
							{
								if(print_resolving)
									printf("(%s, %s, %d)\n", (char*)_ip, (char*)_mac, ARP_TTL_DEF);
								sem_post(&sem_arp_res);
							}
						}
						else if (ntohs(arp_h->operation) == ARP_REQUEST)
						{
							CHAR_T * _ip = format_address(arp_h->sender_ip_addr);
							CHAR_T * _mac = malloc(17);
							sprintf(
								(char*)_mac,
								"%02X:%02X:%02X:%02X:%02X:%02X",
								arp_h->sender_hardware_addr[0], 
								arp_h->sender_hardware_addr[1], 
								arp_h->sender_hardware_addr[2], 
								arp_h->sender_hardware_addr[3], 
								arp_h->sender_hardware_addr[4], 
								arp_h->sender_hardware_addr[5]
							);
								
							char *cmd_arp_add = malloc(45);
							sprintf(
								cmd_arp_add, 
								"arp add %s %s %d\n",
								(char*)_ip,
								(char*)_mac,
								ARP_TTL_DEF
							);
							
							sub_arp_add((void *)cmd_arp_add);
							
							send_arp_pkt((DWORD*)&arp_h->sender_hardware_addr[0], arp_h->sender_ip_addr, ARP_REPLY);
							send_arp_pkt((DWORD*)&arp_h->sender_hardware_addr[0], arp_h->sender_ip_addr, ARP_REPLY);
						}
					}
				}
				else if (ntohs(eth_h->type) == IP)
				{
					ip_h = (IP_HEADER *) (eth_h + 1);
					
					SWORD sum_ip_rcv = ntohs(ip_h->checksum);	//Guardando o cksum do ip_header
					ip_h->checksum = 0;
					SWORD sum_ip_calc = calc_check_sum(ip_h, IP);
					ip_h->checksum = htons(sum_ip_rcv);		//Retornando o cksum do ip_header
					
					if (sum_ip_rcv != sum_ip_calc)	return 0;
					
					if (ip_h->destination_address == ifaces[riface].ip)
					{
						if (ip_h->protocol == ICMP)
						{
							icmp_h = (ICMP_HEADER *)(ip_h + 1);
							
							SWORD sum_icmp_rcv = ntohs(icmp_h->checksum);		//Guardando o cksum do icmp_header
							icmp_h->checksum = 0;
							SWORD sum_icmp_calc = calc_check_sum(icmp_h, ICMP);
							icmp_h->checksum = htons(sum_icmp_rcv);		//Retornando o cksum do icmp_header
							
							if (sum_icmp_rcv != sum_icmp_calc)	return 0;
							
							float dif;
					
							switch(icmp_h->type)
							{
								case ECHO_REQUEST:
									
									entry = FindProxNo(routeTable, (WORD) ip_h->source_address);
									
									if (entry)
									{
										if (*entry->GATEWAY == *entry->TARGET)
										{
											sprintf(resolve_arp, "arp res %s\n", format_address (ip_h->source_address));
											next_ip =ip_h->source_address;
										}
										else
										{
											sprintf(resolve_arp, "arp res %s\n", format_address (*entry->GATEWAY));
											next_ip = *entry->GATEWAY;
										}
										
										if(sub_arp_res (resolve_arp, 0))
										{
											send_icmp_pkt (0, ECHO_REPLAY, entry->interface, next_ip, ip_h->source_address, ip_h->destination_address, (ip_h->time_alive - 1),ntohs(ip_h->identification),0);											
										}
										//else
											//printf("\nNOT RESOLVE SOURCE ADDRESS %s\n", format_address(ip_h->source_address));
									}
								break;
								
								case ECHO_REPLAY:
									gettimeofday( &stop_time, NULL );
									dif = (float)(stop_time.tv_sec - start_time.tv_sec);
									dif += (stop_time.tv_usec - start_time.tv_usec)/(float)1000000;
									
									if (ping_running)
									{
										sem_post(&sem_ping);
										printf("%u bytes from %s: icmp_seq=%u ttl=%u Time=%.4f ms\n", 
											(ntohs(ip_h->total_length) + sizeof(ETHERNET_HEADER)), 
											format_address(ip_h->source_address), 
											ntohs(ip_h->identification), 
											ip_h->time_alive,
											(dif*1000)
										);
									}
									else if (trace_running)
									{
										sem_post(&sem_trace);
										printf("%s %.4f ms\n", format_address(ip_h->source_address), (dif*1000));
										trace_running = 0;
									}
								break;
								
								case DESTINATION_UN:
									if (ping_running)
									{
										printf("Destination unreachable\n");
										sem_post(&sem_ping);
									}
									else if (trace_running)
									{
										printf("*\n");
									}
								break;
								
								case TTL:
									gettimeofday( &stop_time, NULL );
									dif = (float)(stop_time.tv_sec - start_time.tv_sec);
									dif += (stop_time.tv_usec - start_time.tv_usec)/(float)1000000;
									
									if (trace_running)
									{
										if (qtd_pkg_du == 0)
											printf("%s %.4f ms\n", format_address(ip_h->source_address), (dif*1000));
										qtd_pkg_du++;
									}
								break;
								
								case REDIRECT:
									icmp_data = (ICMP_DATA *)(icmp_h + 1);															
									entry = BuildRouteTableEntry((CHAR_T*)format_address(ip_h->source_address), (CHAR_T*)format_address(icmp_data->prox_no), (CHAR_T*)"255.255.255.255", 0, (BYTE)Route2Interface(icmp_data->prox_no), (int)ARP_TTL_DEF);
									AddRouteTableEntry (routeTable, entry);
								break;
							}
						}											
					}	
					else if (ip_h->source_address != ifaces[riface].ip)	//Processar apenas pacotes que foram enviados pelos outros hosts e não aqueles enviados por mim
					{
						if (ip_h->protocol == ICMP)
						{
							icmp_h = (ICMP_HEADER *)(ip_h + 1);
							
							switch(icmp_h->type)
							{
								case ECHO_REQUEST:
									//criar pacote REQUEST (pois chegou em um gateway) alterar os MACs e decrementar o TTL
									entry = FindProxNo(routeTable, (WORD) ip_h->destination_address);
									
									if (entry)
									{							
										if (*entry->GATEWAY == *entry->TARGET)
										{
											sprintf(resolve_arp, "arp res %s\n", format_address (ip_h->destination_address));
											next_ip = ip_h->destination_address;
										}
										else
										{											
											sprintf(resolve_arp, "arp res %s\n", format_address (*entry->GATEWAY));
											next_ip = *entry->GATEWAY;
										}
										
										if (ip_h->time_alive == 0)	//Criar pacote de TTL_EXCEEDED
										{
											entry = FindProxNo(routeTable, (WORD) ip_h->source_address);
								
											if (*entry->GATEWAY == *entry->TARGET)
											{	
												sprintf(resolve_arp, "arp res %s\n", format_address (ip_h->source_address));
												next_ip = ip_h->source_address;
											}
											else
											{								
												sprintf(resolve_arp, "arp res %s\n", format_address (*entry->GATEWAY));
												next_ip = *entry->GATEWAY;
											}
											
											if(sub_arp_res (resolve_arp, 0))
												send_icmp_pkt (0, TTL, entry->interface, next_ip, ip_h->source_address, ifaces[entry->interface].ip, ip_h->time_alive, ntohs(ip_h->identification),0);
											
											break;
										}
										else //criar pacote de REQUEST
										{	
											if(sub_arp_res (resolve_arp, 0))
											{	
												send_icmp_pkt (0, ECHO_REQUEST, entry->interface, next_ip, ip_h->destination_address, ip_h->source_address, (ip_h->time_alive - 1),ntohs(ip_h->identification),0);
												
												if (entry->interface == riface)
												{
													entry_aux = FindProxNo(routeTable, (WORD) ip_h->source_address);
									
													if (*entry_aux->GATEWAY == *entry_aux->TARGET)
													{	
														sprintf(resolve_arp_aux, "arp res %s\n", format_address (ip_h->source_address));
														next_ip_aux = ip_h->source_address;
													}
													else
													{								
														sprintf(resolve_arp_aux, "arp res %s\n", format_address (*entry_aux->GATEWAY));
														next_ip_aux = *entry_aux->GATEWAY;
													}
													
													if(sub_arp_res (resolve_arp_aux, 0))
														send_icmp_pkt (0, REDIRECT, entry_aux->interface, next_ip_aux, ip_h->source_address, ip_h->destination_address, (ip_h->time_alive),ntohs(ip_h->identification), next_ip);
													//else
														//printf("\nNOT RESOLVE: GATEWAY: %s IP-SOURCE: %s IP-DEST %s PROX-IP: %s\n", format_address(next_ip_aux),format_address(ip_h->destination_address),format_address(ip_h->source_address),format_address(next_ip));
												}
												break;											
											}
											//else
												//printf("\nNOT RESOLVE SOURCE ADDRESS %s\n", format_address(ip_h->source_address));
										}
									}
										
									//criando pacote DESTINATION_UREACHABLE para o remetente
									entry = FindProxNo(routeTable, (WORD) ip_h->source_address);
									
									if (*entry->GATEWAY == *entry->TARGET)
									{	
										sprintf(resolve_arp, "arp res %s\n", format_address (ip_h->source_address));
										next_ip = ip_h->source_address;
									}
									else
									{								
										sprintf(resolve_arp, "arp res %s\n", format_address (*entry->GATEWAY));
										next_ip = *entry->GATEWAY;
									}
									
									if(sub_arp_res (resolve_arp, 0))
										send_icmp_pkt (0, DESTINATION_UN, entry->interface, next_ip, ip_h->source_address, ifaces[entry->interface].ip, (ip_h->time_alive - 1),ntohs(ip_h->identification),0);
								
								break;
								
								case ECHO_REPLAY:
								case TTL:
								case DESTINATION_UN:
								
									//restransmitir pacote (pois chegou em um gateway) alterar os MACs
									entry = FindProxNo(routeTable, (WORD) ip_h->destination_address);
									
									if (entry)
									{
										if (*entry->GATEWAY == *entry->TARGET)
										{
											sprintf(resolve_arp, "arp res %s\n", format_address (ip_h->destination_address));
											next_ip = ip_h->destination_address;
										}
										else
										{
											sprintf(resolve_arp, "arp res %s\n", format_address (*entry->GATEWAY));
											next_ip = *entry->GATEWAY;
										}
															
										if(sub_arp_res (resolve_arp, 0))
										{
											send_icmp_pkt (0, icmp_h->type, entry->interface, next_ip, ip_h->destination_address, ip_h->source_address, ip_h->time_alive, ntohs(ip_h->identification),0);
										}
									}
								break;
							}
						}							
						else if (ip_h->protocol == UDP)
						{
							udp_h = (UDP_HEADER *)(ip_h + 1);
							
							if (ntohs(udp_h->dest_port) == 520)
							{
								printf("\nRecebi pacote UDP\n");
								//Reconstruir a tabela RIP
								//Analizar cada entrada da tabela RIP e verificar se possui uma rota para essa entrada na tabela de roteamento;
								//Caso não exista então inclua essa entrada na tabela de roteamento com: máscara baseada na classe do endereço IP da rede; gateway igual ao endereço ip de quem eu recebi essa tabela
								// e incremente o custo para esta entrada em uma unidade
								//Caso exista então verifique se ela é uma entrada estática, neste caso não há o que fazer, caso contrário, verifica se o custo
								// é menor do que a dela em pelo menos duas unidades, se for atualize (remova a entrada atual e insira uma nova entrada): o custo desta entrada como sendo o custo observado mais uma unidade e o gateway como sendo o endereço ip de quem eu 
								//recebi essa tabela
								
								RIP_PKT *rip_pkt;
								
								printf("\nLength: %d\n",ntohs(udp_h->length));
								
								int i,j, tam = ntohs(udp_h->length) - sizeof(UDP_HEADER);
								char *mask;
																
								//memcpy(&udp_data[0], &udp_h->fisrt_data, tam);
								
								i = 0;
								printf("\nTam: %d\n",tam);
								BYTE *b = (BYTE *)(udp_h + 1);
								b = b - 1;
								while(i < (tam/sizeof(RIP_PKT)))
								{
									rip_pkt = (RIP_PKT *) (b + i);
									printf("\nRede: %s\n",format_address(rip_pkt->IP));
									printf("\nCusto: %d\n",(int)rip_pkt->metric);
									i += sizeof(RIP_PKT);
									
									mask = to_ip_mask_default(rip_pkt->IP);
									
									entry = BuildRouteTableEntry(format_address(rip_pkt->IP), format_address(ip_h->source_address), (CHAR_T*) mask, (rip_pkt->metric + 1), riface, 180);
									
									sem_wait(&allow_route_entry);
									RouteTableEntry *find_entry = FindRouteTableEntry2(routeTable, entry, 1);
									
									if (find_entry && (find_entry->COST - 2)  >= rip_pkt->metric)
									{ 										
										find_entry = RemoveRouteTableEntry(routeTable, find_entry);
										
										free(find_entry);
									}
									
									AddRouteTableEntry(routeTable,entry);
									
									sem_post(&allow_route_entry);
								}	
							}							
						}
					}		        
					//TODO
				}
			}
			//Fim da busca
			
			_xnoop.npkgs = qtd_pkgs;
    			   
			if (run_xnoop)
			{
				sem_wait(&sem_xnoop);
				xnoop(qtd_parameters, parameters, eth_h, &_xnoop, ifaces);
				sem_post(&sem_xnoop);
			}
		}
    }
}
			
/* Responsável por criar pacotes e empilhá-los na PILHA de pacotes
 * 
 * @param len Tamanho do pacote, desconsiderando o tamanho de ETHERNET_PKT
 * @param iface Identificação da interface de envio do pacote
 * @param da End. MAC de destino do pacote
 * @param type Tipo do pacote
 * @param data Dados do pacote
 * 
 * @since           2.0
 */
void send_pkt(u_short len, BYTE iface, BYTE *da, u_short type, BYTE *data)
{
    ETHERNET_PKT *pkt;
    PKT_QUEUE *qaux;
    ETHERNET_HEADER * ether;
     
    pkt = malloc(len + sizeof(ETHERNET_PKT) );
    pkt->len   = len + sizeof(ETHERNET_PKT);
    pkt->iface = iface;
    pkt->net   = ifaces[iface].net;
    memcpy(&pkt->sa[0], ifaces[iface].mac, MAC_ADDR_LEN);
    memcpy(&pkt->da[0], da, MAC_ADDR_LEN);
    pkt->type = htons(type);   
   
    ether = (ETHERNET_HEADER *) (pkt+1);
    
    memcpy(ether, data, len);
   
    qaux = malloc(sizeof(PKT_QUEUE));
    qaux->next = NULL;
    qaux->pkt  = pkt;
    sem_wait(&sem_queue);
    if (queue_head) 
		queue_tail = queue_tail->next = qaux;
    else 
    {
		queue_head = queue_tail = qaux;
		sem_post(&sem_data_ready);
    }    
    sem_post(&sem_queue);
}

/* Responsável por criar pacotes oriundos do arquivo TRACE e empilhá-los na PILHA de pacotes
 * 
 * @param len Tamanho do pacote, desconsiderando o tamanho de ETHERNET_PKT e ETHERNET_HEADER
 * @param da End. MAC de destino do pacote
 * @param type_ether Tipo do pacote
 * @param data Dados do pacote
 * 
 * @since           2.0
 */
void xnoop_send_pkt(u_short len, u_short type_ether, BYTE *data)
{
    ETHERNET_PKT *pkt;
    PKT_QUEUE *qaux;
    ETHERNET_HEADER * ether;
    ETHER_HEADER * ether_2;
    void * p;
     
    pkt = malloc(len + sizeof(ETHERNET_HEADER) + sizeof(ETHERNET_PKT));
    pkt->len   = len + sizeof(ETHERNET_HEADER) + sizeof(ETHERNET_PKT);
    
	ether_2 = (ETHER_HEADER *) (data);
    
    /* Esses dois campos não existem em ETHER_HEADER, por isso eles vão com 0 (zero) no ETHERNET_PKT*/
    pkt->iface = 0;
    pkt->net   = 0;
    
    memcpy(&pkt->sa[0], ether_2->sender, MAC_ADDR_LEN);
    memcpy(&pkt->da[0], ether_2->receiver, MAC_ADDR_LEN);
    pkt->type = htons(type_ether);
    
    //Remontando o ETHERNET_HEADER baseado no ETHER_HEADER
    ether = (ETHERNET_HEADER *) (pkt+1);
    
    ether->net = 0;
    memcpy(&ether->receiver[0], ether_2->sender, MAC_ADDR_LEN);
    memcpy(&ether->sender[0], ether_2->receiver, MAC_ADDR_LEN);
    ether->type = htons(type_ether);
            
    p = (void *) (ether+1);
    
    memcpy(p, data, len);
   
    qaux = malloc(sizeof(PKT_QUEUE));
    qaux->next = NULL;
    qaux->pkt  = pkt;
    sem_wait(&sem_queue);
    if (queue_head) 
		queue_tail = queue_tail->next = qaux;
    else 
    {
		queue_head = queue_tail = qaux;
		sem_post(&sem_data_ready);
    }    
    sem_post(&sem_queue);
}

/* Responsável por ler pacotes do arquivo TRACE e enviá-los para a rede
 * 
 * @param b String com os comandos digitados na shell
 * 
 * @return 1 qdo não detectou problemas no comando ou 0, caso contrário
 * 
 * @since           2.0
 */
int sub_send_trace(char* b)
{
	unsigned int tam;
	unsigned int interval = 0;
	
	FILE *inf;
	
	FILE_HEADER file_header;
	FRAME_HEADER frame_header;
	
	char *aux1 = NULL;
	char *aux2 = NULL;
	
	char *trace_name;
	
	char pkt_buf[BUF_SIZE];	
	
	ETHER_HEADER * pkg_ethernet;
    IP_HEADER * pkg_ip;
    ARP_HEADER * pkg_arp;
	
	//Capturando os parâmetros passados juntamente com o send
	tam = strlen(b);
	b[tam-1] = ' ';
	aux2 = strtok_r(b," ", &aux1);	/*Desconsidera o send*/	

	/*Capturando o nome do arquivo trace*/
	if ((trace_name = strtok_r(NULL, " ", &aux1)) != NULL)	
	{
		/*Capturando o valor do intervalo de renvio de pacotes*/
		if ((aux2 = strtok_r(NULL, " ", &aux1)) != NULL)	
		{
			if (!is_decimal ((CHAR_T *)aux2))
			{
				printf("Incorret interval. Interval between 1 and ...");
				return 0;			
			}
			
			interval = strtoul((const char *)aux2, NULL, 10);
		}
			
		inf = fopen(trace_name, "rb");
	
		if (!inf)
		{
			printf("Could not open file: %s", trace_name);	
			return 0;
		}

		/* read file header */
		fread(&file_header, sizeof(FILE_HEADER), 1, inf);

		if (file_header.magic_number != 0xa1b2c3d4) 
			invert_file_header(&file_header);
			
		printf("\nSending Packets.\n");
		
		sending_packets = 1;
			
		while (fread(&frame_header, sizeof(FRAME_HEADER), 1, inf)) 
		{
			if (file_header.magic_number != 0xa1b2c3d4) 
				invert_pkt_header(&frame_header);

			/*Le o conteudo do pacote*/
			fread(pkt_buf, frame_header.capt_data, 1, inf);

			/*Capturando um pacote ethernet*/
			pkg_ethernet = (ETHER_HEADER *)pkt_buf;
			
			switch (ntohs(pkg_ethernet->type))
			{
				case ARP:
					pkg_arp = (ARP_HEADER *)( pkg_ethernet + 1 );
		    		xnoop_send_pkt(sizeof(ARP_HEADER), ARP, (BYTE*)pkg_arp);		    		
		    	break;
		    	
		    	case IP:
		    		
		    		pkg_ip = (IP_HEADER *)( pkg_ethernet + 1 );
		    		
		    		switch(pkg_ip->protocol)
		    		{
		    			case TCP:
		    				xnoop_send_pkt(sizeof(IP_HEADER) + sizeof(TCP_HEADER), IP, (BYTE*)pkg_ip);
		    			break;
		    			
		    			case UDP:
		    				xnoop_send_pkt(sizeof(IP_HEADER) + sizeof(UDP_HEADER), IP, (BYTE*)pkg_ip);
		    			break;
		    			
		    			case ICMP:
		    				xnoop_send_pkt(sizeof(IP_HEADER) + sizeof(ICMP_HEADER), IP, (BYTE*)pkg_ip);	
		    			break;
		    		}
		    	break;
		    }
		    sleep(interval);
		}
		sending_packets = 0;
		
		printf("\nPackets Sended.\n");
	}
	else
		printf("Usage: send <trace> <interval>");
	
	return 1;
}

/* */
int sub_get_parameters(char** res, char*b)
{
	/*
	unsigned int i = 0, j = 0;
	unsigned int tam;
	
	char *aux1;
	char *aux2;
	
	char *res[MAX_PARAMETERS];
	
	//Capturando os [options] e [filters] do analisador de pacotes (XNOOP)
	for (i =0; i < MAX_PARAMETERS; i++)
		res[i] = maloc(MAX_SIZE_PARAMETER);
	i = 0;
	tam = strlen(buf);
	buf[tam-1] = ' ';
	aux2 = strtok_r(buf," ", &aux1);
	for (j=0; j<strlen(aux2); j++)
		*(res[i] + j) = aux2[j];
	*(res[i] + j) = '\0';
	i++;
	while ((aux2 = strtok_r(NULL, " ", &aux1)) != NULL)
	{
		for (j=0; j<strlen(aux2); j++)
			*(res[i] + j) = aux2[j];
		*(res[i] + j) = '\0';
		i++;
	}
	*/
	return 0;
}

/* */
int sub_arp_del( void *arg )
{
	if (!arg)
		return 0;
	int tam;
	ArpTableEntry *entry;
	char *aux1 = NULL;
	char *aux2 = NULL;
	char *_ip;	
	DWORD * end_ip;
	
	char *b = (char *)arg;
	
	//Capturando os parâmetros passados juntamente com o arp del
	tam = strlen(b);
	b[tam-1] = ' ';
	aux2 = strtok_r(b," ", &aux1);	/*Desconsidera o arp*/
	aux2 = strtok_r(NULL," ", &aux1);	/*Desconsidera o del*/
	
	/*Capturando o end. IP*/
	if ((_ip = strtok_r(NULL, " ", &aux1)) != NULL)
	{
		if (!is_ip ((CHAR_T *)_ip))
		{
			printf("Incorret IP Address.");
			return 0;
		}
		
		end_ip = to_ip_byte((CHAR_T *)aux2);
		
		/* Código para remoção na tabela */
		sem_wait(&allow_entry);
		entry = BuildArpTableEntry((CHAR_T*)_ip, NULL, 0);		
		entry = RemoveArpTableEntry (arpTable, entry);
		if(entry)
		{
			free(entry);
			DisplayArpTable(arpTable);
		}
		sem_post(&allow_entry);
	}
	else				
		printf("Usage: arp del [EndIP]");
	return 1;
}

/* */
int sub_arp_add( void * arg )
{		
	if(!arg)
		return 0;
	int tam;
	ArpTableEntry *entry;
	char *aux1 = NULL, *aux2 = NULL;
	char * _mac, *_ip;
	int ttl;
	char * b = (char *)arg;
	
	//Capturando os parâmetros passados juntamente com o arp add
	tam = strlen(b);
	b[tam-1] = ' ';
	aux2 = strtok_r(b," ", &aux1);	/*Desconsidera o arp*/
	aux2 = strtok_r(NULL," ", &aux1);	/*Desconsidera o add*/
	
	/*Capturando o end. IP*/
	if ((_ip = strtok_r(NULL, " ", &aux1)) != NULL)
	{
		if (!is_ip ((CHAR_T *)_ip))
		{
			printf("Incorret IP Address.");
			return 0;
		}
		
		/*Capturando o end. MAC*/
		if ((_mac = strtok_r(NULL, " ", &aux1)) != NULL)
		{
			if (!is_mac_address ((CHAR_T *)_mac))
			{
				printf("Incorret MAC Address.");
				return 0;
			}
			
			/*Capturando o ttl*/
			if ((aux2 = strtok_r(NULL, " ", &aux1)) != NULL)
			{
				ttl = strtoul((const char *)aux2, NULL, 10);
				
				if (ttl < -1)
				{
					printf("Incorret ttl.");
					return 0;
				}
	
				/* Código para inserção na tabela */
				sem_wait(&allow_entry);
				entry = BuildArpTableEntry((CHAR_T*)_ip, (CHAR_T*)_mac, ttl);
				AddArpTableEntry (arpTable, entry);
				sem_post(&allow_entry);
				return 1;
			}
			else				
				printf("Usage: arp add [EndIP] [EndEth] [ttl]");
		}
		else				
			printf("Usage: arp add [EndIP] [EndEth] [ttl]");
	}
	else				
		printf("Usage: arp add [EndIP] [EndEth] [ttl]");
	return 0;
}

/* */
int sub_arp( char *b )
{
	char *aux1 = NULL, *aux2 = NULL;
	int tam, ttl;
	
	//Capturando os parâmetros passados juntamente com o arp add
	tam = strlen(b);
	b[tam-1] = ' ';
	aux2 = strtok_r(b," ", &aux1);	/*Desconsidera o arp*/
	
	/*Capturando o ttl*/
	if ((aux2 = strtok_r(NULL, " ", &aux1)) != NULL)
	{
		ttl = strtoul((const char *)aux2, NULL, 10);
		
		if (ttl < -1)
		{
			printf("Incorret TTL. Just TTL more than -1.");
			return 0;
		}
		
		ARP_TTL_DEF = ttl;
		
		printf ("TTL updated.");
	}
	else
	{				
		printf("Usage:  arp add [EndIP] [EndEth] [ttl]");
		printf("\n\tarp del [EndIP]");
		printf("\n\tarp res [EndIP]");
		printf("\n\tarp show");
		printf("\n\tarp [ttl]");
	}
	
	return 0;
}

/* */
int sub_arp_res( void *arg , int print)
{
	if (!arg)
		return 0;
	int tam;
	int rv;
	
	char *aux1 = NULL;
	char *aux2 = NULL;
	CHAR_T *_mac = NULL;
	
	DWORD * end_ip;
	
	char *b = (char *)arg;
	
	//Capturando os parâmetros passados juntamente com o arp res
	tam = strlen(b);
	b[tam-1] = ' ';
	aux2 = strtok_r(b," ", &aux1);	/*Desconsidera o arp*/
	aux2 = strtok_r(NULL," ", &aux1);	/*Desconsidera o res*/
	/*Capturando o end. IP*/
	if ((aux2 = strtok_r(NULL, " ", &aux1)) != NULL)
	{
		if (!is_ip ((CHAR_T *)aux2))
		{
			printf("Incorret IP Address.");
			return 0;
		}
		
		end_ip = to_ip_byte((CHAR_T *)aux2);
		
		/* Código para resolução de endereços */
		sem_wait(&allow_entry);
		ArpTableEntry * entry;
		entry = BuildArpTableEntry((CHAR_T *)aux2, NULL, 0);
		entry = FindArpTableEntry (arpTable, entry, 1);	
		
		if (entry)
		{
			_mac = format_mac_address(*(entry->MAC));
			entry->TTL = ARP_TTL_DEF;
			AddArpTableEntry(arpTable,entry);
			if(print)
				printf ("\n(%s, %s, %d)\n", aux2, (char*)_mac, entry->TTL);
			sem_post(&allow_entry);
			return 1;
		}			
		else
		{
			sem_post(&allow_entry);
			
			send_arp_pkt((DWORD *)&broad_eth[0], *(end_ip), ARP_REQUEST);
			
			struct timespec ts;
			
			ts.tv_sec = time(NULL) + TIMEOUT;
			ts.tv_nsec = 0;
			
			arp_resolving = 1;
			
			print_resolving = print;
			
			while ((rv = sem_timedwait(&sem_arp_res, &ts) ) == -1 && errno == EINTR)
               continue;

			arp_resolving = 0;
			
			print_resolving = 0;
			
			if (rv == -1 && errno == ETIMEDOUT) 
			{
				//the semaphore returned
				if(print)
	 				printf("Ip address not found!\n");
	 			return 0;
			}
		}
		return 1;
		
	}
	else
	{				
		printf("Usage: arp res [EndIP]");
		return 0;
	}
}

/* */
void control_xnoop()
{
	if (run_xnoop || sending_packets || ping_running || trace_running || rip_running)
	{
		if (run_xnoop)
			run_xnoop = 0;
		else if (ping_running)
			ping_running = 0;
		else if (trace_running)
			trace_running = 0;
		else if (rip_running)
			rip_running = 0;
		else
			sending_packets = 0;
	}
	else
	{
		printf("\n");
		exit(0);
	}
	
	sem_post(&sem_main);
}

void * update_arp_table(void *p)
{
	
	ArpTableEntry *_previous, *_entry;
	while(1)
	{
		sem_wait(&allow_entry);
		
		_entry = arpTable->list;
		_previous  = NULL;
		
		if(arpTable->length == 0)
		{
			sem_post(&allow_entry);
			continue;
		}

		if(arpTable->length == 1 && _entry->TTL == 1)
		{
			send_arp_pkt(_entry->MAC, *(_entry->IP), ARP_REQUEST);

			free(_entry);
			arpTable->length--;
			arpTable->list = NULL;			
		}
		else
		{			
			while (_entry)
			{
				if (_entry->TTL == -1)
				{
					_entry = _entry->next;	
					continue;
				}
				
				_entry->TTL--;
						
				if(_entry->TTL == 0)
				{
					if(arpTable->list == _entry)
					{
						arpTable->list = _entry->next;
						
						send_arp_pkt(_entry->MAC, *(_entry->IP), ARP_REQUEST);	
						
						free(_entry);
						
						_entry = arpTable->list;
					}
					else
					{
						_previous->next = _entry->next;
						
						send_arp_pkt(_entry->MAC, *(_entry->IP), ARP_REQUEST);
						
						free(_entry);
						
						_entry = _previous;		
					}
					
					arpTable->length--;
				}
				else
				{
					_previous = _entry;
					_entry = _entry->next;	
				}
			}
		}
		
		sem_post(&allow_entry);
		sleep(1);
	}
	return NULL;
}

void * update_route_table(void *p)
{	
	RouteTableEntry *_previous, *_entry;
	while(1)
	{
		sem_wait(&allow_route_entry);
		
		_entry = routeTable->list;
		_previous  = NULL;
		
		if(routeTable->length == 0)
		{
			sem_post(&allow_route_entry);
			continue;
		}

		if(routeTable->length == 1 && _entry->TTL == 1)
		{
			free(_entry);
			routeTable->length--;
			routeTable->list = NULL;			
		}
		else
		{			
			while (_entry)
			{
				if (_entry->TTL == -1)
				{
					_entry = _entry->next;	
					continue;
				}
				
				_entry->TTL--;
						
				if(_entry->TTL == 0)
				{
					if(routeTable->list == _entry)
					{
						routeTable->list = _entry->next;	
						
						free(_entry);
						
						_entry = routeTable->list;
					}
					else
					{
						_previous->next = _entry->next;
						
						free(_entry);
						
						_entry = _previous;		
					}
					
					routeTable->length--;
				}
				else
				{
					_previous = _entry;
					_entry = _entry->next;	
				}
			}
		}
		
		sem_post(&allow_route_entry);
		sleep(1);
	}
	return NULL;
}

/* */
int sub_route_add( void *arg )
{
	int tam;
	BYTE _interface;	
	char *aux1 = NULL, *aux2 = NULL, *_target = NULL, *_gateway = NULL, *_netmask = NULL;
	RouteTableEntry *entry;
	char resolve_arp[100];
	
	if (!arg)
		return 0;
	char *b = (char *)arg;
	
	//Capturando os parâmetros passados juntamente com o route add
	tam = strlen(b);
	b[tam-1] = ' ';
	aux2 = strtok_r(b," ", &aux1);	/*Desconsidera o route*/
	aux2 = strtok_r(NULL," ", &aux1);	/*Desconsidera o add*/
	/*Capturando o end. IP de destino*/
	if ((_target = strtok_r(NULL, " ", &aux1)) != NULL)
	{
		if (!is_ip ((CHAR_T *)_target))
		{
			printf("Incorret Target IP Address.");
			return 0;
		}
		
		/*Capturando a mascara de subrede*/
		if ((_netmask = strtok_r(NULL, " ", &aux1)) != NULL)
		{
			if (!is_ip ((CHAR_T *)_netmask))
			{
				printf("Incorret MASK Address.");
				return 0;
			}
			
			/*Capturando o end. IP do Gateway*/
			if ((_gateway = strtok_r(NULL, " ", &aux1)) != NULL)
			{
				if (!is_ip ((CHAR_T *)_gateway))
				{
					printf("Incorret Gateway IP Address.");
					return 0;
				}
				
				/* Código para inserção na tabela */
				DWORD *_gw = to_ip_byte((CHAR_T*)_gateway);
				DWORD *_tg = to_ip_byte((CHAR_T*)_target);
				_interface = Route2Interface((WORD)*_gw);
				
				if (_interface == (BYTE) -1)
				{
					printf("Incorret Route.");
					return 0;
				}
				
				sem_wait(&allow_route_entry);
				entry = BuildRouteTableEntry((CHAR_T*)_target, (CHAR_T*)_gateway, (CHAR_T*)_netmask, 0, _interface, -1);
				AddRouteTableEntry (routeTable, entry);
				
				if (*_gw != *_tg)
				{
					sprintf(resolve_arp, "arp res %s\n", format_address ((WORD)*_gw));
					sub_arp_res (resolve_arp, 0);
				}
				
				sem_post(&allow_route_entry);
				return 1;
			}
			else				
				printf("Usage: route add [Target] [Netmask] [Gateway]");
		}
		else				
			printf("Usage: route add [Target] [Netmask] [Gateway]");
	}
	else				
		printf("Usage: route add [Target] [Netmask] [Gateway]");
	
	return 0;
}

/* */
int sub_route_del( void *arg )
{	
	int tam;
	BYTE _interface;
	char *aux1 = NULL, *aux2 = NULL, *_target = NULL, *_gateway = NULL, *_netmask = NULL;
	RouteTableEntry *entry;
	
	if (!arg)
		return 0;
	char *b = (char *)arg;
	
	//Capturando os parâmetros passados juntamente com o route del
	tam = strlen(b);
	b[tam-1] = ' ';
	aux2 = strtok_r(b," ", &aux1);	/*Desconsidera o route*/
	aux2 = strtok_r(NULL," ", &aux1);	/*Desconsidera o del*/
	/*Capturando o end. IP de destino*/
	if ((_target = strtok_r(NULL, " ", &aux1)) != NULL)
	{
		if (!is_ip ((CHAR_T *)_target))
		{
			printf("Incorret Target IP Address.");
			return 0;
		}
		
		/*Capturando a mascara de subrede*/
		if ((_netmask = strtok_r(NULL, " ", &aux1)) != NULL)
		{
			if (!is_ip ((CHAR_T *)_netmask))
			{
				printf("Incorret MASK Address.");
				return 0;
			}
			
			/*Capturando o end. IP do Gateway*/
			if ((_gateway = strtok_r(NULL, " ", &aux1)) != NULL)
			{
				if (!is_ip ((CHAR_T *)_gateway))
				{
					printf("Incorret Gateway IP Address.");
					return 0;
				}
				
				//TODO falta chamar a função responsável por verificar qual interface tem que ser usada para a remoção por enquanto está sendo usado 0 (zero)
				
				/* Código para remoção na tabela */
				DWORD *_gw = to_ip_byte((CHAR_T*)_gateway);
				//DWORD *_nm = to_ip_byte((CHAR_T*)_netmask);
				_interface = Route2Interface((WORD)*_gw);
				sem_wait(&allow_route_entry);
				entry = BuildRouteTableEntry((CHAR_T*)_target, (CHAR_T*)_gateway, (CHAR_T*)_netmask, 0, _interface, 0);
				entry = RemoveRouteTableEntry (routeTable, entry);
				if(entry)
				{
					free(entry);
					DisplayRouteTable(routeTable);
				}
				sem_post(&allow_route_entry);
				return 1;
			}
			else				
				printf("Usage: route del [Target] [Netmask] [Gateway]");
		}
		else				
			printf("Usage: route del [Target] [Netmask] [Gateway]");
	}
	else				
		printf("Usage: route del [Target] [Netmask] [Gateway]");
	
	return 0;

}

/* */
int sub_traceroute( void *arg )
{
	if (!arg)
		return 0;
	int tam;
	
	char *aux1 = NULL;
	char *aux2 = NULL;
	DWORD *end_ip;
	RouteTableEntry *entry;
	
	char *b = (char *)arg;
	
	//Capturando os parâmetros passados juntamente com o traceroute
	tam = strlen(b);
	b[tam-1] = ' ';
	aux2 = strtok_r(b," ", &aux1);	/*Desconsidera o traceroute*/
	/*Capturando o end. IP de destino*/
	if ((aux2 = strtok_r(NULL, " ", &aux1)) != NULL)
	{
		if (!is_ip ((CHAR_T *)aux2))
		{
			printf("Incorret Target IP Address.");
			return 0;
		}
		
		end_ip = to_ip_byte((CHAR_T *)aux2);
		
		traceroute_ip = *end_ip;		//Armazena o endereço IP do Trace
		
		char resolve_arp[100];
		trace_running = 1;
		int ident = 0;
		int i = 0;
		WORD next_ip;
		
		printf("traceroute to %s, 16 hops max, 39 bytes packets\n", format_address(*end_ip));
		
		while (i < 16 && trace_running)
		{
			sem_wait(&allow_route_entry);
			entry = FindProxNo(routeTable, (WORD)*end_ip);
		
			printf("%d ", ident);
			
			if(entry)
			{
				if(*entry->GATEWAY == *entry->TARGET)
				{
					sprintf(resolve_arp, "arp res %s\n", format_address (*end_ip));
					next_ip = (WORD)*end_ip;
				}
				else
				{
					sprintf(resolve_arp, "arp res %s\n", format_address (*entry->GATEWAY));
					next_ip = *entry->GATEWAY;
				}
				if(sub_arp_res (resolve_arp, 0))
				{
					gettimeofday( &start_time, NULL ); 
					
					send_icmp_pkt (0, ECHO_REQUEST, entry->interface, next_ip, *end_ip, ifaces[entry->interface].ip, ident, ident,0);
					//send_icmp_pkt (0, ECHO_REQUEST, entry->interface, next_ip, *end_ip, ifaces[entry->interface].ip, ident, ident,0);
					//send_icmp_pkt (0, ECHO_REQUEST, entry->interface, next_ip, *end_ip, ifaces[entry->interface].ip, ident, ident,0);	
					
					sem_post(&allow_route_entry);
					
					ident++;
					qtd_pkg_du = 0;
					
					struct timespec ts;
			
					ts.tv_sec = time(NULL) + TIMEOUT*2;
					ts.tv_nsec = 0;
					int rv;
					
					while ((rv = sem_timedwait(&sem_trace, &ts) ) == -1 && errno == EINTR)
		               continue;
					
					if (rv == -1 && errno == ETIMEDOUT) 
					{
						//the semaphore returned
						if(trace_running)
			 				printf ("*\n");
					}
				}
				else
				{
					ident++;
					printf ("*\n");
					sem_post(&allow_route_entry);
				}
			}
			else
			{
				ident++;
				printf ("*\n");			
				sem_post(&allow_route_entry);
			}
			
			i++;
			sleep (1);
		}		
		trace_running = 0;
		traceroute_ip = 0;		
		return 1;
	}
	else
		printf("Usage: traceroute [Target]");
	return 0;
}

/* */
int sub_ping( void *arg )
{
	if (!arg)
		return 0;
	int tam;
	
	char *aux1 = NULL;
	char *aux2 = NULL;
	DWORD *end_ip;
	RouteTableEntry *entry;
	
	char *b = (char *)arg;
	
	//Capturando os parâmetros passados juntamente com o ping
	tam = strlen(b);
	b[tam-1] = ' ';
	aux2 = strtok_r(b," ", &aux1);	/*Desconsidera o ping*/
	/*Capturando o end. IP de destino*/
	if ((aux2 = strtok_r(NULL, " ", &aux1)) != NULL)
	{
		if (!is_ip ((CHAR_T *)aux2))
		{
			printf("Incorret Target IP Address.");
			return 0;
		}
		
		end_ip = to_ip_byte((CHAR_T *)aux2);
		
		char resolve_arp[100];
		ping_running = 1;
		int ident = 0;

		WORD next_ip;
		
		while (ping_running)
		{
			sem_wait(&allow_route_entry);
			entry = FindProxNo(routeTable, (WORD)*end_ip);
			
			if(entry)
			{
				if(*entry->GATEWAY == *entry->TARGET)
				{
					sprintf(resolve_arp, "arp res %s\n", format_address (*end_ip));
					next_ip = (WORD)*end_ip;
				}
				else
				{
					sprintf(resolve_arp, "arp res %s\n", format_address (*entry->GATEWAY));
					next_ip = *entry->GATEWAY;
				}
				if(sub_arp_res (resolve_arp, 0))
				{
					gettimeofday( &start_time, NULL ); 
					send_icmp_pkt (0, ECHO_REQUEST, entry->interface, next_ip, *end_ip, ifaces[entry->interface].ip, 64, ident, 0);
					
					sem_post(&allow_route_entry);
					
					ident++;
					
					struct timespec ts;
					
					ts.tv_sec = time(NULL) + TIMEOUT*2;
					ts.tv_nsec = 0;
					int rv;
					
					while ((rv = sem_timedwait(&sem_ping, &ts) ) == -1 && errno == EINTR)
		               continue;
					
					if (rv == -1 && errno == ETIMEDOUT) 
					{
						//the semaphore returned
						if(ping_running)
			 				printf ("Host is unreachable1\n");
					}
				}
				else
				{
					printf ("Host is unreachable2\n");				
					sem_post(&allow_route_entry);
				}
			}
			else
			{
				printf ("Host is unreachabl3\n");
				sem_post(&allow_route_entry);
			}
			
			sleep (1);
		}		
		ping_running = 0;		
		return 1;
	}
	else
		printf("Usage: ping [Target]");
	return 0;
}

void * rip_control (void *p)
{
	int i, j;
	while(1)
	{
		if (!rip_running)
			continue;
		
		//Criar um pacote com a tabela RIP para ser enviada por broadcast através da rede
		sem_wait(&allow_route_entry);
		
		RouteTableEntry *entry = routeTable->list;
		
		BYTE udp_data[512];
		
		RIP_PKT *rip_pkt;
		
		i=0;
		
		//printf("\nRede: %d\n",(int)*entry->TARGET);
		while (entry)
		{
			rip_pkt = malloc(sizeof(RIP_PKT));
			rip_pkt->IP = (WORD)*entry->TARGET;
			rip_pkt->metric = entry->COST;	
			memcpy(&udp_data[i], (BYTE *)rip_pkt , sizeof(RIP_PKT));
			i += sizeof(RIP_PKT);
			
			entry = entry->next;
		}
		//printf("\nRede: %d\n",(int )(rip_pkt->IP));
		sem_post(&allow_route_entry);
		
		for (j = 0; j < nifaces; j++)
			send_udp_pkt(RIP_PORT, udp_data, i, j);
		
		sleep(30);
		//Bloquear esta thread por 30 segundos
	}
}

int sub_rip_start( void *arg )
{
	rip_running = 1;
	return 0;
}

int sub_rip_stop( void *arg )
{
	rip_running = 0;
	return 0;
}

void send_udp_pkt(int porta, BYTE *data, int tam, int interface)
{
	ETHERNET_HEADER * eth;
	UDP_HEADER * udp;
	IP_HEADER *ip_pkt;
	
	eth =  malloc(sizeof(ETHERNET_HEADER) + sizeof(IP_HEADER) + sizeof (UDP_HEADER) + tam);
	
	/*construção do pacote ETHERNET*/
	eth->net = ifaces[interface].net;
	
	memcpy(&eth->sender[0], ifaces[interface].mac, MAC_ADDR_LEN);
		
	memcpy(&eth->receiver[0], broad_eth , MAC_ADDR_LEN);		
	
	eth->type = htons(IP);
	
	/*construção do pacote IP*/
	ip_pkt = (IP_HEADER *)(eth + 1);
	ip_pkt->version = 0x45;
	ip_pkt->type_service = 5;
	ip_pkt->total_length = htons(tam + sizeof(UDP_HEADER) + sizeof (IP_HEADER));

	ip_pkt->identification = htons(0);
	ip_pkt->fragment = htons(0);
	ip_pkt->time_alive = 1;
	ip_pkt->protocol = UDP;
	ip_pkt->source_address = ifaces[interface].ip; // ip da interface de saída
	ip_pkt->destination_address = 0; //ip do host a receber o echo
	ip_pkt->checksum = 0;
	ip_pkt->checksum = htons(calc_check_sum(ip_pkt, IP));
	
	/*construção do pacote UDP*/
	udp = (UDP_HEADER *)(ip_pkt + 1);
	udp->src_port = htons(porta);
	udp->dest_port = htons(porta);
	udp->checksum = htons(0);
	udp->fisrt_data = *data;
	udp->length = htons(sizeof (UDP_HEADER) + tam);
	
	send_pkt(sizeof(ETHERNET_HEADER) + sizeof(IP_HEADER) + sizeof (UDP_HEADER) + tam, interface, broad_eth, IP, (BYTE*)eth);	
}

void send_icmp_pkt ( BYTE _icmp_code, BYTE _icmp_type, BYTE interface, WORD gateway, WORD destination, WORD source, BYTE hopnum, WORD id_pkg, WORD prox_no)
{
	ICMP_HEADER *icmp_pkt;
	ICMP_DATA *icmp_data;
	ETHERNET_HEADER * eth;
	ArpTableEntry * _entry;
	
	eth =  malloc(sizeof(ETHERNET_HEADER) + sizeof(IP_HEADER) + sizeof (ICMP_HEADER) + sizeof (ICMP_DATA));
	
	eth->net = ifaces[interface].net;
	
	memcpy(&eth->sender[0], ifaces[interface].mac, MAC_ADDR_LEN);
	
	_entry = BuildArpTableEntry((CHAR_T *)format_address (gateway), NULL, 0);
	
	_entry = FindArpTableEntry (arpTable, _entry, 1);
		
	if (!_entry)
		return;
		
	memcpy(&eth->receiver[0], (_entry->MAC) , MAC_ADDR_LEN);		
	
	eth->type = htons(IP);
	
	/*construção do pacote ICMP*/	
	IP_HEADER * ip_pkt = (IP_HEADER *)(eth + 1);
	icmp_pkt = (ICMP_HEADER *)(ip_pkt + 1);	
	icmp_pkt->type = _icmp_type;
	icmp_pkt->code = _icmp_code;
	icmp_pkt->checksum = 0;
	icmp_pkt->checksum = htons(calc_check_sum(icmp_pkt, ICMP));
	
	icmp_data = (ICMP_DATA*)(icmp_pkt + 1);
	icmp_data->prox_no = 0;
	
	if (_icmp_type == REDIRECT)		
		icmp_data->prox_no = prox_no;
		
	/*construção do pacote IP*/
	ip_pkt->version = 0x45;
	ip_pkt->type_service = 5;
	ip_pkt->total_length = htons(sizeof(ICMP_DATA) + sizeof(ICMP_HEADER) + sizeof (IP_HEADER));

	ip_pkt->identification = htons(id_pkg);
	ip_pkt->fragment = htons(0);
	ip_pkt->time_alive = hopnum;
	ip_pkt->protocol = ICMP;
	ip_pkt->source_address = source; // ip da interface de saída
	ip_pkt->destination_address = destination; //ip do host a receber o echo
	ip_pkt->checksum = 0;
	ip_pkt->checksum = htons(calc_check_sum(ip_pkt, IP));
	
	send_pkt(sizeof(ETHERNET_HEADER) + sizeof(IP_HEADER) + sizeof (ICMP_HEADER) + sizeof (ICMP_DATA), interface, (BYTE *)_entry->MAC, IP, (BYTE*)eth);
}

SWORD calc_check_sum(void *pkg, int tipo)
{	
	int tam;
	unsigned short *aux = (unsigned short *) pkg;
	register unsigned long sum = 0;
	
	sum = sum & 0x00000000;  
	
	if (tipo == IP)
		tam = sizeof(IP_HEADER);
	else if (tipo == ICMP)
		tam = sizeof(ICMP_HEADER);
	
	tam = tam/2; 	//pois tam guarda a quantidade em bytes e nós queremos a quantidade de palavras de 16 bits, logo 2 bytes 
	
	while(tam--)
	{
		sum += *aux;
		aux++;
		if (sum & 0xFFFF0000)	//se vai um
		{
			sum &= 0xFFFF;
			sum++;
		}
	}	
	return (SWORD) ~(sum & 0xFFFF);;
}

int main(int argc, char *argv[])
{
	pthread_t tid;
	char buf[MAX_PARAMETERS];
	int i;
	char add_arp[100], aux_mac[100];
	
	/* Construcao das tabelas ARP e ROUTE */	
	arpTable   = BuildArpTable();
	routeTable = BuildRouteTable();

	//Ajustando as opções padrões do XNOOP	
	_xnoop.npkgs = 0;
	run_xnoop = 0;
	sending_packets = 0;
	qtd_pkgs = 0;
	
	signal (SIGINT, control_xnoop);
	
	for (i=0; i<MAX_PARAMETERS; i++)
		parameters[i] = malloc (MAX_SIZE_PARAMETER);
	
	if (argc < 3)
		error_exit("\nUsage: subnet <port> <cfg_file> [cfg_files ...]\n");
	my_port = htons(atoi(argv[1]));
	nifaces = 0;
	for (i = 2; i < argc; i++) {
		if (read_net_cfg(argv[i], my_port, nifaces))
			nifaces++;
	}
	
	queue_head = NULL;
	/* Initialize semaphore */
	sem_init(&sem_data_ready, 0, 0);
	sem_init(&sem_queue, 0, 1);
	sem_init(&sem_xnoop, 0, 1);
	sem_init(&allow_entry, 0, 1);
	sem_init(&allow_route_entry, 0, 1);
	sem_init(&sem_main, 0, 0);
	sem_init(&sem_arp_res, 0, 0);
	sem_init(&sem_ping, 0, 0);
	sem_init(&sem_trace, 0, 0);
	
	/* Create sender and receiver threads */
	printf("Listening on port: %d\n", ntohs(my_port));
	pthread_create(&tid, NULL, subnet_rcv, (void *)&my_port);
	pthread_create(&tid, NULL, subnet_send, (void *)NULL);
	
	pthread_create(&tid, NULL, (void *)rip_control, NULL);
	
	//pthread_create(&tid, NULL,(void *) RemoveArpTableEntry, (void *)NULL);
	//pthread_create(&tid, NULL, (void *)AddArpTableEntry, (void *)NULL);
	pthread_create(&tid, NULL, (void *)sub_arp_add, NULL);
	pthread_create(&tid, NULL, (void *)update_arp_table, NULL);
	pthread_create(&tid, NULL, (void *)update_route_table, NULL);
	
	//Realiza um arp add para cada uma das interfaces para popular a tabela arp inicialmente
	for (i = 0; i < nifaces; i++) {
		sprintf(aux_mac, "%s",(char *)format_mac_address((DWORD)(*(DWORD *)ifaces[i].mac)));
		sprintf(add_arp, "arp add %s %s %d\n", format_address(ifaces[i].ip), aux_mac, -1);
		sub_arp_add ((void *)add_arp);
	}
	
	while (1) 
	{
		printf("\ncmd> ");
		fgets(buf, MAX_PARAMETERS, stdin);
	
		if (!strncasecmp(buf, "XNOOP", 5)) 
			sub_xnoop(buf);			
		else if (!strncasecmp(buf, "ARP SHOW", 8)) 			
			DisplayArpTable(arpTable);
		else if (!strncasecmp(buf, "ARP ADD", 7)) 
			sub_arp_add((void *)buf);
		else if (!strncasecmp(buf, "ARP RES", 7)) 
			sub_arp_res((void *)buf, 1);
		else if (!strncasecmp(buf, "ARP DEL", 7))
			sub_arp_del((void *)buf);
		else if (!strncasecmp(buf, "ARP", 3)) {
			sub_arp((char *)buf);
		}
		else if (!strncasecmp(buf, "IFCONFIG SHOW", 13)) {
			printf ("\nInterface  IP Address\t    Netmask\t     Broadcast\t      MAC Address\t  MTU\t  UP\n");
			for (i=0; i<nifaces;i++)
				print_if_info(i);
		}
		else if (!strncasecmp(buf, "IFCONFIG", 8))
			sub_ifconfig(buf);
		else if (!strncasecmp(buf, "IF", 2))
			sub_if(buf);
		else if (!strncasecmp(buf, "EXIT", 4))
			exit(0);
		else if (!strncasecmp(buf, "SEND", 4))
			sub_send_trace(buf);
		else if (!strncasecmp(buf, "RIP START", 9))
			sub_rip_start(buf);
		else if (!strncasecmp(buf, "RIP STOP", 8))
			sub_rip_stop(buf);
		else if (!strncasecmp(buf, "ROUTE SHOW", 10))
			DisplayRouteTable(routeTable);
		else if (!strncasecmp(buf, "ROUTE ADD", 9))
			sub_route_add(buf);
		else if (!strncasecmp(buf, "ROUTE DEL", 9))
			sub_route_del(buf);
		else if (!strncasecmp(buf, "ROUTE", 5))
		{
			printf("Usage:  route add [Target] [Netmask] [Gateway]");
			printf("\n\troute del [Target] [Netmask] [Gateway]");
			printf("\n\troute show");
		}
		else if (!strncasecmp(buf, "PING", 4))
			sub_ping(buf);
		else if (!strncasecmp(buf, "TRACEROUTE", 10))
			sub_traceroute(buf);
		else if (!strncasecmp(buf,"\n",1))
		{}
		else
			printf("Invalid command");
	}
	//#######
	FlushArpTable(arpTable);
	free(arpTable);
	
	FlushRouteTable(routeTable);
	free(routeTable);
	//#######
	
	return 0;
}
