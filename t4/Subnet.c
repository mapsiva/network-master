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

ArpTable *arpTable;

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
	
	eth->net = ifaces[0].net;
	memcpy(&eth->sender[0], ifaces[0].mac, MAC_ADDR_LEN);
	memcpy(&eth->receiver[0], _dmac, MAC_ADDR_LEN);
	eth->type = htons(ARP);
	
	arp = ( ARP_HEADER * )(eth + 1);
	
	arp->protocol_type = htons(IP);
	arp->hardware_len = MAC_ADDR_LEN;
	arp->protocol_len = IP_ADDR_LEN;
	arp->operation = htons(type_op);
	memcpy(&arp->sender_hardware_addr[0], ifaces[0].mac, MAC_ADDR_LEN);
	arp->sender_ip_addr = ifaces[0].ip;
	memcpy(&arp->target_hardware_addr[0], _dmac, MAC_ADDR_LEN);
	arp->target_ip_addr = _dip;
	
	send_pkt(sizeof(ETHERNET_HEADER) + sizeof(ARP_HEADER), 0, &arp->target_hardware_addr[0], ARP, (BYTE*)eth);	
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
						
				if (aux < 0)
					printf("Error sending pkt: %s\n", strerror(errno));
			}
			ifaces[pkt->pkt->iface].pkt_tx++;
			free(pkt->pkt);
			free(pkt);
		}
    }
}

/* Converte um endereço MAC no formato de string em um numero hexadecimal que representa o end. MAC
 * @param s End. MAC no formato de string
 * @param addr End. MAC no formato hexadecimal convertido
 * 
 * @since           2.0
 */
void str2eth(char *s, BYTE addr[])
{
    int i;
    char *p;
    
    p = strtok(s, ":");
    for (i = 0; i < 5; i++) {
		addr[i] = strtol(p, NULL, 16);
		p = strtok(NULL, ":");
    }
    addr[i] = strtol(p, NULL, 16);
}

/* Converte um endereço IP no formato decimal em um End. IP no formato de string
 * @param buf End. IP no formato de string convertido
 * @param addr End. IP no formato decimal
 * 
 * @since           2.0
 */
char *ip2str(char *buf, unsigned ip)
{
    BYTE *pb = (BYTE*)&ip;
    sprintf(buf, "%d.%d.%d.%d", pb[0], pb[1], pb[2], pb[3]);
    return buf;
}

/* Lê dados de um arquivo (CFG) que representa a configuração da rede virtual
 * @param fname Nome do arquivo (CFG) de entrada
 * @param port
 * @param iface 
 * 
 * @since           2.0
 */
void read_net_cfg(char *fname, u_short port, u_short iface)
{
    FILE *cfg_file;
    char line[100];
    NET_HOSTS *p; 
    int first;
    
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
				s = strtok(line, ",");
				p->port = ntohs(atoi(s));
				s = strtok(NULL, ",");
				p->ip   = inet_addr(s);
				if (p->port == port) {
					my_ip  = p->ip;
					ifaces[iface].ip = p->ip;
					s = strtok(NULL, ",");
					ifaces[iface].mtu = atoi(s);
					s = strtok(NULL, ",");
					str2eth(s, ifaces[iface].mac);
				}
				ifaces[iface].nhosts++;
				p++;
			}
		}
    }
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
				printf("Incorrect address ip.");
				return 0;
			}
			
			/*Capturando a MASK da interface*/
			if ((aux2 = strtok_r(NULL, " ", &aux1)) != NULL)	
			{
				end_mask = to_ip_byte((CHAR_T *)aux2);
				
				if (!end_mask)
				{
					printf("Incorrect address mask network.");
					return 0;
				}				
				ifaces[i].mask = (unsigned) (*end_mask);				
			}
			ifaces[i].ip = (unsigned) (*end_ip);
			
			print_if_info(i);	//Exibir informacoes de apenas uma interface
		}
		else
			printf("Usage:  ifconfig <interface> <IPaddres> <MASKaddress>");
	}
	else
	{
		printf("Usage:  ifconfig <interface> <IPaddres> <MASKaddress>");
		printf("\n\tifconfig [show]");
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
				printf("Sintaxe Correct is: if <interface> [down|up]");
				return 0;
			}
			
			print_if_info(i);
		}
		else
			printf("Usage:  if <interface> [down|up]");	
	}
	else
		printf("Usage:  if <interface> [down|up]");
	
	return 1;
}

/* Imprime informações da interface id_iface
 * @param id_iface Representa o id da interface
 * 
 * @since           2.0
 */
void print_if_info(int id_iface)
{
    char ip_s[16], bcast_s[16], mask_s[16];    
    
	BYTE *pb;
	printf("\nif%d\tHWaddr %02X:%02X:%02X:%02X:%02X:%02X\n",
		   id_iface, ifaces[id_iface].mac[0], ifaces[id_iface].mac[1], ifaces[id_iface].mac[2],
		   ifaces[id_iface].mac[3], ifaces[id_iface].mac[4], ifaces[id_iface].mac[5]);
	pb = (BYTE *)&ifaces[id_iface].ip;
	printf("\tinet addr: %s Bcast: %s Mask: %s\n",
		   ip2str(ip_s, ifaces[id_iface].ip),
		   ip2str(bcast_s, ifaces[id_iface].ip_bcast),
		   ip2str(mask_s, ifaces[id_iface].mask));
	printf("\t%s MTU: %d\n", ifaces[id_iface].up ? "UP" : "DOWN",
		   ifaces[id_iface].mtu);
	printf("\tRX packets: %d TX packet: %d\n",
		   ifaces[id_iface].pkt_rx, ifaces[id_iface].pkt_tx);
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
    ETHERNET_PKT *ppkt;
    
    sockd = passive_UDP_socket(port);
    ppkt = (ETHERNET_PKT*)&in_buf[0];
    
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
			if (!memcmp(eth_h->receiver, broad_eth,6) || !memcmp(eth_h->receiver, ifaces[0].mac, 6))
			{
				ifaces[riface].pkt_rx++; /* The packet must be processed */
				if (ntohs(eth_h->type) == ARP)
				{
					arp_h = (ARP_HEADER *) (eth_h + 1);
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
							printf("(%s, %s, %d)\n", (char*)_ip, (char*)_mac, ARP_TTL_DEF);
							sem_post(&sem_arp_res);
							
						}						
					}
					else if (ntohs(arp_h->operation) == ARP_REQUEST)
					{
						if (arp_h->target_ip_addr == ifaces[0].ip)
							send_arp_pkt((DWORD*)&arp_h->sender_hardware_addr[0], arp_h->sender_ip_addr, ARP_REPLY);
					}
				}
			}				
			
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
		    //printf("\r.");
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
		printf("Sintaxe Correct is: arp [show|ttl|res|add|del] [EndIP] [EndEth] [ttl]");
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
			printf("Sintaxe Correct is: arp [show|ttl|res|add|del] [EndIP] [EndEth] [ttl]");
		}
		else				
		printf("Sintaxe Correct is: arp [show|ttl|res|add|del] [EndIP] [EndEth] [ttl]");
	}
	else				
		printf("Sintaxe Correct is: arp [show|ttl|res|add|del] [EndIP] [EndEth] [ttl]");
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
			printf("Incorret ttl. Just ttl more than -1.");
			return 0;
		}
		
		ARP_TTL_DEF = ttl;
		
		printf ("ttl updated.");
	}
	else				
		printf("Sintaxe Correct is: arp [show|ttl|res|add|del] [EndIP] [EndEth] [ttl]");
	
	return 0;
}

/* */
int sub_arp_res( void *arg )
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
			printf ("\n(%s, %s, %d)\n", aux2, (char*)_mac, entry->TTL);
			sem_post(&allow_entry);
		}			
		else
		{
			sem_post(&allow_entry);
			
			send_arp_pkt((DWORD *)&broad_eth[0], *(end_ip), ARP_REQUEST);
			
			//Falta eperar pelo REPLY e bloquear esta thread
			struct timespec ts;
			
			ts.tv_sec = time(NULL) + TIMEOUT;
			ts.tv_nsec = 0;
			
			arp_resolving = 1;
			
			while ((rv = sem_timedwait(&sem_arp_res, &ts) ) == -1 && errno == EINTR)
               continue;

			arp_resolving = 0;
			
			if (rv == -1 && errno == ETIMEDOUT) //the semaphore returned
	 			printf("Ip address not found!\n");
		}
		
	}
	else				
		printf("Sintaxe Correct is: arp [show|ttl|res|add|del] [EndIP] [EndEth] [ttl]");
	return 1;
}

/* */
void control_xnoop()
{
	if (run_xnoop || sending_packets)
	{
		if (run_xnoop)
			run_xnoop = 0;
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

void * update_table(void *p)
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
/* */
int sub_route_show( void *arg )
{
		
	return 0;
}

/* */
int sub_route_add( void *arg )
{
	if (!arg)
		return 0;
	int tam;
	
	char *aux1 = NULL;
	char *aux2 = NULL;
	DWORD *end_ip;
	DWORD *mask;
	DWORD *gateway;
	
	char *b = (char *)arg;
	
	//Capturando os parâmetros passados juntamente com o route add
	tam = strlen(b);
	b[tam-1] = ' ';
	aux2 = strtok_r(b," ", &aux1);	/*Desconsidera o route*/
	aux2 = strtok_r(NULL," ", &aux1);	/*Desconsidera o add*/
	/*Capturando o end. IP de destino*/
	if ((aux2 = strtok_r(NULL, " ", &aux1)) != NULL)
	{
		if (!is_ip ((CHAR_T *)aux2))
		{
			printf("Incorret Target IP Address.");
			return 0;
		}
		
		end_ip = to_ip_byte((CHAR_T *)aux2);
		
		/*Capturando a mascara de subrede*/
		if ((aux2 = strtok_r(NULL, " ", &aux1)) != NULL)
		{
			if (!is_ip ((CHAR_T *)aux2))
			{
				printf("Incorret MASK Address.");
				return 0;
			}
			
			mask = to_ip_byte((CHAR_T *)aux2);
			
			/*Capturando o end. IP do Gateway*/
			if ((aux2 = strtok_r(NULL, " ", &aux1)) != NULL)
			{
				if (!is_ip ((CHAR_T *)aux2))
				{
					printf("Incorret Gateway IP Address.");
					return 0;
				}
				
				gateway = to_ip_byte((CHAR_T *)aux2);
				
				//TODO falta chamar a função responsável por adicionar uma entrada na tabela de roteamento
				
				return 1;
			}
			else				
				printf("Sintaxe Correct is: route add [Target] [Netmask] [Gateway]");
		}
		else				
			printf("Sintaxe Correct is: route add [Target] [Netmask] [Gateway]");
	}
	else				
		printf("Sintaxe Correct is: route add [Target] [Netmask] [Gateway]");
	
	return 0;
}

/* */
int sub_route_del( void *arg )
{
	if (!arg)
		return 0;
	int tam;
	
	char *aux1 = NULL;
	char *aux2 = NULL;
	DWORD *end_ip;
	DWORD *mask;
	DWORD *gateway;
	
	char *b = (char *)arg;
	
	//Capturando os parâmetros passados juntamente com o route del
	tam = strlen(b);
	b[tam-1] = ' ';
	aux2 = strtok_r(b," ", &aux1);	/*Desconsidera o route*/
	aux2 = strtok_r(NULL," ", &aux1);	/*Desconsidera o del*/
	/*Capturando o end. IP de destino*/
	if ((aux2 = strtok_r(NULL, " ", &aux1)) != NULL)
	{
		if (!is_ip ((CHAR_T *)aux2))
		{
			printf("Incorret Target IP Address.");
			return 0;
		}
		
		end_ip = to_ip_byte((CHAR_T *)aux2);
		
		/*Capturando a mascara de subrede*/
		if ((aux2 = strtok_r(NULL, " ", &aux1)) != NULL)
		{
			if (!is_ip ((CHAR_T *)aux2))
			{
				printf("Incorret MASK Address.");
				return 0;
			}
			
			mask = to_ip_byte((CHAR_T *)aux2);
			
			/*Capturando o end. IP do Gateway*/
			if ((aux2 = strtok_r(NULL, " ", &aux1)) != NULL)
			{
				if (!is_ip ((CHAR_T *)aux2))
				{
					printf("Incorret Gateway IP Address.");
					return 0;
				}
				
				gateway = to_ip_byte((CHAR_T *)aux2);
				
				//TODO falta chamar a função responsável por remover uma entrada na tabela de roteamento
				
				return 1;
			}
			else				
				printf("Sintaxe Correct is: route del [Target] [Netmask] [Gateway]");
		}
		else				
			printf("Sintaxe Correct is: route del [Target] [Netmask] [Gateway]");
	}
	else				
		printf("Sintaxe Correct is: route del [Target] [Netmask] [Gateway]");
	
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
		
		//TODO falta chamar a função responsável pelo traceroute
		
		return 1;
	}
	else
		printf("Sintaxe Correct is: traceroute [Target]");
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
		
		//TODO falta chamar a função responsável pelo ping
		
		return 1;
	}
	else
		printf("Sintaxe Correct is: ping [Target]");
	return 0;
}

/* */
int main(int argc, char *argv[])
{
	pthread_t tid;
	char buf[MAX_PARAMETERS];
	int i;
	
	/* Construcao da tebala ARP */
	
	arpTable = BuildArpTable();

	//Ajustando as opções padrões do XNOOP	
	_xnoop.npkgs = 0;
	run_xnoop = 0;
	sending_packets = 0;	
	qtd_pkgs = 0;
	
	signal (SIGINT, control_xnoop);
	
	for (i=0; i<MAX_PARAMETERS; i++)
		parameters[i] = malloc (MAX_SIZE_PARAMETER);
	
	if (argc < 3)
	error_exit("\nUsage: subnet port cfg_file [cfg_files ...]\n");
	my_port = htons(atoi(argv[1]));
	nifaces = 0;
	for (i = 2; i < argc; i++) {
		read_net_cfg(argv[i], my_port, nifaces);
		nifaces++;
	}
	queue_head = NULL;
	/* Initialize semaphore */
	sem_init(&sem_data_ready, 0, 0);
	sem_init(&sem_queue, 0, 1);
	sem_init(&sem_xnoop, 0, 1);
	sem_init (&allow_entry, 0, 1);
	sem_init(&sem_main, 0, 0);
	sem_init(&sem_arp_res, 0, 0);
	
	/* Create sender and receiver threads */
	printf("Listening on port: %d\n", ntohs(my_port));
	pthread_create(&tid, NULL, subnet_rcv, (void *)&my_port);
	pthread_create(&tid, NULL, subnet_send, (void *)NULL);
	
	//pthread_create(&tid, NULL,(void *) RemoveArpTableEntry, (void *)NULL);
	//pthread_create(&tid, NULL, (void *)AddArpTableEntry, (void *)NULL);
	pthread_create(&tid, NULL, (void *)sub_arp_add, NULL);
	pthread_create(&tid, NULL, (void *)update_table, NULL);
	
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
			sub_arp_res((void *)buf);
		else if (!strncasecmp(buf, "ARP DEL", 7))
			sub_arp_del((void *)buf);
		else if (!strncasecmp(buf, "ARP", 3)) {
			sub_arp((char *)buf);
		}
		else if (!strncasecmp(buf, "IFCONFIG SHOW", 13)) {
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
		else if (!strncasecmp(buf, "ROUTE SHOW", 10))
			sub_route_show(buf);
		else if (!strncasecmp(buf, "ROUTE ADD", 9))
			sub_route_add(buf);
		else if (!strncasecmp(buf, "ROUTE DEL", 9))
			sub_route_add(buf);
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
	//#######
	
	return 0;
}