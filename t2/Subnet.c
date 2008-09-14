/**
	Universidade Federal de Mato Grosso do Sul
	Mestrado em Ciência da Computação DCT - UFMS
	Redes de Computadores 2008
	
	Márcio Aparecido Inacio da Silva
	Maxwell Sampaio dos Santos
	
	Xnoop - Analizador de Pacotes [Trabalho 1]
*/



#include "Subnet.h"
#include "Xnoop.h"
#include "Analyzer.h"

#include "Ethernet.h"
#include "Arp.h"
/* */

/* Open a passive UDP socket. port must be in net-byte order. */
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


/* */
int sub_xnoop(char *param[], char *b)
{
	unsigned int i = 0;
	unsigned int tam;
	
	char *aux1;
	char *aux2;
	
	//Capturando os [options] e [filters] do analisador de pacotes (XNOOP)
	tam = strlen(b);
	b[tam-1] = ' ';
	aux2 = strtok_r(b," ", &aux1);
	param[i++] = aux2;
	while ((aux2 = strtok_r(NULL, " ", &aux1)) != NULL)
		param[i++] = aux2;

	//Ajustando as opções padrões do XNOOP    
    _xnoop.modo = BASIC;
	_xnoop.translation = 1;
	_xnoop.npkgs_max = 400000000;
	_xnoop.position = 1;
	
	//Verifica se os [options] e [filters] estão corretos
	if (check_parameters(i, param, &_xnoop))
	{
		//Habilita a execução do XNOOP 
		run_xnoop = 1;
		
		printf("Runing xnoop");	
	}		
	
	return i;
}

/* */
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
/* */
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
/* */
char *ip2str(char *buf, unsigned ip)
{
    BYTE *pb = (BYTE*)&ip;
    sprintf(buf, "%d.%d.%d.%d", pb[0], pb[1], pb[2], pb[3]);
    return buf;
}
/* */
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

/* */
int sub_ifconfig(char *b)
{
	unsigned int id_iface = -1;
	unsigned int tam;
	
	DWORD* end_ip = 0;
	DWORD* end_mask = 0;
	
	char *aux1;
	char *aux2;
	
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
			if (nifaces > 0)
				printf(" Interfaces between 0 and %d", (nifaces-1));
			return 0;			
		}
		
		id_iface = strtoul((const char *)aux2, NULL, 10);
		
		if (id_iface < 0 || id_iface >= nifaces)
		{
			printf("Incorrect interface.");
			if (nifaces > 0)
				printf(" Interfaces between 0 and %d", (nifaces-1));
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
				ifaces[id_iface].mask = (unsigned) (*end_mask);				
			}
			ifaces[id_iface].ip = (unsigned) (*end_ip);
		}
		print_if_info(id_iface);	//Exibir informacoes de apenas uma interface
	}
		
	return 1;
}

int sub_if( char* b)
{
	unsigned int id_iface = -1;
	unsigned int tam;
	
	char *aux1;
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
			if (nifaces > 0)
				printf(" Interfaces between 0 and %d", (nifaces-1));
			return 0;			
		}
		
		id_iface = strtoul((const char *)aux2, NULL, 10);
		
		if (id_iface < 0 || id_iface >= nifaces)
		{
			printf("Incorret Interface.");
			if (nifaces > 0)
				printf(" Interfaces between 0 and %d", (nifaces-1));
			return 0;
		}
		
		/*Capturando a opção escolhida para a interface (down ou up)*/
		if ((aux2 = strtok_r(NULL, " ", &aux1)) != NULL)	
		{
			if (!strncasecmp(aux2, "DOWN", 4) || !strncasecmp(aux2, "UP", 2))
			{
				if (!strncmp(aux2, "down", 4))
					ifaces[id_iface].up = 0;
				else
					ifaces[id_iface].up = 1;
			}
			else
			{
				printf("asdasdInvalid Comand. Sintaxe Correct is: if <interface> down|up");
				return 0;
			}
		}
	}
	else
		printf("Invalid Comand. Sintaxe Correct is: if <interface> down|up");
	
	return 0;
}

/* */
int print_if_info(int id_iface)
{
    int i;
    char ip_s[16], bcast_s[16], mask_s[16];
    
    if (id_iface != -1)
    {
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
		return 0;
	}
	
	for (i = 0; i < nifaces; i++) {
		BYTE *pb;
		printf("\nif%d\tHWaddr %02X:%02X:%02X:%02X:%02X:%02X\n",
			   i, ifaces[i].mac[0], ifaces[i].mac[1], ifaces[i].mac[2],
			   ifaces[i].mac[3], ifaces[i].mac[4], ifaces[i].mac[5]);
		pb = (BYTE *)&ifaces[i].ip;
		printf("\tinet addr: %s Bcast: %s Mask: %s\n",
			   ip2str(ip_s, ifaces[i].ip),
			   ip2str(bcast_s, ifaces[i].ip_bcast),
			   ip2str(mask_s, ifaces[i].mask));
		printf("\t%s MTU: %d\n", ifaces[i].up ? "UP" : "DOWN",
			   ifaces[i].mtu);
		printf("\tRX packets: %d TX packet: %d\n",
			   ifaces[i].pkt_rx, ifaces[i].pkt_tx);
	}
	return 0;
}

int sub_arp ( WORD ip_addres)
{   
    ARP_HEADER * arp;
    ETHERNET_HEADER * eth;
    
    eth =  malloc(sizeof(ETHERNET_HEADER) + sizeof(ARP_HEADER));
    
    arp = ( ARP_HEADER * )(eth + 1);

	/* Ajustando dados do ETHERNET_HEADER */
    eth->net = ifaces[0].net;
    memcpy(&eth->sender[0], ifaces[0].mac, MAC_ADDR_LEN);
    memcpy(&eth->receiver[0], &broad_eth[0], MAC_ADDR_LEN);    
    eth->type = htons(ARP);
   	
   	/* Ajustando dados do ARP_HEADER */
    arp->hardware_type = htons(15);
    arp->protocol_type = 0;				/*colocamos 0 (zero) pois este não é um pacote IP dentro do ARP*/
    arp->hardware_len = MAC_ADDR_LEN;
    arp->protocol_len = IP_ADDR_LEN;
    arp->operation = htons(ARP_REQUEST);
    memcpy(&arp->sender_hardware_addr[0], ifaces[0].mac, MAC_ADDR_LEN);
    arp->sender_ip_addr = ifaces[0].ip;    
    memcpy(&arp->target_hardware_addr[0], &broad_eth[0], MAC_ADDR_LEN);

    /*IP da maquina que se deseja descobrir o MAC*/
    arp->target_ip_addr = ip_addres;
    
    /*Enviando pacote*/
    send_pkt(sizeof(ETHERNET_HEADER) + sizeof(ARP_HEADER), 0, &broad_eth[0], ARP, (BYTE*)eth);
    
    return 1;
}
/* */
void *subnet_rcv(void *ptr)
{
    unsigned port = *((unsigned *)ptr);
    int      sockd;		/* socket descriptor		*/
    unsigned alen;		/* from-address length		*/
    struct sockaddr_in fsin;	/* address of a client		*/
    ETHERNET_HEADER *eth_h;
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
			if (!memcmp(eth_h->receiver, broad_eth,6) || !memcmp(eth_h->receiver, ifaces[riface].mac, 6))			  
			{
			    ifaces[riface].pkt_rx++; /* The packet must be processed */
				
				/*Atualizando a qtde de pacotes recebidos para que o XNOOP possa imprimir corretamente a id do pacote corrente travegando na rede*/
				_xnoop.npkgs = ifaces[riface].pkt_rx;			

    			   
				if (run_xnoop)
				{
					sem_wait(&sem_xnoop);
					xnoop(qtd_parameters, parameters, eth_h, &_xnoop);
					sem_post(&sem_xnoop);
				}
				//printf("Packet received (0x%04X) ()\n",(unsigned short) ntohs(eth_h->type));
			}
		}
    }
}
			
/* */
void send_pkt(u_short len, BYTE iface, BYTE *da, u_short type, BYTE *data)
{
    ETHERNET_PKT *pkt;
    PKT_QUEUE *qaux;
    ETHERNET_HEADER * ether;
     
    pkt = malloc(len + sizeof(ETHERNET_PKT));
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

/* */
int main(int argc, char *argv[])
{
	pthread_t tid;
	char buf[100];
	int i;
	//#####################
	ArpTable *arpTable;
	ArpTableEntry *entry;
	
	arpTable = BuildArpTable();
	
	entry = BuildArpTableEntry(1,1,2);
	
	AddArpTableEntry (arpTable, entry);
	entry = BuildArpTableEntry(2,1,2);
	 AddArpTableEntry (arpTable, entry);
	 entry = BuildArpTableEntry(3,1,5);
	 AddArpTableEntry (arpTable, entry);
	 entry = BuildArpTableEntry(3,1,5);
	 AddArpTableEntry (arpTable, entry);
	 entry = BuildArpTableEntry(1,1,9);
	 AddArpTableEntry (arpTable, entry);
	 
	 DisplayArpTable(arpTable);
	 //#####################   
	//Ajustando as opções padrões do XNOOP    
	_xnoop.modo = VERB_EXT;
	_xnoop.translation = 0;
	_xnoop.npkgs = 0;
	_xnoop.npkgs_max = 400000000;
	_xnoop.position = 1;
	run_xnoop = 1;
	
	qtd_pkgs = 0;
	
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
	
	
	/* Create sender and receiver threads */
	printf("Listening on port: %d\n", ntohs(my_port));
	pthread_create(&tid, NULL, subnet_rcv, (void *)&my_port);
	pthread_create(&tid, NULL, subnet_send, (void *)NULL);
	//#######
	FlushArpTable(arpTable);
	free(arpTable);
	//#######
	
	while (1) {
		printf("\ncmd> ");
		fgets(buf, MAX_PARAMETERS, stdin);		
		/*Tive de usar fgets pois com scanf não está funcionando os strncmps abaixo*/
		//scanf("%s", buf);
		if (!strncasecmp(buf, "XNOOP", 5)) {
			qtd_parameters = sub_xnoop(parameters, (char*)buf);
		}
		else if (!strncasecmp(buf, "ARP", 3)) 
		{
			sub_arp(2128162);
		}
		else if (!strncasecmp(buf, "IP", 2)) {
			scanf("%s", buf);
			send_pkt(100, atoi(buf), &broad_eth[0], 0x0800, (BYTE*)buf);
		}
		else if (!strncasecmp(buf, "IFCONFIG SHOW", 13)) {
			print_if_info(-1); /* O -1 é pra indicar que será impresso todas as interfaces */
		}
		else if (!strncasecmp(buf, "IFCONFIG", 8)) {
			sub_ifconfig((char*)buf);
		}
		else if (!strncasecmp(buf, "IF", 2)) {
			sub_if((char*)buf);
		}
		else if (!strncasecmp(buf, "EXIT", 4)) {
			exit(0);
		}
		else if (!strncasecmp(buf,"\n",1))
		{}
		else
			printf("Invalid command");
	}
	return 0;
}
/* */
