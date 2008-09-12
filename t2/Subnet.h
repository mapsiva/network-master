/**
	Universidade Federal de Mato Grosso do Sul
	Mestrado em Ciência da Computação DCT - UFMS
	Redes de Computadores 2008
	
	Márcio Aparecido Inacio da Silva
	Maxwell Sampaio dos Santos
	
	Xnoop - Analizador de Pacotes [Trabalho 1]
*/

#ifndef SUBNET_H_
#define SUBNET_H_

/* */
#define MAX_PKT_SZ	65536
#define MAX_HOSTS	10
#define MAC_ADDR_LEN	6
#define MAX_IFACES	5
#define MAX_NETWORKS	20
#define MAX_PARAMETERS	256

/* */
typedef struct {
    u_short  port;
    unsigned ip;
} NET_HOSTS;

/* */
u_char net2iface[MAX_NETWORKS];

/* */
typedef struct {
    u_char	interface;		/* Interface number		*/
    u_char	mac[6];			/* MAC address			*/
    u_short	mtu;			/* MTU value			*/
    unsigned	ip;			/* IP address			*/
    unsigned	mask;			/* IP network mask		*/
    unsigned    ip_bcast;		/* IP broadcast address		*/
    unsigned	pkt_tx;			/* Number of packets transmitted*/
    unsigned	pkt_rx;			/* Number of packets received	*/
    NET_HOSTS	hosts[MAX_HOSTS];	/* Hosts in the same network	*/
    u_char	nhosts;			/* Number of hosts in the net	*/
    u_char	up;			/* Interface up or down		*/
    u_char	net;			/* Simul. network number	*/
} INTERFACE;

/* */
typedef struct {
    u_char  net;
    u_char  da[6];
    u_char  sa[6];
    u_short type;
} ETHER_HEADER;

/* */
typedef struct {
    u_short len;
    u_char  iface;
    u_char  net;
    u_char  da[6];
    u_char  sa[6];
    u_short type;
    u_char  data[1];
} ETHER_PKT;

/* */
typedef struct _pq {
    ETHER_PKT  *pkt;
    struct _pq *next;
} PKT_QUEUE;

/* */
PKT_QUEUE *queue_head;
PKT_QUEUE *queue_tail;

/* */
sem_t sem_data_ready;
sem_t sem_queue;

/* */
INTERFACE ifaces[MAX_IFACES];	/* Interfaces of the host/router */

/* */
unsigned nifaces;		/* Number of interfaces */

/* */
unsigned my_ip;
u_short  my_port;

/* */
u_char broad_eth[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

/* */
char in_buf[MAX_PKT_SZ];

int qtd_parameters, run_xnoop;

char *parameters[MAX_PARAMETERS];

/* functions*/

int passive_UDP_socket(u_short);

void *subnet_rcv(void *);

void send_pkt(u_short, u_char , u_char *, u_short , u_char *);

void *subnet_send(void *);

void str2eth(char *, u_char[]);

char *ip2str(char *, unsigned);

void read_net_cfg(char *, u_short, u_short);

int print_if_info(int);

int sub_xnoop(char *[], char *);

int sub_ifconfig( char* );

int sub_if( char* );

#endif 
