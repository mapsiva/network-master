/**
	Universidade Federal de Mato Grosso do Sul
	Mestrado em Cincia da Computao DCT - UFMS
	Redes de Computadores 2008
	
	Mrcio Aparecido Inacio da Silva
	Maxwell Sampaio dos Santos
	
	Xnoop - Analizador de Pacotes [Trabalho 1]
*/
#ifndef TYPES_H_
#define TYPES_H_

typedef unsigned char CHAR_T;
typedef unsigned char BYTE;
typedef unsigned short SWORD;
typedef unsigned long WORD;
typedef unsigned long long DWORD;

typedef struct
{
    CHAR_T * name;
    int code;
    DWORD value;
}Token;


#define DATA 64;

enum
{
    IP      = 0x0800,
    ARP     = 0x0806
};

enum
{
    ICMP    = 1,
    TCP     = 6,
    UDP     = 17
};

enum
{
    BASIC    	= 1,
    VERB  		= 2,
    VERB_EXT    = 3
};

enum
{
	ARP_REQUEST = 1,
	ARP_REPLY	= 2
};

enum Types
{
    ECHO_REPLAY             = 0,
    DESTINATION_UN          = 3,
    SOURCE_QUENCH           = 4,
    REDIRECT                = 5,
    ECHO_REQUEST            = 8,
    ROUTER_AD               = 9,
    ROUTER_SOL              = 10,
    TTL                     = 11,
    PP                      = 12,
    TIMESTAMP_REQUEST       = 13,
    TIMESTAMP_REPLY         = 14,
    INFO_REQUEST            = 15,
    INFO_REPLY              = 16,
    ADDRESS_MASK_REQUEST    = 17,
    ADDRESS_MASK_REPLY      = 18
};

enum Flags
{
	BIN128 = 0x0080,
	BIN64 = 0x0040,
    BIN32 = 0x0020,
    BIN16 = 0x0010, 
    BIN8 = 0x0008, 
    BIN4 = 0x0004, 
    BIN2 = 0x0002, 
    BIN1 = 0x0001
};

enum _tokens
{
    _NUMBER     = 1,
    _HEXA,
    _ADDRESS_IP,
    _MAC,
    _KEYWORD,
    _EQ,
    _AND,
    _OR,
    _NOT,
    _OPERATOR,
    _DIV,
    _MOD,
    _SUM,
    _MINUS,
    _MULT,
    _BIN_OPERATOR,
    _ETHERNET,
    _IP,
    _UDP,
    _TCP,
    _ICMP,
    _ARP,
    _ETHERTO,
    _ETHERFROM,
    _ETHERTYPE,
    _IPTO,
    _IPFROM,
    _IPPROTO,
    _UDPTOPORT,
    _UDPFROMPORT,
    _TCPTOPORT,
    _TCPFROMPORT,
    _ICMPTYPE
};


/* ip PRECENDENCE
111 - Network Control
110 - Internetwork Control
101 - CRITIC/ECP
100 - Flash Override
011 - Flash
010 - Immediate
001 - Priority
000 - Routine
*/
enum
{
    NETWORKCTRL     = 7,
    INTERNETCTRL    = 6,
    CRITICCEP       = 5,
    FLASHOVER       = 4,
    FLASH           = 3,
    IMMEDIATE       = 2,
    PRIORITY        = 1,
    ROUTINE         = 0
};

WORD to_word(void *);

enum type_pkgs
{
    T_ETHER = 0,
    T_ARP,
    T_IP,
    T_TCP,
    T_UDP,
    T_ICMP,
    T_BROAD,
    T_PKG_ME    
};

#define MAX_HOSTS		10

/* */
typedef struct {
    SWORD  port;
    unsigned ip;
} NET_HOSTS;

/* */
typedef struct {
    BYTE	interface;				/* Interface number		*/
    BYTE	mac[6];					/* MAC address			*/
    SWORD	mtu;					/* MTU value			*/
    unsigned	ip;					/* IP address			*/
    unsigned	mask;				/* IP network mask		*/
    unsigned    ip_bcast;			/* IP broadcast address		*/
    unsigned	pkt_tx;				/* Number of packets transmitted*/
    unsigned	pkt_rx;				/* Number of packets received	*/
    NET_HOSTS	hosts[MAX_HOSTS];	/* Hosts in the same network	*/
    BYTE	nhosts;					/* Number of hosts in the net	*/
    BYTE	up;						/* Interface up or down		*/
    BYTE	net;					/* Simul. network number	*/
} INTERFACE;

/* Definitions for XNOOP */
typedef struct {
    int modo;						/*modo de funcionamento (BASIC)*/
    int translation;				/*traducao de nomes*/
	unsigned long npkgs;			/*quantidade atual de pacotes analisados*/
	unsigned long npkgs_max; 		/*quantidade mxima de pacotes a serem analisados*/
	int position;					/*posicao da lista de parmetros onde comeam os filtros */	

	int count[8];	/*contadores para os tipos de pacotes analisados*/
} _XNOOP;

typedef struct tKeywordTableEntry
{
		CHAR_T* Name;
		int Token;
		int Code;

}tKeywordTableEntry;


tKeywordTableEntry*
SearchKeyword(tKeywordTableEntry* k, const char * name);

tKeywordTableEntry* 
FindKeyword(const char * name) ;


#define DECLARE_KEYWORD_TABLE() \ \
	tKeywordTableEntry _keywords[]; \
	
#define DEFINE_KEYWORD_TABLE() \
tKeywordTableEntry* \
FindKeyword(const char * name) \
{ \
	tKeywordTableEntry* kword = SearchKeyword(_keywords, name); \
	return kword; \
} \
DEFINE_KEYWORD_TABLE_ENTRIES()

#define DEFINE_KEYWORD_TABLE_ENTRIES() \
tKeywordTableEntry _keywords[] = {

#define KEYWORD(name, token, code) \
	{name, token, code}

#define END_KEYWORD_TABLE \
	{0, -1, 0}}
	
	


#endif
