#ifndef TYPES_H_
#define TYPES_H_

typedef unsigned char CHAR_T;
typedef unsigned char BYTE;
typedef unsigned short SWORD;
typedef unsigned long WORD;
typedef unsigned long long DWORD;

typedef struct
{
    int code;
    void * value;
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
    URG = 0x0020,
    ACK = 0x0010, 
    PSH = 0x0008, 
    RST = 0x0004, 
    SYN = 0x0002, 
    FIN = 0x0001
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
#endif
