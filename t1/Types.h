#ifndef TYPES_H_
#define TYPES_H_

typedef unsigned char CHAR_T;
typedef unsigned char BYTE;
typedef unsigned short SWORD;
typedef unsigned long WORD;

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
