#ifndef UTIL_H_
#define UTIL_H_

#define IP_VER(p) (p->version >> 4)/*Version*/
#define IP_IHL(p) ((p->version & 0xf)*2)/*internet header length*/

#define IP_DELAY(p) ((p->type_service >> 4) & 0x1)
#define IP_THROU(p) ((p->type_service >> 3) & 0x1)
#define IP_RELIA(p) ((p->type_service >> 2) & 0x1)
#define IP_FLAGS(p) ((ntohs(p->fragment) >> 13))/*Flags*/
#define IP_OFFSET(p) ((ntohs(p->fragment) & 0x1FFF))/*fragment offset*/

#endif 
