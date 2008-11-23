#ifndef RIP_H_
#define RIP_H_

typedef struct tRipTableEntry
{
    BYTE cmd;
    BYTE version;
    SWORD ZERO1;
    SWORD AFI;
    SWORD ZERO2;
    WORD IP;
    WORD ZERO3;
    WORD ZERO4;
    WORD metric;    
    struct tRipTableEntry* next;
}RipTableEntry;


typedef struct
{
    int length;
    struct tRipTableEntry *list ;
}RipTable;


/*
* Busca uma entrada na tabela de Roteamnto, caso sucesso retorna a entrada, caso contrário retorna NULL
*/
RipTableEntry * 
FindRipTableEntry( RipTable * table, RipTableEntry * entry, int current);

RipTableEntry *
FindProxNo( RipTable * table, WORD _ip);

/*
*constrói uma entrada para a tabela RIP
*/
RipTableEntry * 
BuildRipTableEntry( CHAR_T*, CHAR_T* , CHAR_T*, BYTE,  int);

/*
*Adiciona uma entrada na tabela RIP
*/
void  
AddRipTableEntry( RipTable * table, RipTableEntry * entry);

/*
*Remove uma entrada da tabela RIP
*/
RipTableEntry *
RemoveRipTableEntry( RipTable * table, RipTableEntry * entry );

/*
*Instancia uma tabela RIP
*/
RipTable * 
BuildRipTable();

/*
*Imprime toda a tabela RIP na tela
*/
void 
DisplayRipTable (RipTable * table);

/*
* Destrói uma tabela RIP
*/
void 
FlushRipTable (RipTable * table);

#endif /*RIP_H_*/
