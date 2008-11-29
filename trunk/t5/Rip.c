#ifndef RIP_C_
#define RIP_C_

#include "Rip.h"


/*
* @param IP Ip da maquina
* @param MAC mac da maquina
* @param TTL tempo de vida da entrada
* 
* @return ArpTableEntry* retorna um ponteiro para a entrada criada
* 
* @since           2.0
*/


RipTableEntry * BuildRipTableEntry( WORD host , int num_hops)
{
	 RipTableEntry * _entry =  (RipTableEntry *) malloc(sizeof(RipTableEntry));
	 
	 _entry->host 		=  	host;
	 _entry->num_hops	= 	num_hops;
	 return _entry;
}

/*
* @param void
* @since           2.0
*/

RipTable *
BuildRipTable()
{
	 RipTable * _table =  (RipTable *) malloc(sizeof(RipTable));
     
     _table->list = NULL;
     
     _table->length = 0;
     
     return _table;
}
/* Funcao que imprime a tabela RIP na tela
 * 
 * @param void
 * @return void
 */
void DisplayRipTable (RipTable * table)
{
	RipTableEntry *_entry = table->list;
	
	printf ("\nIP\t\t prox no\t\tDistancia\n");
	
	while (_entry)
	{
		printf ("%-16s %-16d\t ", format_address((DWORD)*(&_entry->host)),
		_entry->num_hops);
		
		_entry = _entry->next;
	}
	
}


/*
* Busca um elemento na tabela RIP baseado no valor do IP
* @param table ponteiro para a tabela RIP
* @param entry uma entrada da tabela RIP que se deseja encontrar
* @param current flag que indica para funcao retornar o elemento corrente (1) na busca ou seu anterior(0)
*
* @return NULL ou uma entrada valida na tabela RIP
*
* @since           2.0
*/
RipTableEntry *
FindRipTableEntry( RipTable * table, RipTableEntry * entry, int current )
{
	RipTableEntry *_entry = table->list;
	
	while ( _entry)
	{		
		if(current && (_entry->host) == (entry->host))
			break;
		else if(!current && _entry->next && _entry->next->host == entry->host)
			break;
		else if(!current && table->list->host == entry->host)	
			break;
		_entry = _entry->next;
		
	}
	return _entry;
	
}



/*
* @param table ponteiro para a tabela RIP
* @param entry uma entrada da tabela RIP que se deseja adicionar
*
* @return void
*
* @since           2.0
*/

void AddRipTableEntry( RipTable * table, RipTableEntry * newer)
{
	RipTableEntry *_entry = table->list;
	RipTableEntry *_prev = NULL;
	
	while ( _entry )
	{
		if (_entry->host == newer->host)
			return;
		
		_prev = _entry;
		_entry = _entry->next;
	}
	
	if (_prev)
	{
		newer->next = _prev->next;
		_prev->next = newer;
	}
	else
	{
		newer->next = table->list;
		table->list = newer;	
	}
	table->length++;
}

/*
* Remove um elemento da tabela RIP
*
* @param table ponteiro para a tabela RIP
* @param entry uma entrada da tabela RIP que se deseja remover
*
* @return NULL ou uma entrada valida na tabela RIP
*
* @since           2.0
*/

RipTableEntry * 
RemoveRipTableEntry( RipTable * table, RipTableEntry * entry )
{
	RipTableEntry *_entry = NULL, *_remove = NULL;
	
	if(!table->length)
		return NULL;		
	
	if( (_entry = FindRipTableEntry (table, entry, 0 )))
	{
		if(_entry == table->list && (entry->host) == (_entry->host))	//Remover o primeiro elemento da lista
		{
			_remove = table->list; 
			table->list = (table->list)->next;
		}
		else if (_entry == table->list)	//Remover segundo elemento da lista
		{
			_remove = _entry->next; 
			(table->list)->next = _remove->next;
		}
		else
		{	
			_remove = _entry->next;
			_entry->next = _remove->next;
		}
		table->length --;		
	}
	
	return _remove;
}

/*
* Destrói a tabela RIP
* @param table ponteiro para a tabela RIP
*
* @return void
*
* @since           2.0
*/
void 
FlushRipTable (RipTable * table)
{
    RipTableEntry *_remove,  *_entry = table->list;
    
    while (_entry)
    {
        _remove = _entry;
        
        _entry = _remove->next;
        
        free (_remove);
    }
    
    table->length = 0;
}

#endif 
