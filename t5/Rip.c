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


RouteTableEntry * BuildRipTableEntry( BYTE cmd, WORD IP , WORD metric)
{
	 RipTableEntry * _entry =  (RipTableEntry *) malloc(sizeof(RipTableEntry));
	 
	 _entry->cmd =  	cmd;
	 _entry->IP = 	(WORD *)to_ip_byte ( IP );
	 _entry->metric = 	metric;
	 _entry->ZERO1 = 0;
	 _entry->ZERO2 = 0;
	 _entry->ZERO3 = 0;
	 _entry->ZERO4 = 0;
	 _entry->next = NULL;
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
/* Funcao que imprime a tabela de Roteamento na tela
 * 
 * @param void
 * @return void
 */
void DisplayRipTable (RipTable * table)
{
	RipTableEntry *_entry = table->list;
	
	printf ("\nIP\t\t Distancia\n");
	
	while (_entry)
	{
		printf ("%-16s %-16s\t ", format_address((DWORD)*(&_entry->IP)),_entry->metric);
		
		_entry = _entry->next;
	}
	
}


/*
* Busca um elemento na tabela de Roteamento baseado no valor do IP
* @param table ponteiro para a tabela de Roteamento
* @param entry uma entrada da tabela de roteamento que se deseja encontrar
* @param current flag que indica para funcao retornar o elemento corrente (1) na busca ou seu anterior(0)
*
* @return NULL ou uma entrada valida na tabela de Roteamento
*
* @since           2.0
*/
RipTableEntry *
FindRipTableEntry( RipTable * table, RipTableEntry * entry, int current )
{
	RipTableEntry *_entry = table->list;
	
	while ( _entry)
	{		
		if(current && *(_entry->TARGET) == *(entry->TARGET) &&
				*(_entry->GATEWAY) == *(entry->GATEWAY) && *(_entry->MASK) == *(entry->MASK))
			break;
		else if(!current && _entry->next && *(_entry->next->TARGET) == *(entry->TARGET) &&
				*(_entry->next->GATEWAY) == *(entry->GATEWAY) && *(_entry->next->MASK) == *(entry->MASK))
			break;
		else if(!current && *(table->list->TARGET) == *(entry->TARGET) &&
				*(table->list->GATEWAY) == *(entry->GATEWAY) && *(table->list->MASK) == *(entry->MASK))	
			break;
		_entry = _entry->next;
		
	}
	return _entry;
	
}

/*
* Busca a rota para o endereço ip
* @param table ponteiro para a tabela de Roteamento
* @param _ip endereço ip da subrede de destino
*
* @return NULL ou uma entrada valida na tabela de Roteamento
*
* @since           2.0
*/
RipTableEntry *
FindProxNo( RipTable * table, WORD _ip)
{
	RipTableEntry *_entry = table->list;
	
	while ( _entry )
	{	
		if ((_ip & *(_entry->MASK)) == *(_entry->TARGET))
		{
			return _entry;	
		}
		_entry = _entry->next;	
	}
	return NULL;	
}

/*
* @param table ponteiro para a tabela de Roteamento
* @param entry uma entrada da tabela de roteamento que se deseja adicionar
*
* @return void
*
* @since           2.0
*/

void AddRipTableEntry( RipTable * table, RipTableEntry * newer)
{
	RipTableEntry *_entry = table->list;
	RipTableEntry *_prev = NULL;
	
	while (_entry && *(newer->MASK) <= *(_entry->MASK))
	{
		if (*(_entry->TARGET) == *(newer->TARGET) && *(_entry->GATEWAY) == *(newer->GATEWAY) && *(_entry->MASK) == *(newer->MASK))
		{
			_entry->TTL = newer->TTL;
			return;
		}
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
* Remove um elemento da tabela de Roteamento
*
* @param table ponteiro para a tabela de Roteamento
* @param entry uma entrada da tabela de roteamento que se deseja remover
*
* @return NULL ou uma entrada valida na tabela de Roteamento
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
		if(_entry == table->list
			&& *(entry->TARGET) == *(_entry->TARGET) 
			&& *(entry->GATEWAY) == *(_entry->GATEWAY) 
			&& *(entry->MASK) == *(_entry->MASK) 
		)	//Remover o primeiro elemento da lista
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
* Destrói a tabela de Roteamento
* @param table ponteiro para a tabela de Roteamento
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
