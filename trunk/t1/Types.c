#ifndef TYPES_C_
#define TYPE_C_
#include "Types.h"
#include "strings.h"

WORD to_word(void * value)
{
	return (WORD) ((void*)value); 
}

tKeywordTableEntry*
SearchKeyword(tKeywordTableEntry* k, const char * name)
{
    while (k->Name)
    {
		if (!strcasecmp((const char *)k->Name, (const char*)name))
			return k;
		k++;
	}
	return 0;
}



#endif 
