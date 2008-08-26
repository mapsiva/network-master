#ifndef ANALYZER_C_
#define ANALYZER_C_
#include "Types.h"
#include "Analyzer.h"
#include <ctype.h>
#include <wctype.h>
#include <stdlib.h>

Token *
token()
{
    Token token;
    DWORD ip, hexa;
    if(!_current)
        return 0;

_decimal:
    
    if(iswdigit(*_current))
    {
        int num;
        
        while (iswdigit(*_current))
        {
            num *= 10;
            num += (int)atoi (*((char *)_current++));
        }
        
        if(iswspace(*_current))
        {
            token.value = (int *)&num;
            token.code = _NUMBER;
            
            return token;
        }
        
        if((*_current)== '.')
        {
            
            goto _ip_format;
        }
    }

_ip_format:

_hexa:

    return 0;
}

#endif 
