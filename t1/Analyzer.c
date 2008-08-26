#ifndef ANALYZER_C_
#define ANALYZER_C_
#include "Types.h"
#include "Analyzer.h"
#include <ctype.h>


Token *
token()
{
    if(!_current)
        return 0;
    
    if(isdigit(*_current))
    {
        
    }
    return 0;
}

#endif 
