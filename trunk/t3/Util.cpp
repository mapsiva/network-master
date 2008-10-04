#include <stdlib.h>
#include <stdio.h>
#include "Util.h"

void perror_exit(const char *msg)
{
    perror(msg);
    exit(1);
}
