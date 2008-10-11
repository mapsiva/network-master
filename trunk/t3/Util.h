#ifndef UTIL_H_
#define UTIL_H_

enum {
	_QLEN			= 5,
	_SERVER_PORT 	= 8080,
	_HTTP_THREAD 	= 1,
	_HTTP_PROCESS 	= 2, 
	MAX_SIZE_BUF	= 1024,
};   	

void perror_exit(const char *msg);

#endif /*UTIL_H_*/
