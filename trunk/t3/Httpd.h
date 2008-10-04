#ifndef HTTPD_H_
#define HTTPD_H_

#include <stdio.h>

class Httpd
{
   	public:
   		//methods
    	Httpd(int, int, int);    	
   		void Run();	
   	private:
   		//atributes
   		int _modo;
   		int _qtd_threads;
   		int _port;
   		
   		//methods
   		int PassiveTCPSocket();
};

#endif /*HTTPD_H_*/
