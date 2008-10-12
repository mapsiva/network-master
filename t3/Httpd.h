#ifndef HTTPD_H_
#define HTTPD_H_

#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <wait.h>
class Httpd
{
   	public:
   		//methods
    	Httpd(int, int, int);
   		void Run();
   		void Start();
   	private:
   		//atributes
   		int _modo;
   		int _qtd_threads;
   		int _port;
   		
   		//methods
   		int PassiveTCPSocket();
   		
   		static void* Kill_Defuncts();
};

#endif /*HTTPD_H_*/
