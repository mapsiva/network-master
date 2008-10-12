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
   		char cfg_file_name[64];
   		char DOCUMENT_ROOT[256];
   		char DEFAULT_INDEX[256];
   		char SERVER_TYPE[256];
   		char CGI_PATH[256];
   		bool DEBUG_MODE;
   		
   		//methods
   		int PassiveTCPSocket();
   		
   		static void* Kill_Defuncts();
   		void Config_Server();
};

#endif /*HTTPD_H_*/
