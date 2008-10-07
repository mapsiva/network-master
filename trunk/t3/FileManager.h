#ifndef FILEMANAGER_H_
#define FILEMANAGER_H_
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/errno.h>
#include <unistd.h>
//#include <sys/signal.h>
//#include <wait.h>
class FileManager
{
	public:
		bool FileExist();
		FileManager();
		FileManager(char *, int*);
		FileManager(const char *, int*);
		~FileManager();
		bool Open();
		void Write();
		int GetParameters(char ***, const char *);
   		char * GetExtension(const char *);
		
	private:
		FILE *Handle;
		char *FileName;
		int *Ssock;	
		char buf[1024];
};
#endif /*FILEMANAGER_H_*/
