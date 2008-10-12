#ifndef FILEMANAGER_H_
#define FILEMANAGER_H_
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/errno.h>
#include <unistd.h>
#include <string.h>
#include "Mime.h"

struct Parameter
{
	char *name;
	char *value;	
};

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
		int GetParameters(Parameter **, char *);
   		static char * GetExtension(const char *);
   		inline char * GetQueryString();
   		inline char * GetScript();
   		
		char* strmcpy(char *dest, const char *src, int n);
		void HeaderAccept(char *);
		void FileNotFound();
	private:
		int Handle;
		char *FileName;
		int *Ssock;	
		char buf[1024];
		Parameter *parameters;
};
#endif /*FILEMANAGER_H_*/
