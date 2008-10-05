
#include "FileManager.h"


							 
bool FileManager::FileExist()
{
	return Handle;
}

FileManager::FileManager(){}

FileManager::FileManager(char *file, int *s)
{
	FileName = file;
	Ssock = s;
}
FileManager::FileManager(const char *file, int *s)
{
	FileName = (char *)file;
	Ssock = s;
}
FileManager::~FileManager(){}

bool FileManager::Open()
{
	return ((Handle = fopen(FileName, "r")));
}
void FileManager::Write()
{
	printf("Load file...\n");
	if(Open())
	{
		printf("Arquivo aberto");
		
		sprintf(buf, "HTTP/1.1 200 Document follows\r\nServer: %s\r\nContent-Type: %s\r\n\r\n", "DCT", "text/html");
			 	
		write (*Ssock, buf, strlen (buf));
		while (!feof (Handle))					
		{
			fread(&buf, 512, 1, Handle);
			
			write (*Ssock, buf, strlen (buf));				
		}
		fclose(Handle);
	}
	else
	{
		printf("erro ao carregar o arquivo");
		sprintf(buf, "<h1>Object Not Found</h2>");
		write (*Ssock, buf, strlen (buf));
		//error page load here
	}
	printf("DONE!...\n");
}
