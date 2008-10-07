
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
		
		sprintf(buf, "HTTP/1.1 200 Document follows\r\nServer: %s\r\nContent-Type: %s \r\n\r\n", "DCT", "text/html");
			 	
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

/*
 * Recebe uma string (GET_STRING)
 * Retorna por referência um array com as variaveis e seus valores
 * Retorna a quantidade de variaveis encontradas 
 */
int FileManager::GetParameters(char ***p, const char *a)
{
	int qtd = 0;	
	
	return qtd;	
}

/*
 * Recebe uma string (GET_STRING)
 * Retorna a extensão do arquivo sendo solicitado
 */
char * FileManager::GetExtension(const char *b)
{
	int i, j, tam, tam2, pos;
	char *ext;
	
	tam = strlen(b);
	pos = tam;
	for (i=0; i<tam; i++)
	{
		if (b[i] == '.')
			pos = i;
	}
	
	if (pos == tam)
		return '\0';
	
	tam2 = tam-pos-1;
	ext = (char *) malloc(tam2);
	for (i=0; i<tam2; i++)
		ext[i] = '\0';
	j = 0;
	for (i=pos; i<tam; i++)
	{
		if (b[i] == '&' || b[i] == '?')
			break;
		ext[j] = b[i];
		j++;
	}
	
	return ext;
}

