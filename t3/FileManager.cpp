
#include "FileManager.h"
#include "Mime.h"

							 
bool FileManager::FileExist()
{
	return Handle;
}

FileManager::FileManager(){}

FileManager::FileManager(char *file, int *s)
{
	strmcpy(FileName, file, strlen(file));
	Ssock = s;
}
FileManager::FileManager(const char *file, int *s)
{
	strmcpy(FileName, (char *)file, strlen((char *)file));
	Ssock = s;
}
FileManager::~FileManager(){}

bool FileManager::Open()
{
	return ((Handle = fopen(FileName, "r")));
}

char*
FileManager::strmcpy(char *dest, const char *src, int n)
{
       int i;

       for (i = 0 ; i < n-1 && src[i] != '\0' ; i++)
           dest[i] = src[i+1];
       for ( ; i < n ; i++)
           dest[i] = '\0';

       return dest;
   }

void FileManager::Write()
{
	Mime *mime = Mime::GetInstance();
	MimeTableEntry *_m = mime->FindMimeType(FileManager::GetExtension(FileName));
	printf("FileName => %s\n", FileName);	
	if(_m && Open())
	{		
		sprintf(buf, "HTTP/1.1 200 Document follows\r\nServer: %s\r\nContent-Type: %s \r\n\r\n", "DCT", (char *)_m->mime);

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
		sprintf(buf, "<h1>Ih! Ferrou!</h2>");
		write (*Ssock, buf, strlen (buf));
		//error page load here
	}
	
}

/*
 * Recebe uma string (GET_STRING)
 * Retorna por referência um vetor de parameters com as variaveis e seus valores
 * Retorna a quantidade de variaveis encontradas 
 */
int FileManager::GetParameters(Parameter **p, char *a)
{
	int qtd = 0;
	int i, tam, tam2;
	char *aux1, *aux2, *aux3, *aux4;
	
	aux1 = aux2 = aux3 = aux4 = NULL;
	
	tam = strlen(a);
	
	a[tam-1] = '&';
	aux1 = strtok(a,"?");
	
	if (aux1)
	{
		//Determina a quantidade de parametros
		while ((aux1 = strtok(NULL, "&")) != NULL)
			qtd++;
			
		p = new Parameter*[qtd];
		
		i = 0;
		aux1 = strtok(a,"?");
		while ((aux1 = strtok(NULL, "&")) != NULL)
		{
			p[i++] = new Parameter();
			
			aux1[tam2-1] = '=';
			
			aux2 = strtok(aux1,"=");
			p[i]->name = (char *) malloc(sizeof(aux3));
			memcpy(p[i]->name, aux3, sizeof(aux3)); 			
			
			aux3 = strtok(NULL,"=");
			p[i]->value = (char *) malloc(sizeof(aux3));
			memcpy(p[i]->value, aux3, sizeof(aux3));			
		}
	}
	
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
	for (i=pos+1; i<tam; i++)
	{
		if (b[i] == '&' || b[i] == '?')
			break;
		ext[j] = b[i];
		j++;
	}
	printf("Extensao [%s]\n", ext);
	return ext;
}
