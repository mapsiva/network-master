/** \file FileManager.cpp
 * \brief Arquivo de difinução da classe FileManager.
 *
 * Trabalho 3 - Redes de Computadores - Mestrado 2008
 * 
 * Servidor HTTP
 * 
 * Márcio Aparecido Inácio da Silva
 * Maxwell Sampaio dos Santos.
 */

#include "Util.h"
#include "FileManager.h"
#include "Config.h"

#include <fcntl.h>
#include <dirent.h>

 
bool FileManager::FileExist()
{
	return Handle;
}

FileManager::FileManager(){}

FileManager::FileManager(char *file, int *s)
{
	FileName = file;
	strmcpy(FileName, file, strlen(file));
	Ssock = s;
}
FileManager::FileManager(const char *file, int *s)
{
	FileName = (char *)file;
	strmcpy(FileName, (char *)file, strlen((char *)file));
	Ssock = s;
}
FileManager::~FileManager(){}

bool 
FileManager::Open(MimeTableEntry *&_mte)
{
	char *aux = new char[MAX_SIZE_BUF];
	strcpy(aux,"\0");
	sprintf(aux, "%s%s", Config::GetDocumentRoot(), FileName);
	//Verifica se existe o arquivo DEFAULT_INDEX dentro 
	//de um possível diretório apontado por FileName
	if (strlen(aux) > 0 && aux[strlen(aux)-1] != '/')
		strcat(aux, "/");	
	strcat(aux, Config::GetDefaultIndex());
	//printf("--%s--\n", aux);
	if ((Handle = open(aux, O_RDONLY)) > 0)
		return true;
	
	if (_mte == NULL)
		return false;
	
	strcpy(aux,"\0");
	sprintf(aux, "%s%s", Config::GetDocumentRoot(),FileName);
	if (strlen(aux) > 0 && aux[strlen(aux)-1] != '/')
		strcat(aux, "/");
	//printf("%s\n", aux);
	//Verifica se realmente existe um diretório apontado por FileName
	//printf("--%s--\n", aux);
	if ((Handle = open(aux, O_RDONLY)) > 0)
	{
		_mte = NULL;
		return false;
	}
	
	strcpy(aux,"\0");
	sprintf(aux, "%s%s", Config::GetDocumentRoot(),FileName);
	//printf("%s\n", aux);
	//Verifica se realmente existe o arquivo FileName
	//printf("--%s--\n", aux);
	return ((Handle = open(aux, O_RDONLY)) > 0);
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

void 
FileManager::HeaderAccept(char *mime)
{
	sprintf(buf, "HTTP/1.1 200 Document follows\r\nServer: %s\r\nContent-Type: %s\r\n\r\n", "DCT",mime);

	write (*Ssock, buf, strlen (buf));
}

void 
FileManager::HeaderNotFound()
{
	sprintf(buf, "HTTP/1.1 404 File Not Found\r\nServer: %s\r\nContent-Type: text/plain\r\n\r\n", Config::GetServerType());

	write (*Ssock, buf, strlen (buf));
	
	sprintf(buf,"\r\n\t\r\n\t\t404 Not Found\r\n\t\r\n\t\r\n\t\tNot Found\r\n\t\tThe request URL /%s was not found on this server.\r\n\t\t\r\n\t\t%s\r\n\t\r\n",FileName,Config::GetServerType());
	write (*Ssock, buf, strlen(buf));
}

inline char * 
FileManager::GetQueryString()
{
	char * url = new char[1024], *query;
	strcat (url, "QUERY_STRING=");
	query = strtok(FileName, "?");
	query = strtok(NULL, "?");
	strcat (url, query);
	return url;
}

inline char * FileManager::GetScript()
{	
	char * script;
	
	script = strtok(FileName, "?");
	script = strtok(script, "/");
	script = strtok(NULL, "/");
	
	return script;
}


void 
FileManager::Write()
{	
	Mime *mime = Mime::GetInstance();
	MimeTableEntry *_m = mime->FindMimeType(FileManager::GetExtension(FileName));
	int n,m;
	bool isDir = false;
	 
	if(Open(_m))	//o arquivo FileName ou um DEFAULT_INDEX dentro do diretório apontado por FileName
	{
		if (_m)
			HeaderAccept((char *)_m->mime);
		else
			HeaderAccept((char *)"text/html");
		
		while ((m = read(Handle, buf, 1024)) > 0)					
		{	
			for(int k=0; k<m; k+=n)
				n = write (*Ssock, buf, m-k);				
		}
		close(Handle);
	}
	else
	{
		DIR * pdir;
		char aux[MAX_SIZE_BUF], aux2[MAX_SIZE_BUF], aux3[MAX_SIZE_BUF];
		struct dirent *pent;

		sprintf(aux3, "%s%s",Config::GetDocumentRoot(), FileName);
		
		strcpy(aux2, "\0");
		strcpy(aux2, FileName);
		
		if (strlen(FileName) == 0)
		{
			strcpy(aux2, ".");
			strcat(aux3, ".");
		}
		else
		{
			if (aux2[strlen(aux2)-1] != '/')
				strcat(aux2, "/");
			if (aux3[strlen(aux3)-1] != '/')
				strcat(aux3, "/");
		}
		
		if(!_m && (pdir=opendir(aux3)))
		{
			 HeaderAccept((char *)"text/html");
			 isDir = true;
			 sprintf(buf,"<html>\r\n\t<head>\r\n\t\t<title></title>\r\n\t</head>\r\n\t<body>\r\n\t\t%s<hr>",aux2);
			 write (*Ssock, buf, strlen(buf));
			 
			 while ((pent = readdir(pdir)))
			 {
			 	strcpy(aux, "\0");
			 	strcpy(aux, aux2);
			  	strcpy(buf, "\0");
			  	m=0;
			  	if(!strcmp(pent->d_name, ".."))
			  	{
			  		if (strlen(FileName) != 0)
			  			m = sprintf(buf, "\r\n\t\t<a href=\"/%s..\">%s</a><br>", aux, "Back");
			  	}
			  	else if(!strcmp(pent->d_name, "."))  
			  	{
			  		if (strlen(FileName) == 0)
			  			m = sprintf(buf, "\r\n\t\t<a href=\"./.\">%s</a><br>", "Refresh");
			  		else
			  			m = sprintf(buf, "\r\n\t\t<a href=\"/%s.\">%s</a><br>", aux, "Refresh");
			  	}
			  	else
			  	{			  		
			  		if (strlen(FileName) == 0)
			  			m = sprintf(buf, "\r\n\t\t<a href=\"/%s\">%s</a><br>", pent->d_name, pent->d_name);
			  		else
			  		{
			  			strcat(aux, pent->d_name);
			  			m = sprintf(buf, "\r\n\t\t<a href=\"/%s\">%s</a><br>", aux, pent->d_name);
			  		}
			  	}
			  	
			  	for(int k=0; k<m; k+=n)
					n = write (*Ssock, buf, m-k);
			 }
			 sprintf(buf,"<hr>\r\n\t\t<i>%s</i>\r\n\t</body>\r\n</html>", Config::GetServerType());
			 write (*Ssock, buf, strlen(buf));
			 closedir(pdir);
		}
		else
		{
			if(!strncasecmp(FileName, Config::GetCgiPath() , 8))
			{
				FILE *file;
				char pipeContent[1024];
				char scriptName[64]={"cgi-bin/./"};
				putenv( GetQueryString () ); 
				
				HeaderAccept((char *)"text/html");
				
				strcat(scriptName, GetScript ());
				
				if ((file = popen( scriptName , "r"))) 
				{
					while(fgets(pipeContent, sizeof(pipeContent), file))
						write (*Ssock, pipeContent,  strlen(pipeContent));		
				
					pclose(file);
				}
				else
					printf("Error executing test\n");
			}
			else
				HeaderNotFound();
		}
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
		return NULL;
	
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
	
	return ext;
}
