#include <stdio.h>
#include <string.h>
#include "Config.h"
#include "Util.h"

char Config::cfg_file_name[64] = "httpd.conf";
char Config::DOCUMENT_ROOT[256] = "/";
char Config::DEFAULT_INDEX[256] = "index.html";
char Config::SERVER_TYPE[256] = "DCT-REDES-2008/1.0";
char Config::CGI_PATH[256] = "cgi-bin/";
bool Config::DEBUG_MODE = false;

Config::Config()
{
	FILE *cfg_file;
	char line[MAX_SIZE_BUF];
	char *aux;
	
	cfg_file = fopen(cfg_file_name, "r");
	if (!cfg_file)
		perror_exit("Error Config File");
	else
	{
		while (fgets(line, sizeof(line), cfg_file))
			if (line[0] != '#' && line[0] != '\n') //ignorando comentários e linhas em branco do arquivo de configurcao
			{
				aux = strtok(line, " ");
				if (!strncasecmp(aux, "DOCUMENT_ROOT", 12))
				{
					aux = strtok(NULL, "\n");
					strcpy(DOCUMENT_ROOT, aux);
					
					//Verificando se o usuário inseriu o '/' no fim
					if (DOCUMENT_ROOT[strlen(DOCUMENT_ROOT)-1] != '/')
						strcat(DOCUMENT_ROOT,"/");
				}
				else if (!strncasecmp(aux, "DEFAULT_INDEX", 12))
				{
					aux = strtok(NULL, "\n");
					strcpy(DEFAULT_INDEX, aux);
				}
				else if (!strncasecmp(aux, "SERVER_TYPE", 10))
				{
					aux = strtok(NULL, "\n");
					strcpy(SERVER_TYPE, aux);
				}
				else if (!strncasecmp(aux, "CGI_PATH", 7))
				{
					aux = strtok(NULL, "\n");
					strcpy(CGI_PATH, aux);
					
					//Verificando se o usuário inseriu o '/' no fim
					if (CGI_PATH[strlen(CGI_PATH)-1] != '/')
						strcat(CGI_PATH,"/");
				}				
				else if (!strncasecmp(aux, "DEBUG_MODE", 9))
				{
					aux = strtok(NULL, "\n");
					if (!strncasecmp(aux, "TRUE", 4))
						DEBUG_MODE = true;
					else
						DEBUG_MODE = false;
				}
			}
	}
}

Config::~Config(){}

char * 
Config::GetDocumentRoot()
{
	return DOCUMENT_ROOT;
}

char * 
Config::GetDefaultIndex()
{
	return DEFAULT_INDEX;	
}

char * 
Config::GetServerType()
{
	return SERVER_TYPE;	
}

char * 
Config::GetCgiPath()
{
	return CGI_PATH;	
}

bool 
Config::GetDebugMode()
{
	return DEBUG_MODE;	
}
