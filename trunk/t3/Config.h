#ifndef CONFIG_H_
#define CONFIG_H_

class Config
{
	public:
		Config();
		~Config();
		static char* GetDocumentRoot(); 
		static char* GetDefaultIndex();
		static char* GetServerType();
		static char* GetCgiPath();
		static bool GetDebugMode();
	protected:
		static char cfg_file_name[64];
   		static char DOCUMENT_ROOT[256];
   		static char DEFAULT_INDEX[256];
   		static char SERVER_TYPE[256];
   		static char CGI_PATH[256];
   		static bool DEBUG_MODE;
};

#endif /*CONFIG_H_*/
