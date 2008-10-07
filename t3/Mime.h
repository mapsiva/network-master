#ifndef MIME_H_
#define MIME_H_
#include "string.h"

class MimeTableEntry
{
	public:
		const char* Extension;
		const char* mime;
		long Code;

};


#define DECLARE_MIMETYPE_TABLE(clazz) \
	private: \
		static MimeTableEntry _mimetypes[]; \
	public: \
		MimeTableEntry* FindMimeType(const char*)

#define DEFINE_MIMETYPE_TABLE(clazz) \
MimeTableEntry* \
clazz::FindMimeType(const char * ext) \
{ \
	MimeTableEntry* mime = SearchMimeType(_mimetypes, ext); \
	return mime; \
} \
DEFINE_MIMETYPE_TABLE_ENTRIES(clazz)

#define DEFINE_MIMETYPE_TABLE_ENTRIES(clazz) \
MimeTableEntry clazz::_mimetypes[] = {

#define MIMETYPE(ext, mime, code) \
	{ext, mime, code}

#define END_MIMETYPE_TABLE \
	{0, 0, 0}}
	
class Mime
{
	public:
		Mime();
		~Mime();
		static Mime * GetInstance();
	private:
		MimeTableEntry* SearchMimeType(MimeTableEntry*, const char *);
		
		static Mime * Instance;
		
		DECLARE_MIMETYPE_TABLE(Mime);
		
		
		
};

#endif /*MIME_H_*/
