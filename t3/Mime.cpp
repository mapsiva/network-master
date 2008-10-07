#include "Mime.h"

Mime * Mime::Instance = NULL;

Mime::Mime(){}

Mime::~Mime(){}

DEFINE_MIMETYPE_TABLE(Mime)
	MIMETYPE("GIF"     , "image/gif", 0),
END_MIMETYPE_TABLE;

MimeTableEntry*
Mime::SearchMimeType(MimeTableEntry* k, const char* ext)
{
	while (k->Extension)
    {
		if (!strcasecmp((const char *)k->Extension, (const char*)ext))
			return k;
		k++;
	}
	return 0;
}

Mime*
Mime::GetInstance()
{
	if(!Instance)
		Instance = new Mime();

	return Instance;
}
