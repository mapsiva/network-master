#include "Mime.h"

Mime * Mime::Instance = NULL;

Mime::Mime(){}

Mime::~Mime(){}

DEFINE_MIMETYPE_TABLE(Mime)
	MIMETYPE("txt", "text/plain", 0),
	MIMETYPE("pdf", "application/pdf",  0),
	MIMETYPE("doc", "application/msword",0),
	MIMETYPE("css", "text/css", 0),
	MIMETYPE("fh",  "image/x-freehand", 0),
	MIMETYPE("htm", "text/html", 0),
	MIMETYPE("html","text/html", 0),
	MIMETYPE("ini", "zz-application/zz-winassoc-ini", 0),
	MIMETYPE("inf", "text/inf", 0),
	MIMETYPE("mov", "video/quicktime", 0),
	MIMETYPE("mp3", "audio/x-mpeg3", 0),
	MIMETYPE("mp4", "video/mp4v-es", 0),
	MIMETYPE("mpg", "video/x-mpeg",0),
	MIMETYPE("ogg", "audio/x-ogg",0),
	MIMETYPE("ppt", "application/mspowerpoint", 0),
	MIMETYPE("swf", "application/x-shockwave-flash", 0),
	MIMETYPE("tiff", "image/tiff",0),
	MIMETYPE("wav", "audio/wav", 0),
	MIMETYPE("wma", "audio/x-ms-wma", 0),
	MIMETYPE("wmv", "video/x-ms-wmv",0),
	MIMETYPE("xls","application/msexcel", 0),
	MIMETYPE("xml", "text/xml",0),
	MIMETYPE("zip", "application/x-zip-compressed", 0),
	MIMETYPE("zip", "application/zip",0),
	MIMETYPE("rar", "application/x-rar-compressed",0),
	MIMETYPE("file", "application/octet-stream",0),
	MIMETYPE("7zip", "application/x-7z-compressed",0),
	MIMETYPE("ace", "application/x-ace",0),
	MIMETYPE("ai", "application/illustrator",0),
	MIMETYPE("aiff", "audio/aiff",0),
	MIMETYPE("asp", "text/asp",0),
	MIMETYPE("avi", "video/msvideo",0),
	MIMETYPE("bat", "application/bat",0),
	MIMETYPE("bin", "application/octet-stream",0),
	MIMETYPE("exe", "application/octet-stream",0),
	MIMETYPE("dll", "application/x-msdownload",0),
	MIMETYPE("fla", "application/x-shockwave-flash",0),
	MIMETYPE("hqx", "application/binhex",0),
	MIMETYPE("midi","audio/mid",0),
	MIMETYPE("php","application/x-httpd-php",0),
	MIMETYPE("sit","application/stuffit",0),
	MIMETYPE("sitx","application/x-sit",0),
	MIMETYPE("jpg","image/jpeg",0),
	MIMETYPE("gif","image/gif",0),
	MIMETYPE("jpg","image/pjpeg",0),
	MIMETYPE("png","image/png",0),
	MIMETYPE("bmp","image/x-bitmap",0),
	MIMETYPE("psd","image/photoshop",0),
	MIMETYPE("psp","image/bmp",0),
END_MIMETYPE_TABLE;

MimeTableEntry*
Mime::SearchMimeType(MimeTableEntry* k, const char* ext)
{
	if(!ext)
		return NULL;
	while (k->Extension)
    {
		if (!strcasecmp((const char *)k->Extension, (const char*)ext))
			return k;
		k++;
	}
	return NULL;;
}

Mime*
Mime::GetInstance()
{
	if(!Instance)
		Instance = new Mime();

	return Instance;
}
