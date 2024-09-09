#pragma once 

// complete

static int ida_qregcomp(IntPtr preg, IntPtr pattern, int cflags)
{
	return qregcomp((::regex_t*)(preg.ToPointer()), (const char*)(pattern.ToPointer()), cflags);
}

static unsigned long long ida_qregerror(int errcode, IntPtr preg, IntPtr errbuf, unsigned long long errbuf_size)
{
	return qregerror(errcode, (const ::regex_t*)(preg.ToPointer()), (char*)(errbuf.ToPointer()), errbuf_size);
}

static int ida_qregexec(IntPtr preg, IntPtr str, unsigned long long nmatch, cli::array<regmatch_t*>^ pmatch, int eflags)
{
	pin_ptr<regmatch_t*> pmatchPtr = &pmatch[0];
	return qregexec((const ::regex_t*)(preg.ToPointer()), (const char*)(str.ToPointer()), nmatch, (regmatch_t*)(pmatchPtr), eflags);
}

static void ida_qregfree(IntPtr preg)
{
	return qregfree((::regex_t*)(preg.ToPointer()));
}

#ifdef OBSOLETE_FUNC
static int ida_regcomp(IntPtr preg, IntPtr pattern, int cflags)
{
	return regcomp((::regex_t*)(preg.ToPointer()), (const char*)(pattern.ToPointer()), cflags);
}

static unsigned long long ida_regerror(int errcode, IntPtr preg, IntPtr errbuf, unsigned long long errbuf_size)
{
	return regerror(errcode, (const ::regex_t*)(preg.ToPointer()), (char*)(errbuf.ToPointer()), errbuf_size);
}

static int ida_regexec(IntPtr preg, IntPtr str, unsigned long long nmatch, cli::array<regmatch_t*>^ pmatch, int eflags)
{
	pin_ptr<regmatch_t*> pmatchPtr = &pmatch[0];
	return regexec((const ::regex_t*)(preg.ToPointer()), (const char*)(str.ToPointer()), nmatch, (regmatch_t*)(pmatchPtr), eflags);
}

static void ida_regfree(IntPtr preg)
{
	return regfree((::regex_t*)(preg.ToPointer()));
}
#endif
