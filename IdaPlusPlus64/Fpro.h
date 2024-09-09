#pragma once

// complete ???

[::System::Runtime::InteropServices::UnmanagedFunctionPointer(::System::Runtime::InteropServices::CallingConvention::Cdecl)]
delegate bool Func_bool_UInt64_UInt64___IntPtr(unsigned long long pos, unsigned long long total, ::System::IntPtr ud);

static IntPtr ida_qfopen(IntPtr file, IntPtr mode)
{
	return IntPtr((void*)qfopen((const char*)(file.ToPointer()), (const char*)(mode.ToPointer())));
}

static ssize_t ida_qfread(IntPtr fp, IntPtr buf, size_t n)
{
	return qfread((FILE*)(fp.ToPointer()), (void*)(buf.ToPointer()), n);
}

static ssize_t ida_qfwrite(IntPtr fp, IntPtr buf, size_t n)
{
	return qfwrite((FILE*)(fp.ToPointer()), (const void*)(buf.ToPointer()), n);
}

static int64 ida_qftell(IntPtr fp)
{
	return qftell((FILE*)(fp.ToPointer()));
}

static int ida_qfseek(IntPtr fp, int64 offset, int whence)
{
	return qfseek((FILE*)(fp.ToPointer()), offset, whence);
}

static int ida_qfclose(IntPtr fp)
{
	return qfclose((FILE*)(fp.ToPointer()));
}

static int ida_qflush(IntPtr fp)
{
	return qflush((FILE*)(fp.ToPointer()));
}

static int ida_qfputc(int chr, IntPtr fp)
{
	return qfputc(chr, (FILE*)(fp.ToPointer()));
}

static int ida_qfgetc(IntPtr fp)
{
	return qfgetc((FILE*)(fp.ToPointer()));
}

static IntPtr ida_qfgets(IntPtr s, size_t len, IntPtr fp)
{
	return IntPtr((void*)qfgets((char*)(s.ToPointer()), len, (FILE*)(fp.ToPointer())));
}

static int ida_qfputs(IntPtr s, IntPtr fp)
{
	return qfputs((const char*)(s.ToPointer()), (FILE*)(fp.ToPointer()));
}

static IntPtr ida_qtmpfile()
{
	return IntPtr((void*)qtmpfile());
}

static int ida_qunlink(IntPtr fname)
{
	return qunlink((const char*)(fname.ToPointer()));
}

static int ida_qaccess(IntPtr fname, int mode)
{
	return qaccess((const char*)(fname.ToPointer()), mode);
}

static IntPtr ida_qgets(IntPtr line, size_t linesize)
{
	return IntPtr((void*)qgets((char*)(line.ToPointer()), linesize));
}

static uint64 ida_qfsize(IntPtr fp)
{
	return qfsize((FILE*)(fp.ToPointer()));
}

static int ida_qvfprintf(IntPtr fp, IntPtr format)
{
	return qvfprintf((FILE*)(fp.ToPointer()), (const char*)(format.ToPointer()), nullptr);
}

static int ida_qvprintf(IntPtr format)
{
	return qvprintf((const char*)(format.ToPointer()), nullptr);
}

static int ida_qveprintf(IntPtr format)
{
	return qveprintf((const char*)(format.ToPointer()), nullptr);
}

static int ida_qvfscanf(IntPtr fp, IntPtr format)
{
	return qvfscanf((FILE*)(fp.ToPointer()), (const char*)(format.ToPointer()), nullptr);
}

static int ida_qfprintf(IntPtr fp, IntPtr format)
{
	return qvfprintf((FILE*)(fp.ToPointer()), (const char*)(format.ToPointer()), nullptr);
}

static int ida_qprintf(IntPtr format)
{
	return qvprintf((const char*)(format.ToPointer()), nullptr);
}

static int ida_qeprintf(IntPtr format)
{
	return qveprintf((const char*)(format.ToPointer()), nullptr);
}

static int ida_qfscanf(IntPtr fp, IntPtr format)
{
	return qvfscanf((FILE*)(fp.ToPointer()), (const char*)(format.ToPointer()), nullptr);
}

static ssize_t ida_qgetline(IntPtr buf, IntPtr fp)
{
	return qgetline((qstring*)(buf.ToPointer()), (FILE*)(fp.ToPointer()));
}

static int ida_qrename(IntPtr oldfname, IntPtr newfname)
{
	return qrename((const char*)(oldfname.ToPointer()), (const char*)(newfname.ToPointer()));
}

static int ida_qmove(IntPtr oldfname, IntPtr newfname, uint32 flags)
{
	return qmove((const char*)(oldfname.ToPointer()), (const char*)(newfname.ToPointer()), flags);
}

static int ida_qcopyfile(IntPtr from, IntPtr to, bool overwrite, Func_bool_UInt64_UInt64___IntPtr^ cb, IntPtr ud, int flags)
{
	return qcopyfile((const char*)(from.ToPointer()), (const char*)(to.ToPointer()), overwrite, static_cast<bool (*)(uint64, uint64, void*)>(::System::Runtime::InteropServices::Marshal::GetFunctionPointerForDelegate(cb).ToPointer()), (void*)(ud.ToPointer()), flags);
}

static IntPtr ida_qtmpdir(IntPtr buf, size_t bufsize)
{
	return IntPtr((void*)qtmpdir((char*)(buf.ToPointer()), bufsize));
}

static IntPtr ida_qtmpnam(IntPtr buf, size_t bufsize)
{
	return IntPtr((void*)qtmpnam((char*)(buf.ToPointer()), bufsize));
}

static int ida_freadbytes(IntPtr fp, IntPtr res, int size, int mostfirst)
{
	return freadbytes((FILE*)(fp.ToPointer()), (void*)(res.ToPointer()), size, mostfirst);
}

static int ida_fwritebytes(IntPtr fp, IntPtr l, int size, int mostfirst)
{
	return fwritebytes((FILE*)(fp.ToPointer()), (const void*)(l.ToPointer()), size, mostfirst);
}

static int ida_fread2bytes(IntPtr fp, IntPtr res, bool mostfirst)
{
	return freadbytes((FILE*)(fp.ToPointer()), (void*)(res.ToPointer()), 2, mostfirst);
}

static int ida_fwrite2bytes(IntPtr fp, IntPtr res, bool mostfirst)
{
	return fwritebytes((FILE*)(fp.ToPointer()), (const void*)(res.ToPointer()), 2, mostfirst);
}

static int ida_fread4bytes(IntPtr fp, IntPtr res, bool mostfirst)
{
	return freadbytes((FILE*)(fp.ToPointer()), (void*)(res.ToPointer()), 4, mostfirst);
}

static int ida_fwrite4bytes(IntPtr fp, IntPtr res, bool mostfirst)
{
	return fwritebytes((FILE*)(fp.ToPointer()), (const void*)(res.ToPointer()), 4, mostfirst);
}

static int ida_fread8bytes(IntPtr fp, IntPtr res, bool mostfirst)
{
	return freadbytes((FILE*)(fp.ToPointer()), (void*)(res.ToPointer()), 8, mostfirst);
}

static int ida_fwrite8bytes(IntPtr fp, IntPtr res, bool mostfirst)
{
	return fwritebytes((FILE*)(fp.ToPointer()), (const void*)(res.ToPointer()), 8, mostfirst);
}

