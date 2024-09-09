#pragma once

[::System::Runtime::InteropServices::UnmanagedFunctionPointer(::System::Runtime::InteropServices::CallingConvention::Cdecl)]
delegate void Action_();

static int64 ida_qatoll(IntPtr nptr)
{
	return atoll((const char*)(nptr.ToPointer()));
}

static uint32 ida_get_secs(qtime64_t t)
{
	return (uint32)(t >> 32);
}

static uint32 ida_get_usecs(qtime64_t t)
{
	return (uint32)(t);
}

static qtime64_t ida_make_qtime64(uint32 secs, int32 usecs)
{
	return ((qtime64_t)(secs) << 32) | usecs;
}

static bool ida_qctime(IntPtr buf, size_t bufsize, qtime32_t t)
{
	return qctime((char*)(buf.ToPointer()), bufsize, t);
}

static bool ida_qctime_utc(IntPtr buf, size_t bufsize, qtime32_t t)
{
	return qctime_utc((char*)(buf.ToPointer()), bufsize, t);
}

static bool ida_qlocaltime(IntPtr _tm, qtime32_t t)
{
	return qlocaltime((::tm*)(_tm.ToPointer()), t);
}

bool qlocaltime64(IntPtr _tm, qtime64_t t)
{
	return qlocaltime((::tm*)(_tm.ToPointer()), get_secs(t));
}

static bool ida_qgmtime(IntPtr _tm, qtime32_t t)
{
	return qgmtime((::tm*)(_tm.ToPointer()), t);
}

static bool ida_qgmtime64(IntPtr _tm, qtime64_t t)
{
	return qgmtime((::tm*)(_tm.ToPointer()), get_secs(t));
}

static int ida_qtimegm(IntPtr ptm)
{
	return qtimegm((const ::tm*)(ptm.ToPointer()));
}

static unsigned long long ida_qstrftime(IntPtr buf, size_t bufsize, IntPtr format, qtime32_t t)
{
	return qstrftime((char*)(buf.ToPointer()), bufsize, (const char*)(format.ToPointer()), t);
}

static unsigned long long ida_qstrftime64(IntPtr buf, size_t bufsize, IntPtr format, qtime64_t t)
{
	return qstrftime64((char*)(buf.ToPointer()), bufsize, (const char*)(format.ToPointer()), t);
}

static void ida_qsleep(int milliseconds)
{
	return qsleep(milliseconds);
}

static uint64 ida_get_nsec_stamp()
{
	return get_nsec_stamp();
}

static qtime64_t ida_qtime64()
{
	return qtime64();
}

static bool ida_gen_rand_buf(IntPtr buffer, size_t bufsz)
{
	return gen_rand_buf((void*)(buffer.ToPointer()), bufsz);
}

static error_t ida_set_qerrno(error_t code)
{
	return set_qerrno(code);
}

static error_t ida_get_qerrno()
{
	return get_qerrno();
}

static void ida_interr(int code)
{
	return interr(code);
}

static IntPtr ida_qalloc(size_t size)
{
	return IntPtr((void*)qalloc(size));
}

static IntPtr ida_qrealloc(IntPtr alloc, size_t newsize)
{
	return IntPtr((void*)qrealloc((void*)(alloc.ToPointer()), newsize));
}

static IntPtr ida_qcalloc(size_t nitems, size_t itemsize)
{
	return IntPtr((void*)qcalloc(nitems, itemsize));
}

static void ida_qfree(IntPtr alloc)
{
	return qfree((void*)(alloc.ToPointer()));
}

static IntPtr ida_qstrdup(IntPtr string)
{
	return IntPtr((void*)QT::qstrdup((const char*)(string.ToPointer())));
}

template <class T>
static IntPtr ida_qalloc_array(size_t n)
{
	return IntPtr(qcalloc(n, sizeof(T)));
}

template <class T>
static IntPtr ida_qrealloc_array(IntPtr ptr, size_t n)
{
	size_t nbytes = n * sizeof(T);
	if (nbytes < n)
		return nullptr; // integer overflow
	return IntPtr(qrealloc(ptr, nbytes));
}

static IntPtr ida_memrev(IntPtr buf, ssize_t size)
{
	return IntPtr((void*)memrev((void*)(buf.ToPointer()), size));
}

static IntPtr ida_strrpl(IntPtr str, int char1, int char2)
{
	return IntPtr((void*)strrpl((char*)(str.ToPointer()), char1, char2));
}

static IntPtr ida_tail(IntPtr str)
{
	return IntPtr((void*)(strchr((char*)(str.ToPointer()), '\0')));
}

static IntPtr ida_qstrncpy(IntPtr dst, IntPtr src, size_t dstsize)
{
	return IntPtr((void*)qstrncpy((char*)(dst.ToPointer()), (const char*)(src.ToPointer()), dstsize));
}

static IntPtr ida_qstpncpy(IntPtr dst, IntPtr src, size_t dstsize)
{
	return IntPtr((void*)qstpncpy((char*)(dst.ToPointer()), (const char*)(src.ToPointer()), dstsize));
}

static IntPtr ida_qstrncat(IntPtr dst, IntPtr src, size_t dstsize)
{
	return IntPtr((void*)qstrncat((char*)(dst.ToPointer()), (const char*)(src.ToPointer()), dstsize));
}

static IntPtr ida_qstrtok(IntPtr s, IntPtr delim, IntPtr save_ptr)
{
	return IntPtr((void*)qstrtok((char*)(s.ToPointer()), (const char*)(delim.ToPointer()), (char**)(save_ptr.ToPointer())));
}

static IntPtr ida_qstrlwr(IntPtr str)
{
	return IntPtr((void*)qstrlwr((char*)(str.ToPointer())));
}

static IntPtr ida_qstrupr(IntPtr str)
{
	return IntPtr((void*)qstrupr((char*)(str.ToPointer())));
}

static IntPtr ida_stristr(IntPtr s1, IntPtr s2)
{
	return IntPtr((void*)stristr((const char*)(s1.ToPointer()), (const char*)(s2.ToPointer())));
}

static bool ida_qisascii(char c)
{
	return (c & ~0x7f) == 0;
}

static bool ida_qisspace(char c)
{
	return qisascii(c) && isspace((uchar)(c)) != 0;
}

static bool ida_qisalpha(char c)
{
	return qisascii(c) && isalpha((uchar)(c)) != 0;
}

static bool ida_qisalnum(char c)
{
	return qisascii(c) && isalnum((uchar)(c)) != 0;
}

static bool ida_qispunct(char c)
{
	return qisascii(c) && ispunct((uchar)(c)) != 0;
}

static bool ida_qislower(char c)
{
	return qisascii(c) && islower((uchar)(c)) != 0;
}

static bool ida_qisupper(char c)
{
	return qisascii(c) && isupper((uchar)(c)) != 0;
}

static bool ida_qisprint(char c)
{
	return qisascii(c) && isprint((uchar)(c)) != 0;
}

static bool ida_qisdigit(char c)
{
	return qisascii(c) && isdigit((uchar)(c)) != 0;
}

static bool ida_qisxdigit(char c)
{
	return qisascii(c) && isxdigit((uchar)(c)) != 0;
}

static int ida_qtolower(char c)
{
	return tolower((uchar)(c));
}

static int ida_qtoupper(char c)
{
	return toupper((uchar)(c));
}

static int ida_qsnprintf(IntPtr buffer, size_t n, IntPtr format)
{
	return ::qsnprintf((char*)(buffer.ToPointer()), n, (const char*)(format.ToPointer()));
}

static int ida_qsscanf(IntPtr input, IntPtr format)
{
	return ::qsscanf((const char*)(input.ToPointer()), (const char*)(format.ToPointer()));
}

static int ida_qvsnprintf(IntPtr buffer, size_t n, IntPtr format)
{
	return ::qvsnprintf((char*)(buffer.ToPointer()), n, (const char*)(format.ToPointer()), NULL);
}

static int ida_qvsscanf(IntPtr input, IntPtr format)
{
	return ::qvsscanf((const char*)(input.ToPointer()), (const char*)(format.ToPointer()), NULL);
}

static int ida_append_snprintf(IntPtr buf, IntPtr end, IntPtr format)
{
	return append_snprintf((char*)(buf.ToPointer()), (const char*)(end.ToPointer()), (const char*)(format.ToPointer()));
}

static int ida_nowarn_qsnprintf(IntPtr buf, size_t size, IntPtr format)
{
	return ::qvsnprintf((char*)(buf.ToPointer()), size, (const char*)(format.ToPointer()), NULL);
}

static IntPtr ida_vqmakepath(IntPtr buf, size_t bufsize, IntPtr s1, char* p_3)
{
	return IntPtr((void*)vqmakepath((char*)(buf.ToPointer()), bufsize, (const char*)(s1.ToPointer()), p_3));
}

static IntPtr ida_qmakepath(IntPtr buf, size_t bufsize, IntPtr s1)
{
	return IntPtr((void*)qmakepath((char*)(buf.ToPointer()), bufsize, (const char*)(s1.ToPointer())));
}

static void ida_qgetcwd(IntPtr buf, size_t bufsize)
{
	return qgetcwd((char*)(buf.ToPointer()), bufsize);
}

static int ida_qchdir(IntPtr path)
{
	return qchdir((const char*)(path.ToPointer()));
}

static bool ida_qdirname(IntPtr buf, size_t bufsize, IntPtr path)
{
	return qdirname((char*)(buf.ToPointer()), bufsize, (const char*)(path.ToPointer()));
}

static IntPtr ida_qmakefile(IntPtr buf, size_t bufsize, IntPtr base, IntPtr ext)
{
	return IntPtr((void*)qmakefile((char*)(buf.ToPointer()), bufsize, (const char*)(base.ToPointer()), (const char*)(ext.ToPointer())));
}

static IntPtr ida_qsplitfile(IntPtr file, IntPtr base, IntPtr ext)
{
	return IntPtr((void*)qsplitfile((char*)(file.ToPointer()), (char**)(base.ToPointer()), (char**)(ext.ToPointer())));
}

static bool ida_qisabspath(IntPtr file)
{
	return qisabspath((const char*)(file.ToPointer()));
}

static IntPtr ida_qbasename(IntPtr path)
{
	return IntPtr((void*)qbasename((const char*)(path.ToPointer())));
}

static IntPtr ida_qmake_full_path(IntPtr dst, size_t dstsize, IntPtr src)
{
	return IntPtr((void*)qmake_full_path((char*)(dst.ToPointer()), dstsize, (const char*)(src.ToPointer())));
}

static bool ida_search_path(IntPtr buf, size_t bufsize, IntPtr file, bool search_cwd)
{
	return search_path((char*)(buf.ToPointer()), bufsize, (const char*)(file.ToPointer()), search_cwd);
}

static IntPtr ida_set_file_ext(IntPtr outbuf, size_t bufsize, IntPtr file, IntPtr ext)
{
	return IntPtr((void*)set_file_ext((char*)(outbuf.ToPointer()), bufsize, (const char*)(file.ToPointer()), (const char*)(ext.ToPointer())));
}

static IntPtr ida_get_file_ext(IntPtr file)
{
	return IntPtr((void*)get_file_ext((const char*)(file.ToPointer())));
}

static bool ida_has_file_ext(IntPtr file)
{
	return get_file_ext((const char*)(file.ToPointer())) != nullptr;
}

static IntPtr ida_make_file_ext(IntPtr buf, size_t bufsize, IntPtr file, IntPtr ext)
{
	if (has_file_ext((const char*)(file.ToPointer())))
		return IntPtr((void*)::qstrncpy((char*)(buf.ToPointer()), (const char*)(file.ToPointer()), bufsize));
	else
		return IntPtr((void*)set_file_ext((char*)(buf.ToPointer()), bufsize, (const char*)(file.ToPointer()), (const char*)(ext.ToPointer())));
}

static bool ida_sanitize_file_name(IntPtr name, size_t namesize)
{
	return sanitize_file_name((char*)(name.ToPointer()), namesize);
}

static int ida_qopen(IntPtr file, int mode)
{
	return qopen((const char*)(file.ToPointer()), mode);
}

static int ida_qopen_shared(IntPtr file, int mode, int share_mode)
{
	return qopen_shared((const char*)(file.ToPointer()), mode, share_mode);
}

static int ida_qcreate(IntPtr file, int stat)
{
	return qcreate((const char*)(file.ToPointer()), stat);
}

static int ida_qread(int h, IntPtr buf, size_t n)
{
	return qread(h, (void*)(buf.ToPointer()), n);
}

static int ida_qwrite(int h, IntPtr buf, size_t n)
{
	return qwrite(h, (const void*)(buf.ToPointer()), n);
}

static int64 ida_qtell(int h)
{
	return qtell(h);
}

static int64 ida_qseek(int h, int64 offset, int whence)
{
	return qseek(h, offset, whence);
}

static int ida_qclose(int h)
{
	return qclose(h);
}

static int ida_qdup(int h)
{
	return qdup(h);
}

static int ida_qfsync(int h)
{
	return qfsync(h);
}

static unsigned long long ida_qfilesize(IntPtr fname)
{
	return qfilesize((const char*)(fname.ToPointer()));
}

static uint64 ida_qfilelength(int h)
{
	return qfilelength(h);
}

static int ida_qchsize(int h, uint64 fsize)
{
	return qchsize(h, fsize);
}

static int ida_qmkdir(IntPtr file, int mode)
{
	return qmkdir((const char*)(file.ToPointer()), mode);
}

static int ida_qrmdir(IntPtr file)
{
	return qrmdir((const char*)(file.ToPointer()));
}

static bool ida_qfileexist(IntPtr file)
{
	return qfileexist((const char*)(file.ToPointer()));
}

static bool ida_qisdir(IntPtr file)
{
	return qisdir((const char*)(file.ToPointer()));
}

static int ida_qstat(IntPtr path, IntPtr buf)
{
	return qstat((const char*)(path.ToPointer()), (::qstatbuf*)(buf.ToPointer()));
}

static int ida_qfstat(int fd, IntPtr buf)
{
	return qfstat(fd, (::qstatbuf*)(buf.ToPointer()));
}

static void ida_qatexit(Action_^ func)
{
	return qatexit(static_cast<void (__stdcall*)()>(::System::Runtime::InteropServices::Marshal::GetFunctionPointerForDelegate(func).ToPointer()));
}

static void ida_del_qatexit(Action_^ func)
{
	return del_qatexit(static_cast<void(__stdcall*)()>(::System::Runtime::InteropServices::Marshal::GetFunctionPointerForDelegate(func).ToPointer()));
}

static void ida_qexit(int code)
{
	return qexit(code);
}

template <class T>
static T ida_qabs(T x)
{
	return qabs(x);
}

static bool ida_test_bit(IntPtr bitmap, size_t bit) 
{
	auto ubitmap = (const uchar*)(bitmap.ToPointer());
	return (ubitmap[bit / 8] & (1 << (bit & 7))) != 0;
}

static void ida_set_bit(IntPtr bitmap, size_t bit) 
{
	auto ubitmap = (uchar*)(bitmap.ToPointer());
	uchar* p = ubitmap + bit / 8;
	*p = (uchar)(*p | (1 << (bit & 7)));
}

static void ida_clear_bit(IntPtr bitmap, size_t bit)
{
	auto ubitmap = (uchar*)(bitmap.ToPointer());
	uchar* p = ubitmap + bit / 8;
	*p = (uchar)(*p & ~(1 << (bit & 7)));
}

static void ida_set_bits(IntPtr bitmap, size_t low, size_t high)
{
	size_t bit;
	for (bit = low; bit < high; ++bit)
		ida_set_bit(bitmap, bit);
}

static void ida_clear_bits(IntPtr bitmap, size_t low, size_t high) 
{
	size_t bit;
	for (bit = low; bit < high; ++bit)
		ida_clear_bit(bitmap, bit);
}

static void ida_set_all_bits(IntPtr bitmap, size_t nbits)
{
	auto ubitmap = (uchar*)(bitmap.ToPointer());
	memset(ubitmap, 0xFF, (nbits + 7) / 8);
	if ((nbits & 7) != 0)
	{
		uchar* p = ubitmap + nbits / 8;
		*p = (uchar)(*p & ~((1 << (nbits & 7)) - 1));
	}
}

static void ida_clear_all_bits(IntPtr bitmap, size_t nbits)
{
	auto ubitmap = (uchar*)(bitmap.ToPointer());
	memset(ubitmap, 0, (nbits + 7) / 8);
}

static int ida_log2ceil(uint64 d64)
{
	return log2ceil(d64);
}

static int ida_log2floor(uint64 d64)
{
	return log2floor(d64);
}

static int ida_bitcount(uint64 x)
{
	return bitcount(x);
}

static uint32 ida_round_up_power2(uint32 x)
{
	return round_up_power2(x);
}

static uint32 ida_round_down_power2(uint32 x)
{
	return round_down_power2(x);
}

template <class T>
static T ida_round_up(T val, T base)
{
	return round_up(val, base);
}

template <class T>
static T ida_round_down(T val, T base)
{
	return round_down(val, base);
}

template <class T>
static T ida_left_shift(IntPtr value, int shift)
{
	return left_shift((T&)(value.ToPointer()), shift);
}

template <class T>
static T ida_right_ushift(IntPtr value, int shift)
{
	return right_ushift((T&)(value.ToPointer()), shift);
}

template <class T>
static T ida_right_sshift(IntPtr value, int shift)
{
	return right_sshift((T&)(value.ToPointer()), shift);
}

template <class T>
static T ida_qrotl(T value, unsigned long long count)
{
	return qrotl(value, count);
}

template <class T>
static T ida_qrotr(T value, unsigned long long count)
{
	return qrotr(value, count);
}

template <class T>
static T ida_make_mask(int count)
{
	return make_mask(count);
}

template<class T, class U>
static void ida_setflag(IntPtr where, U bit, bool cnd)
{
	return setflag((T&)(where.ToPointer()), bit, cnd);
}

template <class T>
static bool ida_is_mul_ok(T count, T elsize)
{
	return is_mul_ok(count, elsize);
}

template<class T, class U>
static bool ida_is_add_ok(U x, T y)
{
	return is_add_ok(x, y);
}

template <class T>
static bool ida_is_udiv_ok(T p_0, T b)
{
	return is_udiv_ok(p_0, b);
}

template <class T>
static bool ida_is_sdiv_ok(T a, T b)
{
	return is_sdiv_ok(a, b);
}

static uint64 ida_extend_sign(uint64 v, int nbytes, bool sign_extend)
{
	return extend_sign(v, nbytes, sign_extend);
}

static int ida_readbytes(int h, IntPtr res, int size, bool mf)
{
	return readbytes(h, (unsigned int*)(res.ToPointer()), size, mf);
}

static int ida_writebytes(int h, uint32 l, int size, bool mf)
{
	return writebytes(h, l, size, mf);
}

static int ida_read2bytes(int h, IntPtr res, bool mf)
{
	return read2bytes(h, (unsigned short*)(res.ToPointer()), mf);
}

static unsigned int ida_swap32(unsigned int x)
{
	return (x >> 24) | (x << 24) | ((x >> 8) & 0x0000FF00L) | ((x << 8) & 0x00FF0000L);
}

static unsigned short ida_swap16(unsigned short x)
{
	return ushort((x << 8) | (x >> 8));
}

static void ida_swap_value(IntPtr dst, IntPtr src, int size)
{
	return swap_value((void*)(dst.ToPointer()), (const void*)(src.ToPointer()), size);
}

static void ida_reloc_value(IntPtr value, int size, adiff_t delta, bool mf)
{
	return reloc_value((void*)(value.ToPointer()), size, delta, mf);
}

static uval_t ida_rotate_left(uval_t x, int count, size_t bits, size_t offset)
{
	return rotate_left(x, count, bits, offset);
}

template <class T>
static void ida_qswap(T& a, T& b)
{
	qswap(a, b);
}

static IntPtr ida_pack_db(IntPtr ptr, IntPtr end, unsigned char x)
{
	auto uptr = (uchar*)(ptr.ToPointer());
	if (uptr < (uchar*)(end.ToPointer()))
		*uptr++ = x;
	return IntPtr((void*)uptr);
}

static unsigned char ida_unpack_db(IntPtr pptr, IntPtr end)
{
	auto upptr = (uchar**)(pptr.ToPointer());
	uchar* ptr = *upptr;
	uchar x = 0;
	if (ptr < (uchar*)(end.ToPointer()))
		x = *ptr++;
	*upptr = ptr;
	return x;
}

static IntPtr ida_pack_dw(IntPtr ptr, IntPtr end, unsigned short x)
{
	return IntPtr((void*)pack_dw((unsigned char*)(ptr.ToPointer()), (unsigned char*)(end.ToPointer()), x));
}

static IntPtr ida_pack_dd(IntPtr ptr, IntPtr end, unsigned int x)
{
	return IntPtr((void*)pack_dd((unsigned char*)(ptr.ToPointer()), (unsigned char*)(end.ToPointer()), x));
}

static IntPtr ida_pack_dq(IntPtr ptr, IntPtr end, unsigned long long x)
{
	return IntPtr((void*)pack_dq((unsigned char*)(ptr.ToPointer()), (unsigned char*)(end.ToPointer()), x));
}

static unsigned short ida_unpack_dw(IntPtr pptr, IntPtr end)
{
	return unpack_dw((const unsigned char**)(pptr.ToPointer()), (const unsigned char*)(end.ToPointer()));
}

static unsigned int ida_unpack_dd(IntPtr pptr, IntPtr end)
{
	return unpack_dd((const unsigned char**)(pptr.ToPointer()), (const unsigned char*)(end.ToPointer()));
}

static unsigned long long ida_unpack_dq(IntPtr pptr, IntPtr end)
{
	return unpack_dq((const unsigned char**)(pptr.ToPointer()), (const unsigned char*)(end.ToPointer()));
}

static IntPtr ida_pack_ea(IntPtr ptr, IntPtr end, ea_t ea)
{
	return IntPtr((void*)pack_dq((unsigned char*)(ptr.ToPointer()), (unsigned char*)(end.ToPointer()), ea));
}

static ea_t ida_unpack_ea(IntPtr ptr, IntPtr end)
{
	return unpack_dq((const unsigned char**)(ptr.ToPointer()), (unsigned char*)(end.ToPointer()));
}

static unsigned long long ida_unpack_ea64(IntPtr ptr, IntPtr end)
{
	return ida_unpack_dq(ptr, end) - 1;
}

static IntPtr ida_unpack_obj(IntPtr destbuf, size_t destsize, IntPtr pptr, IntPtr end)
{
	auto upptr = (const uchar**)(pptr.ToPointer());
	auto uend = (const uchar*)(end.ToPointer());
	const uchar* src = *upptr;
	const uchar* send = src + destsize;
	if (send < src || send > uend)
		return IntPtr::Zero;
	*upptr = send;
	return IntPtr(memcpy((void*)(destbuf.ToPointer()), src, destsize));
}

static IntPtr ida_unpack_buf(IntPtr pptr, IntPtr end)
{
	size_t size = ida_unpack_dd(pptr, end);
	if (size == 0)
		return IntPtr::Zero;
	auto upptr = (const uchar**)(pptr.ToPointer());
	auto uend = (const uchar*)(end.ToPointer());
	const uchar* src = *upptr;
	const uchar* srcend = src + size;
	if (srcend < src || srcend > uend)
		return IntPtr::Zero;
	void* dst = qalloc(size);
	if (dst != nullptr)
	{
		memcpy(dst, src, size);
		*upptr = srcend;
	}
	return IntPtr(dst);
}

static IntPtr ida_unpack_obj_inplace(IntPtr pptr, IntPtr end, size_t objsize)
{
	auto upptr = (const uchar**)(pptr.ToPointer());
	auto uend = (const uchar*)(end.ToPointer());
	const uchar* ret = *upptr;
	const uchar* rend = ret + objsize;
	if (rend < ret || rend > uend)
		return IntPtr::Zero;
	*upptr = rend;
	return IntPtr((void*)ret);
}

static IntPtr ida_unpack_buf_inplace(IntPtr pptr, IntPtr end)
{
	size_t objsize = ida_unpack_dd(pptr, end);
	return ida_unpack_obj_inplace(pptr, end, objsize);
}

static IntPtr ida_pack_ds(IntPtr ptr, IntPtr end, IntPtr x, size_t len)
{
	return IntPtr((void*)pack_ds((unsigned char*)(ptr.ToPointer()), (unsigned char*)(end.ToPointer()), (const char*)(x.ToPointer()), len));
}

static IntPtr ida_unpack_ds(IntPtr pptr, IntPtr end, bool empty_null)
{
	return IntPtr((void*)unpack_ds((const unsigned char**)(pptr.ToPointer()), (const unsigned char*)(end.ToPointer()), empty_null));
}

static bool ida_unpack_ds_to_buf(IntPtr dst, size_t dstsize, IntPtr pptr, IntPtr end)
{
	auto upptr = (const uchar**)(pptr.ToPointer());
	auto uend = (const uchar*)(end.ToPointer());
	const void* buf = ida_unpack_buf_inplace(pptr, end).ToPointer();
	if (buf == nullptr)
		return false;
	size_t size = *upptr - (const uchar*)buf;
	if (size >= dstsize)
		size = dstsize - 1;
	memcpy(dst.ToPointer(), buf, size);
	((char*)(dst.ToPointer()))[size] = '\0';
	return true;
}

static bool ida_unpack_xleb128(IntPtr res, int nbits, bool is_signed, IntPtr pptr, IntPtr end)
{
	return unpack_xleb128((void*)(res.ToPointer()), nbits, is_signed, (const unsigned char**)(pptr.ToPointer()), (const unsigned char*)(end.ToPointer()));
}

template <class T>
static bool ida_unpack_uleb128(T *res, IntPtr pptr, IntPtr end)
{
	return unpack_xleb128((void*)(res.ToPointer()), sizeof(T) * 8, false, pptr, end);
}

template <class T>
static bool ida_unpack_sleb128(IntPtr res, IntPtr pptr, IntPtr end)
{
	return unpack_xleb128((void*)(res.ToPointer()), sizeof(T) * 8, true, pptr, end);
}

static int ida_ds_packed_size(IntPtr s)
{
	auto us = (const char*)(s.ToPointer());
	return us ? int(strlen(us) + dd_packed_size) : 1;
}

static int ida_dw_size(unsigned char first_byte)
{
	return (first_byte & 0x80) == 0 ? 1
		: (first_byte & 0xC0) == 0xC0 ? 3
		: 2;
}

static int ida_dd_size(unsigned char first_byte)
{
	return (first_byte & 0x80) == 0x00 ? 1
		: (first_byte & 0xC0) != 0xC0 ? 2
		: (first_byte & 0xE0) == 0xE0 ? 5
		: 4;
}

template <class T>
static unsigned char ida_extract_db(T& v)
{
	uchar x = 0;
	v.read(&x, 1);
	return x;
}

template <class T>
static IntPtr ida_extract_obj(T& v, IntPtr destbuf, size_t destsize)
{
	if (destsize == 0)
		return IntPtr::Zero;
	return v.read(destbuf, destsize) == destsize ? destbuf : IntPtr::Zero;
}

template <class T>
static unsigned short ida_extract_dw(T& v)
{
	uchar packed[dw_packed_size];
	packed[0] = extract_db(v);
	int psize = dw_size(packed[0]);
	extract_obj(v, &packed[1], psize - 1);
	const uchar* ptr = packed;
	return unpack_dw(&ptr, packed + psize);
}

template <class T>
static unsigned int ida_extract_dd(T& v)
{
	uchar packed[dd_packed_size];
	packed[0] = extract_db(v);
	int psize = dd_size(packed[0]);
	extract_obj(v, &packed[1], psize - 1);
	const uchar* ptr = packed;
	return unpack_dd(&ptr, packed + psize);
}

template <class T>
static unsigned long long ida_extract_dq(T& v) 
{
	uint32 l = extract_dd(v);
	uint32 h = extract_dd(v);
	return make_ulonglong(l, h);
}

template <class T>
static ea_t ida_extract_ea(T& v)
{
	return extract_dq(v);
}

template <class T>
static IntPtr ida_extract_buf(T& v, size_t size)
{
	void* buf = qalloc(size);
	if (buf == nullptr)
		return IntPtr::Zero;
	return IntPtr(extract_obj(v, buf, size));
}

template <class T>
static IntPtr ida_extract_array(T& v, IntPtr sz, size_t maxsize)
{
	size_t size = extract_dd(v);
	if (size == 0 || size > maxsize)
		return IntPtr::Zero;
	*(size_t*)(sz.ToPointer()) = size;
	return IntPtr(extract_buf(v, size));
}

static IntPtr ida_unpack_str(IntPtr pptr, IntPtr end) 
{
	auto upptr = (const uchar**)(pptr.ToPointer());
	auto uend = (const uchar*)(end.ToPointer());
	const uchar* ptr = *upptr;
	const uchar* str = ptr;
	do
		if (ptr >= uend)
			return IntPtr::Zero; // no terminating zero?
	while (*ptr++ != '\0');
	*upptr = ptr;
	return IntPtr((void*)str);
}

static IntPtr ida_qalloc_or_throw(size_t size)
{
	return IntPtr((void*)qalloc_or_throw(size));
}

static IntPtr ida_qrealloc_or_throw(IntPtr ptr, size_t size)
{
	return IntPtr((void*)qrealloc_or_throw((void*)(ptr.ToPointer()), size));
}

static IntPtr ida_qvector_reserve(IntPtr vec, IntPtr old, size_t cnt, size_t elsize)
{
	return IntPtr((void*)qvector_reserve((void*)(vec.ToPointer()), (void*)(old.ToPointer()), cnt, elsize));
}

template <class T> 
ref struct ida_movable_type
{
	static constexpr bool value = std::is_pod<T>::value;
};

template <class T>
static bool ida_may_move_bytes()
{
	return ida_movable_type<T>::value;
}

template<class T>
static void ida_shift_down(IntPtr dst, IntPtr src, size_t cnt)
{
	if (may_move_bytes<T>())
	{
		memmove((T*)(dst.ToPointer()), (T*)(src.ToPointer()), cnt * sizeof(T));
	}
	else
	{
		ssize_t s = cnt;
		while (--s >= 0)
		{
			new(((T*)(dst.ToPointer()))) T(std::move(*((T*)(src.ToPointer()))));
			((T*)(src.ToPointer()))->~T();
			++((T*)(src.ToPointer()));
			++((T*)(dst.ToPointer()));
		}
	}
}

template<class T>
static void ida_shift_up(IntPtr dst, IntPtr src, unsigned long long cnt)
{
	if (may_move_bytes<T>())
	{
		memmove((T*)(dst.ToPointer()), (T*)(src.ToPointer()), cnt * sizeof(T));
	}
	else
	{
		ssize_t s = cnt;
		((T*)(dst.ToPointer())) += s;
		((T*)(src.ToPointer())) += s;
		while (--s >= 0)
		{
			--((T*)(src.ToPointer()));
			--((T*)(dst.ToPointer()));
			new(((T*)(dst.ToPointer()))) T(std::move(*((T*)(src.ToPointer()))));
			((T*)(src.ToPointer()))->~T();
		}
	}
}

template <class T>
static int ida_lexcompare(IntPtr a, IntPtr b)
{
	return lexcompare(*(T*)(a.ToPointer()), *(T*)(b.ToPointer()));
}

template <class T>
static int ida_lexcompare_vectors(IntPtr a, IntPtr b)
{
	return lexcompare_vectors(*(T*)(a.ToPointer()), *(T*)(b.ToPointer()));
}

static size_t ida_qstrlen(IntPtr s)
{
	return ::strlen((const char*)(s.ToPointer()));
}

static size_t ida_qstrlen_u(IntPtr s)		// s points to const uchar*
{
	return ::strlen((const char*)(s.ToPointer()));
}

static size_t ida_qstrlen_w(IntPtr s)		// s points to const wchar_t*
{
	return qstrlen((const wchar_t*)(s.ToPointer()));
}

static int ida_qstrcmp(IntPtr s1, IntPtr s2) 
{
	return ::strcmp((const char*)(s1.ToPointer()), (const char*)(s2.ToPointer()));
}

static int ida_qstrcmp_u(IntPtr s1, IntPtr s2)		// s1 & s2 pointing to const uchar*
{
	return ::strcmp((const char*)(s1.ToPointer()), (const char*)(s2.ToPointer()));
}

static int ida_qstrcmp_w(IntPtr s1, IntPtr s2)		// s1 & s2 pointing to const wchar_t*
{
	return qstrcmp((const wchar_t*)(s1.ToPointer()), (const wchar_t*)(s2.ToPointer()));
}

static IntPtr ida_qstrstr(IntPtr s1, IntPtr s2)
{
	return IntPtr((void*)::strstr((const char*)(s1.ToPointer()), (const char*)(s2.ToPointer())));
}

static IntPtr ida_qstrstr_u(IntPtr s1, IntPtr s2)		// s1 & s2 pointing to const uchar*
{
	return IntPtr((void*)::strstr((const char*)(s1.ToPointer()), (const char*)(s2.ToPointer())));
}

static IntPtr ida_qstrchr(IntPtr s1, char c)
{
	return IntPtr((void*)::strchr((char*)(s1.ToPointer()), c));
}

static IntPtr ida_qstrchr_w(IntPtr s1, wchar_t c)
{
	return IntPtr((void*)qstrchr((const wchar_t*)(s1.ToPointer()), c));
}

static IntPtr ida_qstrrchr(IntPtr s1, char c)
{
	return IntPtr((void*)::strrchr((char*)(s1.ToPointer()), c));
}

static IntPtr ida_qstrrchr(IntPtr s1, wchar_t c)
{
	return IntPtr((void*)qstrrchr((const wchar_t*)(s1.ToPointer()), c));
}

static bool ida_relocate_relobj(IntPtr _relobj, ea_t ea, bool mf)
{
	return relocate_relobj((::relobj_t*)(_relobj.ToPointer()), ea, mf);
}

//static void ida_unpack_eavec(IntPtr vec, ea_t ea, IntPtr ptr, IntPtr end) // inline
//{
//	...
//}
//
//static bool ida_unpack_bytevec(IntPtr out, IntPtr pptr, IntPtr end) // inline
//{
//	...
//}
//
//static bool ida_unpack_str(IntPtr out, IntPtr pptr, IntPtr end) // inline
//{
//	...
//}

// ????
 
template <class T> 
T ida_align_up(T val, int elsize)
{
	return align_up(val, elsize);
}

//-------------------------------------------------------------------------
/// Align element down to nearest boundary
template <class T> 
T ida_align_down(T val, int elsize)
{
	return align_down(val, elsize);
}

// mircea, tbc

static bool ida_is_cp_graphical(wchar32_t cp)
{
	return is_cp_graphical(cp);
}

static tty_control_t ida_is_control_tty(int fd)
{
	return is_control_tty(fd);
}

static void ida_qdetach_tty()
{
	return qdetach_tty();
}

static void ida_qcontrol_tty()
{
	return qcontrol_tty();
}

static void ida_qthread_free(qthread_t q)
{
	return qthread_free(q);
}

static bool ida_qthread_join(qthread_t q)
{
	return qthread_join(q);
}

static bool ida_qthread_kill(qthread_t q)
{
	return qthread_kill(q);
}

static qthread_t ida_qthread_self()
{
	return qthread_self();
}

static bool ida_qthread_same(qthread_t q)
{
	return qthread_same(q);
}

static bool ida_qthread_equal(qthread_t q1, qthread_t q2)
{
	return qthread_equal(q1, q2);
}

static bool ida_is_main_thread()
{
	return is_main_thread();
}

static bool ida_qsem_free(qsemaphore_t sem)
{
	return qsem_free(sem);
}

static bool ida_qsem_post(qsemaphore_t sem)
{
	return qsem_post(sem);
}

static bool ida_qsem_wait(qsemaphore_t sem, int timeout_ms)
{
	return qsem_wait(sem, timeout_ms);
}

static bool ida_qmutex_free(qmutex_t m)
{
	return qmutex_free(m);
}

static qmutex_t ida_qmutex_create()
{
	return qmutex_create();
}

static bool ida_qmutex_lock(qmutex_t m)
{
	return qmutex_lock(m);
}

static bool ida_qmutex_unlock(qmutex_t m)
{
	return qmutex_unlock(m);
}

static int ida_qpipe_create(qhandle_t handles[2])
{
	return qpipe_create(handles);
}

static int ida_qpipe_close(qhandle_t handle)
{
	return qpipe_close(handle);
}

