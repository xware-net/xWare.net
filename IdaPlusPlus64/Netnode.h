#pragma once

static bool ida_exist(IntPtr n)
{
	return netnode_exist(*(netnode*)(n.ToPointer()));
}

static bool ida_netnode_check(IntPtr node, IntPtr name, size_t namlen, bool create)
{
	return netnode_check((netnode*)(node.ToPointer()), (char*)(name.ToPointer()), namlen, create);
}

static void ida_netnode_kill(IntPtr node)
{
	netnode_kill((netnode*)(node.ToPointer()));
}

static bool ida_netnode_start(IntPtr node)
{
	return netnode_start((netnode*)(node.ToPointer()));
}

static bool ida_netnode_end(IntPtr node)
{
	return netnode_end((netnode*)(node.ToPointer()));
}

static bool ida_netnode_next(IntPtr node)
{
	return netnode_next((netnode*)(node.ToPointer()));
}

static bool ida_netnode_prev(IntPtr node)
{
	return netnode_prev((netnode*)(node.ToPointer()));
}

static ssize_t ida_netnode_get_name(nodeidx_t num, IntPtr out)
{
	qstring buf;
	ssize_t len = netnode_get_name(num, &buf);
	if (out == IntPtr::Zero)
	{
		return len;
	}

	::ConvertQstringToIntPtr(buf, out, len);
	return len;
}

static bool ida_netnode_rename(nodeidx_t num, IntPtr newname, size_t namlen)
{
	return netnode_rename(num, (char*)(newname.ToPointer()), namlen);
}

static ssize_t ida_netnode_valobj(nodeidx_t num, IntPtr buf, size_t bufsize)
{
	return netnode_valobj(num, (void*)(buf.ToPointer()), bufsize);
}

static ssize_t ida_netnode_valstr(nodeidx_t num, IntPtr buf, size_t bufsize)
{
	return netnode_valstr(num, (char*)(buf.ToPointer()), bufsize);
}

static ssize_t ida_netnode_qvalstr(nodeidx_t num, IntPtr buf)
{
	qstring qstr;
	auto len = netnode_qvalstr(num, &qstr);
	if (buf == IntPtr::Zero)
	{
		return len;
	}

	::ConvertQstringToIntPtr(qstr, buf, len);
	return len;
}

static bool ida_netnode_set(nodeidx_t num, IntPtr value, size_t length)
{
	return netnode_set(num, (void*)(value.ToPointer()), length);
}

static bool ida_netnode_delvalue(nodeidx_t num)
{
	return netnode_delvalue(num);
}

static nodeidx_t ida_netnode_altval(nodeidx_t num, nodeidx_t alt, int tag)
{
	return netnode_altval(num, alt, tag);
}

static uchar ida_netnode_charval(nodeidx_t num, nodeidx_t alt, int tag)
{
	return netnode_charval(num, alt, tag);
}

static nodeidx_t ida_netnode_altval_idx8(nodeidx_t num, uchar alt, int tag)
{
	return netnode_altval_idx8(num, alt, tag);
}

static uchar ida_netnode_charval_idx8(nodeidx_t num, uchar alt, int tag)
{
	return netnode_charval_idx8(num, alt, tag);
}

static ssize_t ida_netnode_supval(nodeidx_t num, nodeidx_t alt, IntPtr buf, size_t bufsize, int tag)
{
	return netnode_supval(num, alt, (void*)(buf.ToPointer()), bufsize, tag);
}

static ssize_t ida_netnode_supstr(nodeidx_t num, nodeidx_t alt, IntPtr buf, size_t bufsize, int tag)
{
	return netnode_supstr(num, alt, (char*)(buf.ToPointer()), bufsize, tag);
}

static ssize_t ida_netnode_qsupstr(nodeidx_t num, IntPtr buf, nodeidx_t alt, int tag)
{
	qstring qstr;
	auto len = netnode_qsupstr(num, &qstr, alt, tag);
	if (buf == IntPtr::Zero)
	{
		return len;
	}

	::ConvertQstringToIntPtr(qstr, buf, len);
	return len;
}

static bool ida_netnode_supset(nodeidx_t num, nodeidx_t alt, IntPtr value, size_t length, int tag)
{
	return netnode_supset(num, alt, (void*)(value.ToPointer()), length, tag);
}

static bool ida_netnode_supdel(nodeidx_t num, nodeidx_t alt, int tag)
{
	return netnode_supdel(num, alt, tag);
}

static nodeidx_t ida_netnode_lower_bound(nodeidx_t num, nodeidx_t cur, int tag)
{
	return netnode_lower_bound(num, cur, tag);
}

static nodeidx_t ida_netnode_supfirst(nodeidx_t num, int tag)
{
	return netnode_supfirst(num, tag);
}

static nodeidx_t ida_netnode_supnext(nodeidx_t num, nodeidx_t cur, int tag)
{
	return netnode_supnext(num, cur, tag);
}

static nodeidx_t ida_netnode_suplast(nodeidx_t num, int tag)
{
	return netnode_suplast(num, tag);
}

static nodeidx_t ida_netnode_supprev(nodeidx_t num, nodeidx_t cur, int tag)
{
	return netnode_supprev(num, cur, tag);
}

static ssize_t ida_netnode_supval_idx8(nodeidx_t num, unsigned char alt, IntPtr buf, size_t bufsize, int tag)
{
	return netnode_supval_idx8(num, alt, (void*)(buf.ToPointer()), bufsize, tag);
}

static ssize_t ida_netnode_supstr_idx8(nodeidx_t num, unsigned char alt, IntPtr buf, size_t bufsize, int tag)
{
	return netnode_supstr_idx8(num, alt, (char*)(buf.ToPointer()), bufsize, tag);
}

static ssize_t ida_netnode_qsupstr_idx8(nodeidx_t num, IntPtr buf, unsigned char alt, int tag)
{
	qstring qstr;
	auto len = netnode_qsupstr_idx8(num, &qstr, alt, tag);
	if (buf == IntPtr::Zero)
	{
		return len;
	}

	::ConvertQstringToIntPtr(qstr, buf, len);
	return len;
}

static bool ida_netnode_supset_idx8(nodeidx_t num, uchar alt, IntPtr value, size_t length, int tag)
{
	return netnode_supset_idx8(num, alt, (void*)(value.ToPointer()), length, tag);
}

static bool ida_netnode_supdel_idx8(nodeidx_t num, uchar alt, int tag)
{
	return netnode_supdel_idx8(num, alt, tag);
}

static nodeidx_t ida_netnode_lower_bound_idx8(nodeidx_t num, uchar alt, int tag)
{
	return netnode_lower_bound_idx8(num, alt, tag);
}

static nodeidx_t ida_netnode_supfirst_idx8(nodeidx_t num, int tag)
{
	return netnode_supfirst_idx8(num, tag);
}

static nodeidx_t ida_netnode_supnext_idx8(nodeidx_t num, uchar alt, int tag)
{
	return netnode_supnext_idx8(num, alt, tag);
}

static nodeidx_t ida_netnode_suplast_idx8(nodeidx_t num, int tag)
{
	return netnode_suplast_idx8(num, tag);
}

static nodeidx_t ida_netnode_supprev_idx8(nodeidx_t num, uchar alt, int tag)
{
	return netnode_supprev_idx8(num, alt, tag);
}

static bool ida_netnode_supdel_all(nodeidx_t num, int tag)
{
	return netnode_supdel_all(num, tag);
}

static int ida_netnode_supdel_range(nodeidx_t num, nodeidx_t idx1, nodeidx_t idx2, int tag)
{
	return netnode_supdel_range(num, idx1, idx2, tag);
}

static int ida_netnode_supdel_range_idx8(nodeidx_t num, nodeidx_t idx1, nodeidx_t idx2, int tag)
{
	return netnode_supdel_range_idx8(num, idx1, idx2, tag);
}

static ssize_t ida_netnode_hashval(nodeidx_t num, IntPtr idx, IntPtr buf, size_t bufsize, int tag)
{
	return netnode_hashval(num, (char*)(idx.ToPointer()), (void*)(buf.ToPointer()), bufsize, tag);
}

static ssize_t ida_netnode_hashstr(nodeidx_t num, IntPtr idx, IntPtr buf, size_t bufsize, int tag)
{
	return netnode_hashstr(num, (const char*)(idx.ToPointer()), (char*)(buf.ToPointer()), bufsize, tag);
}

static ssize_t ida_netnode_qhashstr(nodeidx_t num, IntPtr buf, IntPtr idx, int tag)
{
	qstring qstr;
	auto len = netnode_qhashstr(num, &qstr, (const char*)(idx.ToPointer()), tag);
	if (buf == IntPtr::Zero)
	{
		return len;
	}

	::ConvertQstringToIntPtr(qstr, buf, len);
	return len;
}

static nodeidx_t ida_netnode_hashval_long(nodeidx_t num, IntPtr idx, int tag)
{
	return netnode_hashval_long(num, (const char*)(idx.ToPointer()), tag);
}

static bool ida_netnode_hashset(nodeidx_t num, IntPtr idx, IntPtr value, size_t length, int tag)
{
	return netnode_hashset(num, (const char*)(idx.ToPointer()), (const void*)(value.ToPointer()), length, tag);
}

static bool ida_netnode_hashdel(nodeidx_t num, IntPtr idx, int tag)
{
	return netnode_hashdel(num, (const char*)(idx.ToPointer()), tag);
}

static ssize_t ida_netnode_hashfirst(nodeidx_t num, IntPtr buf, size_t bufsize, int tag)
{
	return netnode_hashfirst(num, (char*)(buf.ToPointer()), bufsize, tag);
}

static ssize_t ida_netnode_qhashfirst(nodeidx_t num, IntPtr buf, int tag)
{
	qstring qstr;
	auto len = netnode_qhashfirst(num, &qstr, tag);
	if (buf == IntPtr::Zero)
	{
		return len;
	}

	::ConvertQstringToIntPtr(qstr, buf, len);
	return len;
}

static ssize_t ida_netnode_hashnext(nodeidx_t num, IntPtr idx, IntPtr buf, size_t bufsize, int tag)
{
	return netnode_hashnext(num, (char*)(idx.ToPointer()), (char*)(buf.ToPointer()), bufsize, tag);
}

static ssize_t ida_netnode_qhashnext(nodeidx_t num, IntPtr buf, IntPtr idx, int tag)
{
	qstring qstr;
	auto len = netnode_qhashnext(num, &qstr, (const char*)(idx.ToPointer()), tag);
	if (buf == IntPtr::Zero)
	{
		return len;
	}

	::ConvertQstringToIntPtr(qstr, buf, len);
	return len;
}

static ssize_t ida_netnode_hashlast(nodeidx_t num, IntPtr buf, size_t bufsize, int tag)
{
	return netnode_hashlast(num, (char*)(buf.ToPointer()), bufsize, tag);
}

static ssize_t ida_netnode_qhashlast(nodeidx_t num, IntPtr buf, int tag)
{
	qstring qstr;
	auto len = netnode_qhashlast(num, &qstr, tag);
	if (buf == IntPtr::Zero)
	{
		return len;
	}

	::ConvertQstringToIntPtr(qstr, buf, len);
	return len;
}

static ssize_t ida_netnode_hashprev(nodeidx_t num, IntPtr idx, IntPtr buf, size_t bufsize, int tag)
{
	return netnode_hashprev(num, (char*)(idx.ToPointer()), (char*)(buf.ToPointer()), bufsize, tag);
}

static ssize_t ida_netnode_qhashprev(nodeidx_t num, IntPtr buf, IntPtr idx, int tag)
{
	qstring qstr;
	auto len = netnode_qhashprev(num, &qstr, (const char*)(idx.ToPointer()), tag);
	if (buf == IntPtr::Zero)
	{
		return len;
	}

	::ConvertQstringToIntPtr(qstr, buf, len);
	return len;
}

static size_t ida_netnode_blobsize(nodeidx_t num, nodeidx_t start, int tag)
{
	return netnode_blobsize(num, start, tag);
}

static IntPtr ida_netnode_getblob(nodeidx_t num, IntPtr buf, size_t% bufsize, nodeidx_t start, int tag)
{
	return IntPtr(netnode_getblob(num, (void*)(buf.ToPointer()), (size_t*)bufsize, start, tag));
}

//static ssize_t ida_netnode_qgetblob(nodeidx_t num, IntPtr buf, size_t elsize, nodeidx_t start, int tag)
//{
//	return netnode_qgetblob(num, (::bytevec_t*)(buf.ToPointer()), elsize, start, tag);
//}

static bool ida_netnode_setblob(nodeidx_t num, IntPtr buf, size_t size, nodeidx_t start, int tag)
{
	return netnode_setblob(num, (void*)(buf.ToPointer()), size, start, tag);
}

static int ida_netnode_delblob(nodeidx_t num, nodeidx_t start, int tag)
{
	return netnode_delblob(num, start, tag);
}

static bool ida_netnode_inited()
{
	return netnode_inited();
}

static bool ida_netnode_is_available()
{
	return netnode_is_available();
}

static size_t ida_netnode_copy(nodeidx_t num, nodeidx_t count, nodeidx_t target, bool move)
{
	return netnode_copy(num, count, target, move);
}

static size_t ida_netnode_altshift(nodeidx_t num, nodeidx_t from, nodeidx_t to, nodeidx_t size, int tag)
{
	return netnode_altshift(num, from, to, size, tag);
}

static size_t ida_netnode_charshift(nodeidx_t num, nodeidx_t from, nodeidx_t to, nodeidx_t size, int tag)
{
	return netnode_charshift(num, from, to, size, tag);
}

static size_t ida_netnode_supshift(nodeidx_t num, nodeidx_t from, nodeidx_t to, nodeidx_t size, int tag)
{
	return netnode_supshift(num, from, to, size, tag);
}

static void ida_netnode_altadjust(nodeidx_t num, nodeidx_t from, nodeidx_t to, nodeidx_t size, IntPtr should_skip)
{
	netnode_altadjust(num, from, to, size, (bool (__stdcall *)(nodeidx_t ea))(should_skip.ToPointer()));
}

static void ida_netnode_altadjust2(nodeidx_t num, nodeidx_t from, nodeidx_t to, nodeidx_t size, IntPtr av)
{
	netnode_altadjust2(num, from, to, size, (altadjust_visitor_t&)av);
}

static bool ida_netnode_exist(IntPtr^ n)
{
	return netnode_exist((netnode&)n);
}

