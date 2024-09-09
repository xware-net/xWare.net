#pragma once

// complete

static size_t ida_get_enum_qty()
{
	return get_enum_qty();
}

static enum_t ida_getn_enum(size_t idx)
{
	return getn_enum(idx);
}

static uval_t ida_get_enum_idx(enum_t id)
{
	return get_enum_idx(id);
}

static enum_t ida_get_enum(IntPtr name)
{
	return get_enum((const char*)(name.ToPointer()));
}

static bool ida_is_bf(enum_t id)
{
	return is_bf(id);
}

static bool ida_is_enum_hidden(enum_t id)
{
	return is_enum_hidden(id);
}

static bool ida_set_enum_hidden(enum_t id, bool hidden)
{
	return set_enum_hidden(id, hidden);
}

static bool ida_is_enum_fromtil(enum_t id)
{
	return is_enum_fromtil(id);
}

static bool ida_set_enum_fromtil(enum_t id, bool fromtil)
{
	return set_enum_fromtil(id, fromtil);
}

static bool ida_is_ghost_enum(enum_t id)
{
	return is_ghost_enum(id);
}

static bool ida_set_enum_ghost(enum_t id, bool ghost)
{
	return set_enum_ghost(id, ghost);
}

static ssize_t ida_get_enum_name(IntPtr name, enum_t id)
{
	qstring qstr;
	auto size = get_enum_name(&qstr, id);
	if (name == IntPtr::Zero)
	{
		return size;
	}

	::ConvertQstringToIntPtr(qstr, name, size);
	return size;
}

static ssize_t ida_get_enum_name2(IntPtr name, enum_t id, int flags)
{
	qstring qstr;
	auto size = get_enum_name2(&qstr, id, flags);
	if (name == IntPtr::Zero)
	{
		return size;
	}

	::ConvertQstringToIntPtr(qstr, name, size);
	return size;
}

static String^ ida_get_enum_name(tid_t id, int flags)
{
	qstring name;
	get_enum_name2(&name, id, flags);
	return ::ConvertQstringToString(name);
}

static size_t ida_get_enum_width(enum_t id)
{
	return get_enum_width(id);
}

static bool ida_set_enum_width(enum_t id, int width)
{
	return set_enum_width(id, width);
}

static ssize_t ida_get_enum_cmt(IntPtr buf, enum_t id, bool repeatable)
{
	qstring qstr;
	auto size = get_enum_cmt(&qstr, id, repeatable);
	if (buf == IntPtr::Zero)
	{
		return size;
	}

	::ConvertQstringToIntPtr(qstr, buf, size);
	return size;
}

static size_t ida_get_enum_size(enum_t id)
{
	return get_enum_size(id);
}

static flags64_t ida_get_enum_flag(enum_t id)
{
	return get_enum_flag(id);
}

static const_t ida_get_enum_member_by_name(IntPtr name)
{
	return get_enum_member_by_name((const char*)(name.ToPointer()));
}

static uval_t ida_get_enum_member_value(const_t id)
{
	return get_enum_member_value(id);
}

static enum_t ida_get_enum_member_enum(const_t id)
{
	return get_enum_member_enum(id);
}

static bmask_t ida_get_enum_member_bmask(const_t id)
{
	return get_enum_member_bmask(id);
}

static const_t ida_get_enum_member(enum_t id, uval_t value, int serial, bmask_t mask)
{
	return get_enum_member(id, value, serial, mask);
}

static bmask_t ida_get_first_bmask(enum_t enum_id)
{
	return get_first_bmask(enum_id);
}

static bmask_t ida_get_last_bmask(enum_t enum_id)
{
	return get_last_bmask(enum_id);
}

static bmask_t ida_get_next_bmask(enum_t enum_id, bmask_t bmask)
{
	return get_next_bmask(enum_id, bmask);
}

static bmask_t ida_get_prev_bmask(enum_t enum_id, bmask_t bmask)
{
	return get_prev_bmask(enum_id, bmask);
}

static uval_t ida_get_first_enum_member(enum_t id, bmask_t bmask)
{
	return get_first_enum_member(id, bmask);
}

static uval_t ida_get_last_enum_member(enum_t id, bmask_t bmask)
{
	return get_last_enum_member(id, bmask);
}

static uval_t ida_get_next_enum_member(enum_t id, uval_t value, bmask_t bmask)
{
	return get_next_enum_member(id, value, bmask);
}

static uval_t ida_get_prev_enum_member(enum_t id, uval_t value, bmask_t bmask)
{
	return get_prev_enum_member(id, value, bmask);
}

static ssize_t ida_get_enum_member_name(IntPtr name, const_t id)
{
	qstring qstr;
	auto size = get_enum_member_name(&qstr, id);
	if (name == IntPtr::Zero)
	{
		return size;
	}

	::ConvertQstringToIntPtr(qstr, name, size);
	return size;
}

static ssize_t ida_get_enum_member_cmt(IntPtr buf, const_t id, bool repeatable)
{
	qstring qstr;
	auto size = get_enum_member_cmt(&qstr, id, repeatable);
	if (buf == IntPtr::Zero)
	{
		return size;
	}

	::ConvertQstringToIntPtr(qstr, buf, size);
	return size;
}

static const_t ida_get_first_serial_enum_member(IntPtr out_serial, enum_t id, uval_t value, bmask_t bmask)
{
	return get_first_serial_enum_member((uchar*)(out_serial.ToPointer()), id, value, bmask);
}

static const_t ida_get_last_serial_enum_member(IntPtr out_serial, enum_t id, uval_t value, bmask_t bmask)
{
	return get_last_serial_enum_member((uchar*)(out_serial.ToPointer()), id, value, bmask);
}

static const_t ida_get_next_serial_enum_member(IntPtr in_out_serial, const_t first_cid)
{
	return get_next_serial_enum_member((uchar*)(in_out_serial.ToPointer()), first_cid);
}

static const_t ida_get_prev_serial_enum_member(IntPtr in_out_serial, const_t first_cid)
{
	return get_prev_serial_enum_member((uchar*)(in_out_serial.ToPointer()), first_cid);
}

static int ida_for_all_enum_members(enum_t id, IntPtr callback)
{
	enum_member_visitor visitor(callback);
	return for_all_enum_members(id, visitor);
}

static uchar ida_get_enum_member_serial(const_t cid)
{
	return get_enum_member_serial(cid);
}

static int32 ida_get_enum_type_ordinal(enum_t id)
{
	return get_enum_type_ordinal(id);
}

static void ida_set_enum_type_ordinal(enum_t id, int32 ord)
{
	set_enum_type_ordinal(id, ord);
}

static enum_t ida_add_enum(size_t idx, IntPtr name, flags64_t flag)
{
	return add_enum(idx, (const char*)(name.ToPointer()), flag);
}

static void ida_del_enum(enum_t id)	
{
	del_enum(id);
}

static bool ida_set_enum_idx(enum_t id, size_t idx)
{
	return set_enum_idx(id, idx);
}

static bool ida_set_enum_bf(enum_t id, bool bf)
{
	return set_enum_bf(id, bf);
}

static bool ida_set_enum_name(enum_t id, IntPtr name)
{
	return set_enum_name(id, (const char*)(name.ToPointer()));
}

static bool ida_set_enum_cmt(enum_t id, IntPtr cmt, bool repeatable)
{
	return set_enum_cmt(id, (const char*)(cmt.ToPointer()), repeatable);
}

static bool ida_set_enum_flag(enum_t id, flags64_t flag)
{
	return set_enum_flag(id, flag);
}

static int ida_add_enum_member(enum_t id, IntPtr name, uval_t value, bmask_t bmask)
{
	return add_enum_member(id, (const char*)(name.ToPointer()), value, bmask);
}

static bool ida_del_enum_member(enum_t id, uval_t value, uchar serial, bmask_t bmask)
{
	return del_enum_member(id, value, serial, bmask);
}

static  bool ida_set_enum_member_name(const_t id, IntPtr name)
{
	return set_enum_member_name(id, (const char*)(name.ToPointer()));
}

static bool ida_set_enum_member_cmt(const_t id, IntPtr cmt, bool repeatable)
{
	return set_enum_cmt(id, (char *)(cmt.ToPointer()), repeatable);
}

static bool ida_is_one_bit_mask(bmask_t mask)
{
	return (mask & (mask - 1)) == 0;
}

static bool ida_set_bmask_name(enum_t id, bmask_t bmask, IntPtr name)
{
	return set_bmask_name(id, bmask, (char*)(name.ToPointer()));
}

static ssize_t ida_get_bmask_name(IntPtr out, enum_t id, bmask_t bmask)
{
	qstring qstr;
	auto size = get_bmask_name(&qstr, id, bmask);
	if (out == IntPtr::Zero)
	{
		return size;
	}

	::ConvertQstringToIntPtr(qstr, out, size);
	return size;
}

static bool ida_set_bmask_cmt(enum_t id, bmask_t bmask, IntPtr cmt, bool repeatable)
{
	return set_bmask_cmt(id, bmask, (char*)(cmt.ToPointer()), repeatable);
}

static ssize_t ida_get_bmask_cmt(IntPtr buf, enum_t id, bmask_t bmask, bool repeatable)
{
	qstring qstr;
	auto size = get_bmask_cmt(&qstr, id, bmask, repeatable);
	if (buf == IntPtr::Zero)
	{
		return size;
	}

	::ConvertQstringToIntPtr(qstr, buf, size);
	return size;
}

