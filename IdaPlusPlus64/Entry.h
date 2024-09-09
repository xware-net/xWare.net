#pragma once

// complete

static size_t ida_get_entry_qty()
{
	return get_entry_qty();
}

static bool ida_add_entry(uval_t ord, ea_t ea, IntPtr name, bool makecode, int flags)
{
	return add_entry(ord, ea, (const char*)(name.ToPointer()), makecode, flags);
}

static uval_t ida_get_entry_ordinal(size_t idx)
{
	return get_entry_ordinal(idx);
}

static ea_t ida_get_entry(uval_t ord)
{
	return get_entry(ord);
}

static ssize_t ida_get_entry_name(IntPtr name, uval_t ord)
{
	if (name == IntPtr::Zero)
	{
		return get_entry_name(static_cast<qstring*>(nullptr), ord);
	}
	else
	{
		qstring buffer;
		auto size = get_entry_name(&buffer, ord);
		::ConvertQstringToIntPtr(buffer, name, size);
		return size;
	}
}

static bool ida_rename_entry(uval_t ord, IntPtr name, int flags)
{
	return rename_entry(ord, (const char*)(name.ToPointer()), flags);
}

static bool ida_set_entry_forwarder(uval_t ord, IntPtr name, int flags)
{
	return set_entry_forwarder(ord, (const char*)(name.ToPointer()), flags);
}

static ssize_t ida_get_entry_forwarder(IntPtr buf, uval_t ord)
{
	if (buf == IntPtr::Zero)
	{
		return get_entry_forwarder(static_cast<qstring*>(nullptr), ord);
	}
	else
	{
		qstring buffer;
		auto size = get_entry_forwarder(&buffer, ord);
		::ConvertQstringToIntPtr(buffer, buf, size);
		return size;
	}
}

