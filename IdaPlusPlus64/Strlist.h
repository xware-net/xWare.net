#pragma once

// complete

static IntPtr ida_get_strlist_options()
{
	return IntPtr((void*)get_strlist_options());
}

static void ida_build_strlist()
{
	return build_strlist();
}

static void ida_clear_strlist()
{
	return clear_strlist();
}

static size_t ida_get_strlist_qty()
{
	return get_strlist_qty();
}

static bool ida_get_strlist_item(IntPtr si, size_t n)
{
	return get_strlist_item((::string_info_t*)(si.ToPointer()), n);
}

