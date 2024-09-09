#pragma once

static void ida_lochist_t_register_live(IntPtr p_0)
{
	return lochist_t_register_live(*(::lochist_t*)(p_0.ToPointer()));
}

static void ida_lochist_t_deregister_live(IntPtr p_0)
{
	return lochist_t_deregister_live(*(::lochist_t*)(p_0.ToPointer()));
}

static bool ida_lochist_t_init(IntPtr p_0, IntPtr p_1, IntPtr p_2, IntPtr p_3, unsigned int p_4)
{
	return lochist_t_init(*(::lochist_t*)(p_0.ToPointer()), (const char*)(p_1.ToPointer()), *(const ::place_t*)(p_2.ToPointer()), (void*)(p_3.ToPointer()), p_4);
}

static void ida_lochist_t_jump(IntPtr p_0, bool try_to_unhide, IntPtr e)
{
	return lochist_t_jump(*(::lochist_t*)(p_0.ToPointer()), try_to_unhide, *(const ::lochist_entry_t*)(e.ToPointer()));
}

static bool ida_lochist_t_fwd(IntPtr p_0, unsigned int cnt, bool try_to_unhide)
{
	return lochist_t_fwd(*(::lochist_t*)(p_0.ToPointer()), cnt, try_to_unhide);
}

static bool ida_lochist_t_back(IntPtr p_0, unsigned int cnt, bool try_to_unhide)
{
	return lochist_t_back(*(::lochist_t*)(p_0.ToPointer()), cnt, try_to_unhide);
}

static bool ida_lochist_t_seek(IntPtr p_0, unsigned int index, bool try_to_unhide, bool apply_cur)
{
	return lochist_t_seek(*(::lochist_t*)(p_0.ToPointer()), index, try_to_unhide, apply_cur);
}

static IntPtr ida_lochist_t_get_current(IntPtr p_0)
{
	return IntPtr((void *)lochist_t_get_current(*(const ::lochist_t*)(p_0.ToPointer())));
}

static unsigned int ida_lochist_t_current_index(IntPtr p_0)
{
	return lochist_t_current_index(*(const ::lochist_t*)(p_0.ToPointer()));
}

static void ida_lochist_t_set(IntPtr p_0, unsigned int p_1, IntPtr p_2)
{
	return lochist_t_set(*(::lochist_t*)(p_0.ToPointer()), p_1, *(const ::lochist_entry_t*)(p_2.ToPointer()));
}

static bool ida_lochist_t_get(IntPtr p_0, IntPtr p_1, unsigned int p_2)
{
	return lochist_t_get((::lochist_entry_t*)(p_0.ToPointer()), *(const ::lochist_t*)(p_1.ToPointer()), p_2);
}

static unsigned int ida_lochist_t_size(IntPtr p_0)
{
	return lochist_t_size(*(const ::lochist_t*)(p_0.ToPointer()));
}

static void ida_lochist_t_save(IntPtr p_0)
{
	return lochist_t_save(*(const ::lochist_t*)(p_0.ToPointer()));
}

static void ida_lochist_t_clear(IntPtr p_0)
{
	return lochist_t_clear(*(::lochist_t*)(p_0.ToPointer()));
}

//static void ida_lochist_entry_t_serialize(IntPtr p_0, IntPtr p_1)
//{
//	return lochist_entry_t_serialize((::bytevec_t*)(p_0.ToPointer()), *(const ::lochist_entry_t*)(p_1.ToPointer()));
//}

static bool ida_lochist_entry_t_deserialize(IntPtr p_0, IntPtr p_1, IntPtr p_2, IntPtr p_3)
{
	return lochist_entry_t_deserialize((::lochist_entry_t*)(p_0.ToPointer()), (const unsigned char**)(p_1.ToPointer()), (const unsigned char* const)(p_2.ToPointer()), (const ::place_t*)(p_3.ToPointer()));
}

static unsigned int ida_bookmarks_t_mark(IntPtr p_0, unsigned int p_1, IntPtr p_2, IntPtr p_3, IntPtr p_4)
{
	return bookmarks_t_mark(*(const ::lochist_entry_t*)(p_0.ToPointer()), p_1, (const char*)(p_2.ToPointer()), (const char*)(p_3.ToPointer()), (void*)(p_4.ToPointer()));
}

//static bool ida_bookmarks_t_get(IntPtr p_0, IntPtr p_1, IntPtr p_2, IntPtr p_3)
//{
//	return bookmarks_t_get((::lochist_entry_t*)(p_0.ToPointer()), (::qstring*)(p_1.ToPointer()), (unsigned int*)(p_2.ToPointer()), (void*)(p_3.ToPointer()));
//}

static bool ida_bookmarks_t_get_desc(IntPtr p_0, IntPtr p_1, unsigned int p_2, IntPtr p_3)
{
	return bookmarks_t_get_desc((::qstring*)(p_0.ToPointer()), *(const ::lochist_entry_t*)(p_1.ToPointer()), p_2, (void*)(p_3.ToPointer()));
}

//static bool ida_bookmarks_t_set_desc(qstring p_0, IntPtr p_1, unsigned int p_2, IntPtr p_3)
//{
//	return bookmarks_t_set_desc(p_0, *(const ::lochist_entry_t*)(p_1.ToPointer()), p_2, (void*)(p_3.ToPointer()));
//}

static unsigned int ida_bookmarks_t_find_index(IntPtr p_0, IntPtr p_1)
{
	return bookmarks_t_find_index(*(const ::lochist_entry_t*)(p_0.ToPointer()), (void*)(p_1.ToPointer()));
}

static unsigned int ida_bookmarks_t_size(IntPtr p_0, IntPtr p_1)
{
	return bookmarks_t_size(*(const ::lochist_entry_t*)(p_0.ToPointer()), (void*)(p_1.ToPointer()));
}

static bool ida_bookmarks_t_erase(IntPtr p_0, unsigned int p_1, IntPtr p_2)
{
	return bookmarks_t_erase(*(const ::lochist_entry_t*)(p_0.ToPointer()), p_1, (void*)(p_2.ToPointer()));
}

static dirtree_id_t ida_bookmarks_t_get_dirtree_id(IntPtr p_0, IntPtr p_1)
{
	return bookmarks_t_get_dirtree_id(*(const ::lochist_entry_t*)(p_0.ToPointer()), (void*)(p_1.ToPointer()));
}

