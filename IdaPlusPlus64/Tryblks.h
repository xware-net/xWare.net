#pragma once

// complete
static size_t ida_get_tryblks(IntPtr tbv, IntPtr range)
{
	return get_tryblks((::tryblks_t*)(tbv.ToPointer()), *(const ::range_t*)(range.ToPointer()));
}

static void ida_del_tryblks(IntPtr range)
{
	return del_tryblks(*(const ::range_t*)(range.ToPointer()));
}

static int ida_add_tryblk(IntPtr tb)
{
	return add_tryblk(*(const ::tryblk_t*)(tb.ToPointer()));
}

static ea_t ida_find_syseh(ea_t ea)
{
	return find_syseh(ea);
}

static bool ida_is_ea_tryblks(ea_t ea, unsigned int flags)
{
	return is_ea_tryblks(ea, flags);
}

