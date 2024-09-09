#pragma once

//static unsigned long long ida_range_t_print(IntPtr p_0, IntPtr buf, size_t bufsize)
//{
//	return range_t_print((const ::range_t*)(p_0.ToPointer()), (char*)(buf.ToPointer()), bufsize);
//}

static bool ida_rangeset_t_add(IntPtr p_0, IntPtr range)
{
	return rangeset_t_add((::rangeset_t*)(p_0.ToPointer()), *(const ::range_t*)(range.ToPointer()));
}

static bool ida_rangeset_t_sub(IntPtr p_0, IntPtr range)
{
	return rangeset_t_sub((::rangeset_t*)(p_0.ToPointer()), *(const ::range_t*)(range.ToPointer()));
}

static bool ida_rangeset_t_add2(IntPtr p_0, IntPtr aset)
{
	return rangeset_t_add2((::rangeset_t*)(p_0.ToPointer()), *(const ::rangeset_t*)(aset.ToPointer()));
}

static bool ida_rangeset_t_sub2(IntPtr p_0, IntPtr aset)
{
	return rangeset_t_sub2((::rangeset_t*)(p_0.ToPointer()), *(const ::rangeset_t*)(aset.ToPointer()));
}

static bool ida_rangeset_t_has_common(IntPtr p_0, IntPtr range, bool strict)
{
	return rangeset_t_has_common((const ::rangeset_t*)(p_0.ToPointer()), *(const ::range_t*)(range.ToPointer()), strict);
}

static bool ida_rangeset_t_has_common2(IntPtr p_0, IntPtr aset)
{
	return rangeset_t_has_common2((const ::rangeset_t*)(p_0.ToPointer()), *(const ::rangeset_t*)(aset.ToPointer()));
}

static bool ida_rangeset_t_contains(IntPtr p_0, IntPtr aset)
{
	return rangeset_t_contains((const ::rangeset_t*)(p_0.ToPointer()), *(const ::rangeset_t*)(aset.ToPointer()));
}

static unsigned long long ida_rangeset_t_print(IntPtr p_0, IntPtr buf, size_t bufsize)
{
	return rangeset_t_print((const ::rangeset_t*)(p_0.ToPointer()), (char*)(buf.ToPointer()), bufsize);
}

static bool ida_rangeset_t_intersect(IntPtr p_0, IntPtr aset)
{
	return rangeset_t_intersect((::rangeset_t*)(p_0.ToPointer()), *(const ::rangeset_t*)(aset.ToPointer()));
}

static IntPtr ida_rangeset_t_find_range(IntPtr p_0, unsigned long long ea)
{
	return IntPtr((void *)rangeset_t_find_range((const ::rangeset_t*)(p_0.ToPointer()), ea));
}

static unsigned long long ida_rangeset_t_next_addr(IntPtr p_0, ea_t ea)
{
	return rangeset_t_next_addr((const ::rangeset_t*)(p_0.ToPointer()), ea);
}

static unsigned long long ida_rangeset_t_prev_addr(IntPtr p_0, ea_t ea)
{
	return rangeset_t_prev_addr((const ::rangeset_t*)(p_0.ToPointer()), ea);
}

static unsigned long long ida_rangeset_t_next_range(IntPtr p_0, ea_t ea)
{
	return rangeset_t_next_range((const ::rangeset_t*)(p_0.ToPointer()), ea);
}

static unsigned long long ida_rangeset_t_prev_range(IntPtr p_0, ea_t ea)
{
	return rangeset_t_prev_range((const ::rangeset_t*)(p_0.ToPointer()), ea);
}

static IntPtr ida_rangeset_t_lower_bound(IntPtr p_0, ea_t ea)
{
	return IntPtr((void*)(rangeset_t_lower_bound((const ::rangeset_t*)(p_0.ToPointer()), ea)));
}

static IntPtr ida_rangeset_t_upper_bound(IntPtr p_0, ea_t ea)
{
	return IntPtr((void*)(rangeset_t_upper_bound((const ::rangeset_t*)(p_0.ToPointer()), ea)));
}

static void ida_rangeset_t_swap(IntPtr p_0, IntPtr r)
{
	return rangeset_t_swap((::rangeset_t*)(p_0.ToPointer()), *(::rangeset_t*)(r.ToPointer()));
}

