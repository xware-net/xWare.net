#pragma once

// complete

static bool ida_search_down(int sflag) 
{
	return (sflag & SEARCH_DOWN) != 0;
}

static unsigned long long ida_find_error(ea_t ea, int sflag, IntPtr opnum)
{
	return find_error(ea, sflag, (int*)(opnum.ToPointer()));
}

static unsigned long long ida_find_notype(ea_t ea, int sflag, IntPtr opnum)
{
	return find_notype(ea, sflag, (int*)(opnum.ToPointer()));
}

static ea_t ida_find_unknown(ea_t ea, int sflag)
{
	return find_unknown(ea, sflag);
}

static ea_t ida_find_defined(ea_t ea, int sflag)
{
	return find_defined(ea, sflag);
}

static unsigned long long ida_find_suspop(ea_t ea, int sflag, IntPtr opnum)
{
	return find_suspop(ea, sflag, (int*)(opnum.ToPointer()));
}

static ea_t ida_find_data(ea_t ea, int sflag)
{
	return find_data(ea, sflag);
}

static ea_t ida_find_code(ea_t ea, int sflag)
{
	return find_code(ea, sflag);
}

static ea_t ida_find_not_func(ea_t ea, int sflag)
{
	return find_not_func(ea, sflag);
}

static ea_t ida_find_imm(ea_t ea, int sflag, uval_t search_value, IntPtr opnum)
{
	return find_imm(ea, sflag, search_value, (int*)(opnum.ToPointer()));
}

static ea_t ida_find_text(ea_t start_ea, int y, int x, IntPtr ustr, int sflag)
{
	return find_text(start_ea, y, x, (const char*)(ustr.ToPointer()), sflag);
}

static ea_t ida_find_reg_access(IntPtr out, ea_t start_ea, ea_t end_ea, IntPtr regname, int sflag)
{
	return find_reg_access((::reg_access_t*)(out.ToPointer()), start_ea, end_ea, (const char*)(regname.ToPointer()), sflag);
}

static int ida_search(IntPtr ud, IntPtr start, IntPtr end, IntPtr startx, IntPtr str, int sflag)
{
	return search((void*)(ud.ToPointer()), (::place_t*)(start.ToPointer()), (const ::place_t*)(end.ToPointer()), (int*)(startx.ToPointer()), (const char*)(str.ToPointer()), sflag);
}

#ifdef OBSOLETE_FUNCS
static int ida_user2bin(IntPtr p_0, IntPtr p_1, ea_t p_2, IntPtr p_3, int p_4, bool p_5)
{
	return user2bin((unsigned char*)(p_0.ToPointer()), (unsigned char*)(p_1.ToPointer()), p_2, (const char*)(p_3.ToPointer()), p_4, p_5);
}

static ea_t ida_find_binary(ea_t p_0, ea_t p_1, IntPtr p_2, int p_3, int p_4)
{
	return find_binary(p_0, p_1, (const char*)(p_2.ToPointer()), p_3, p_4);
}
#endif
