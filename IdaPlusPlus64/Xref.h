#pragma once

static char ida_xrefchar(char xrtype)
{
	return xrefchar(xrtype);
}

static bool ida_add_cref(ea_t from, ea_t to, cref_t type)
{
	return add_cref(from, to, type);
}

static bool ida_del_cref(ea_t from, ea_t to, bool expand)
{
	return del_cref(from, to, expand);
}

static bool ida_add_dref(ea_t from, ea_t to, dref_t type)
{
	return add_dref(from, to, type);
}

static void ida_del_dref(ea_t from, ea_t to)
{
	del_dref(from, to);
}

/// Should not be called directly!
static bool ida_xrefblk_t_first_from(IntPtr ptr, ea_t from, int flags)
{
	return xrefblk_t_first_from((::xrefblk_t*)(ptr.ToPointer()), from, flags);
}

/// Should not be called directly!
static bool ida_xrefblk_t_next_from(IntPtr ptr)
{
	return xrefblk_t_next_from((::xrefblk_t*)(ptr.ToPointer()));
}

/// Should not be called directly!
static bool ida_xrefblk_t_first_to(IntPtr ptr, ea_t to, int flags)
{
	return xrefblk_t_first_to((::xrefblk_t*)(ptr.ToPointer()), to, flags);
}

/// Should not be called directly!
static bool ida_xrefblk_t_next_to(IntPtr ptr)
{
	return xrefblk_t_next_to((::xrefblk_t*)(ptr.ToPointer()));
}

static ea_t ida_get_first_dref_from(ea_t from)
{
	return get_first_dref_from(from);
}

static ea_t ida_get_next_dref_from(ea_t from, ea_t current)
{
	return get_next_dref_from(from, current);
}

static ea_t ida_get_first_dref_to(ea_t to)
{
	return get_first_dref_to(to);
}

static ea_t ida_get_next_dref_to(ea_t to, ea_t current)
{
	return get_next_dref_to(to, current);
}

static ea_t ida_get_first_cref_from(ea_t from)
{
	return get_first_cref_from(from);
}

static ea_t ida_get_next_cref_from(ea_t from, ea_t current)
{
	return get_next_cref_from(from, current);
}

static ea_t ida_get_first_cref_to(ea_t to)
{
	return get_first_cref_to(to);
}

static ea_t ida_get_next_cref_to(ea_t to, ea_t current)
{
	return get_next_cref_to(to, current);
}

static ea_t ida_get_first_fcref_from(ea_t from)
{
	return get_first_fcref_from(from);
}

static ea_t ida_get_next_fcref_from(ea_t from, ea_t current)
{
	return get_next_fcref_from(from, current);
}

static ea_t ida_get_first_fcref_to(ea_t to)
{
	return get_first_fcref_to(to);
}

static ea_t ida_get_next_fcref_to(ea_t to, ea_t current)
{
	return get_next_fcref_to(to, current);
}

static bool ida_has_external_refs(IntPtr pfn, ea_t ea)
{
	return has_external_refs((func_t*)(pfn.ToPointer()), ea);
}

static bool ida_create_switch_table(unsigned long long insn_ea, IntPtr si)
{
	return create_switch_table(insn_ea, *(const ::switch_info_t*)(si.ToPointer()));
}

static void ida_create_switch_xrefs(unsigned long long insn_ea, IntPtr si)
{
	create_switch_xrefs(insn_ea, *(const ::switch_info_t*)(si.ToPointer()));
}

//static bool ida_calc_switch_cases(IntPtr casevec, IntPtr targets, ea_t insn_ea, IntPtr si)
//{
//	return calc_switch_cases((::qvector<::qvector<long long>>*)(casevec.ToPointer()), (::qvector<unsigned long long>*)(targets.ToPointer()), insn_ea, (const ::switch_info_t&)(si.ToPointer()));
//}

static void ida_delete_switch_table(unsigned long long jump_ea, IntPtr si)
{
	delete_switch_table(jump_ea, *(const ::switch_info_t*)(si.ToPointer()));
}

static bool ida_create_xrefs_from(ea_t ea)
{
	return create_xrefs_from(ea);
}

static void ida_delete_all_xrefs_from(ea_t ea, bool expand)
{
	delete_all_xrefs_from(ea, expand);
}


