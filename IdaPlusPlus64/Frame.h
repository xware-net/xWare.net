#pragma once

[::System::Runtime::InteropServices::UnmanagedFunctionPointer(::System::Runtime::InteropServices::CallingConvention::Cdecl)]
delegate bool Func_bool___IntPtr(::insn_t* insn);

static bool ida_add_frame(IntPtr pfn, sval_t frsize, unsigned short frregs, asize_t argsize)
{
	return add_frame((func_t*)(pfn.ToPointer()), frsize, frregs, argsize);
}

static bool ida_del_frame(IntPtr pfn)
{
	return del_frame((func_t*)(pfn.ToPointer()));
}

static bool ida_set_frame_size(IntPtr pfn, asize_t frsize, unsigned short frregs, asize_t argsize)
{
	return set_frame_size((func_t*)(pfn.ToPointer()), frsize, frregs, argsize);
}

static unsigned long long ida_get_frame_size(IntPtr pfn)
{
	return get_frame_size((const func_t*)(pfn.ToPointer()));
}

static int ida_get_frame_retsize(IntPtr pfn)
{
	return get_frame_retsize((const func_t*)(pfn.ToPointer()));
}

static void ida_get_frame_part(IntPtr range, IntPtr pfn, frame_part_t part)
{
	return get_frame_part((range_t*)(range.ToPointer()), (const func_t*)(pfn.ToPointer()), part);
}

static ea_t ida_frame_off_args(IntPtr pfn)
{
	range_t range;
	get_frame_part(&range, (const func_t*)(pfn.ToPointer()), FPC_ARGS);
	return range.start_ea;
}

static ea_t ida_frame_off_retaddr(IntPtr pfn)
{
	range_t range;
	get_frame_part(&range, (const func_t*)(pfn.ToPointer()), FPC_RETADDR);
	return range.start_ea;
}

static ea_t ida_frame_off_savregs(IntPtr pfn)
{
	range_t range;
	get_frame_part(&range, (const func_t*)(pfn.ToPointer()), FPC_SAVREGS);
	return range.start_ea;
}

static ea_t ida_frame_off_lvars(IntPtr pfn)
{
	range_t range;
	get_frame_part(&range, (const func_t*)(pfn.ToPointer()), FPC_LVARS);
	return range.start_ea;
}

static IntPtr ida_get_frame(IntPtr pfn)
{
	return IntPtr((void*)get_frame((const func_t*)(pfn.ToPointer())));
}

static IntPtr ida_get_frame(ea_t ea)
{
	return IntPtr((void*)get_frame(get_func(ea)));
}

static sval_t ida_soff_to_fpoff(IntPtr pfn, uval_t soff)
{
	return soff - ((func_t*)(pfn.ToPointer()))->frsize + ((func_t*)(pfn.ToPointer()))->fpd;
}

static bool ida_update_fpd(IntPtr pfn, asize_t fpd)
{
	return update_fpd((func_t*)(pfn.ToPointer()), fpd);
}

static bool ida_set_purged(ea_t ea, int nbytes, bool override_old_value)
{
	return set_purged(ea, nbytes, override_old_value);
}

static ea_t ida_get_func_by_frame(tid_t frame_id)
{
	return get_func_by_frame(frame_id);
}

static IntPtr ida_get_stkvar(IntPtr actval, IntPtr insn, IntPtr x, sval_t v)
{
	return IntPtr((void*)get_stkvar((long long*)(actval.ToPointer()), *(const insn_t*)(insn.ToPointer()), *(const op_t*)(x.ToPointer()), v));
}

static bool ida_add_stkvar(IntPtr insn, IntPtr x, sval_t v, int flags)
{
	return add_stkvar(*(const insn_t*)(insn.ToPointer()), *(const op_t*)(x.ToPointer()), v, flags);
}

static bool ida_define_stkvar(IntPtr pfn, IntPtr name, sval_t off, flags_t flags, IntPtr ti, asize_t nbytes)
{
	return define_stkvar((func_t*)(pfn.ToPointer()), (const char*)(name.ToPointer()), off, flags, (const opinfo_t*)(ti.ToPointer()), nbytes);
}

static ssize_t ida_build_stkvar_name(IntPtr buf, IntPtr pfn, sval_t v)
{
	qstring qstr;
	auto len = build_stkvar_name(&qstr, (const func_t*)(pfn.ToPointer()), v);
	if (buf == IntPtr::Zero)
	{
		return len;
	}

	if (len == size_t(-1))
	{
		len = strlen((char*)(buf.ToPointer()));
	}

	::ConvertQstringToIntPtr(qstr, buf, len);
	return len;
}

static unsigned long long ida_calc_stkvar_struc_offset(IntPtr pfn, IntPtr insn, int n)
{
	return calc_stkvar_struc_offset((func_t*)(pfn.ToPointer()), *(const insn_t*)(insn.ToPointer()), n);
}

static int ida_delete_wrong_frame_info(IntPtr pfn, Func_bool___IntPtr^ should_reanalyze)
{
	return delete_wrong_frame_info((func_t*)(pfn.ToPointer()), static_cast<bool (__stdcall*)(const insn_t&)>(::System::Runtime::InteropServices::Marshal::GetFunctionPointerForDelegate(should_reanalyze).ToPointer()));
}

static void ida_free_regvar(IntPtr v)
{
	return free_regvar((regvar_t*)(v.ToPointer()));
}

static int ida_add_regvar(IntPtr pfn, ea_t ea1, ea_t ea2, IntPtr canon, IntPtr user, IntPtr cmt)
{
	return add_regvar((func_t*)(pfn.ToPointer()), ea1, ea2, (const char*)(canon.ToPointer()), (const char*)(user.ToPointer()), (const char*)(cmt.ToPointer()));
}

static IntPtr ida_find_regvar(IntPtr pfn, ea_t ea1, ea_t ea2, IntPtr canon, IntPtr user)
{
	return IntPtr((void*)find_regvar((func_t*)(pfn.ToPointer()), ea1, ea2, (const char*)(canon.ToPointer()), (const char*)(user.ToPointer())));
}

static IntPtr ida_find_regvar(IntPtr pfn, ea_t ea, IntPtr canon)
{
	return IntPtr((void*)find_regvar((func_t*)(pfn.ToPointer()), ea, ea + 1, (const char*)(canon.ToPointer()), nullptr));
}

static bool ida_has_regvar(IntPtr pfn, ea_t ea) 
{
	return find_regvar((func_t*)(pfn.ToPointer()), ea, ea + 1, nullptr, nullptr) != nullptr;
}

static int ida_rename_regvar(IntPtr pfn, IntPtr v, IntPtr user)
{
	return rename_regvar((func_t*)(pfn.ToPointer()), (regvar_t*)(v.ToPointer()), (const char*)(user.ToPointer()));
}

static int ida_set_regvar_cmt(IntPtr pfn, IntPtr v, IntPtr cmt)
{
	return set_regvar_cmt((func_t*)(pfn.ToPointer()), (regvar_t*)(v.ToPointer()), (const char*)(cmt.ToPointer()));
}

static int ida_del_regvar(IntPtr pfn, ea_t ea1, ea_t ea2, IntPtr canon)
{
	return del_regvar((func_t*)(pfn.ToPointer()), ea1, ea2, (const char*)(canon.ToPointer()));
}

static bool ida_add_auto_stkpnt(IntPtr pfn, unsigned long long ea, long long delta)
{
	return add_auto_stkpnt((func_t*)(pfn.ToPointer()), ea, delta);
}

static bool ida_add_user_stkpnt(ea_t ea, sval_t delta)
{
	return add_user_stkpnt(ea, delta);
}

static bool ida_del_stkpnt(IntPtr pfn, ea_t ea)
{
	return del_stkpnt((func_t*)(pfn.ToPointer()), ea);
}

static long long ida_get_spd(IntPtr pfn, ea_t ea)
{
	return get_spd((func_t*)(pfn.ToPointer()), ea);
}

static long long ida_get_effective_spd(IntPtr pfn, ea_t ea)
{
	return get_effective_spd((func_t*)(pfn.ToPointer()), ea);
}

static long long ida_get_sp_delta(IntPtr pfn, ea_t ea)
{
	return get_sp_delta((func_t*)(pfn.ToPointer()), ea);
}

static bool ida_recalc_spd(ea_t cur_ea)
{
	return recalc_spd(cur_ea);
}

//static void ida_build_stkvar_xrefs(IntPtr out, IntPtr pfn, IntPtr mptr)
//{
//	return build_stkvar_xrefs((::qvector<::xreflist_entry_t>*)(out.ToPointer()), (::func_t*)(pfn.ToPointer()), (const ::member_t*)(mptr.ToPointer()));
//}

#ifdef OBSOLETE_FUNCS
static unsigned long long ida_get_min_spd_ea(IntPtr pfn)
{
	return get_min_spd_ea((func_t*)(pfn.ToPointer()));
}

static int ida_delete_unreferenced_stkvars(IntPtr pfn)
{
	return delete_unreferenced_stkvars((func_t*)(pfn.ToPointer()));
}

static int ida_delete_wrong_stkvar_ops(IntPtr pfn)
{
	return delete_wrong_stkvar_ops((func_t*)(pfn.ToPointer()));
}
#endif
