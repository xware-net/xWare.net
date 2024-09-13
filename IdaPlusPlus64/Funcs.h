#pragma once

[::System::Runtime::InteropServices::UnmanagedFunctionPointer(::System::Runtime::InteropServices::CallingConvention::Cdecl)]
delegate void Action_UInt64_UInt64___IntPtr(unsigned long long ea1, unsigned long long ea2, ::System::IntPtr ud);

static void ida_free_regarg(IntPtr v)
{
	return free_regarg((regarg_t*)(v.ToPointer()));
}

static bool ida_is_func_entry(IntPtr pfn)
{
	return is_func_entry((func_t*)(pfn.ToPointer()));
}

static bool ida_is_func_tail(IntPtr pfn)
{
	return is_func_tail((func_t*)(pfn.ToPointer()));
}

static void ida_lock_func_range(IntPtr pfn, bool lock)
{
	return lock_func_range((func_t*)(pfn.ToPointer()), lock);
}

static bool ida_is_func_locked(IntPtr pfn)
{
	return is_func_locked((func_t*)(pfn.ToPointer()));
}

static IntPtr ida_get_func(ea_t ea)
{
	return IntPtr(get_func(ea));
}

static int ida_get_func_chunknum(IntPtr pfn, ea_t ea)
{
	return get_func_chunknum((func_t*)(pfn.ToPointer()), ea);
}

static bool ida_func_contains(IntPtr pfn, ea_t ea)
{
	return get_func_chunknum((func_t*)(pfn.ToPointer()), ea) >= 0;
}

static bool ida_is_same_func(ea_t ea1, ea_t ea2)
{
	func_t* pfn = get_func(ea1);
	return pfn != nullptr && func_contains(pfn, ea2);
}

static IntPtr ida_getn_func(size_t n)
{
	return IntPtr(getn_func(n));
}

static size_t ida_get_func_qty()
{
	return get_func_qty();
}

static int ida_get_func_num(ea_t ea)
{
	return get_func_num(ea);
}

static IntPtr ida_get_prev_func(ea_t ea)
{
	return IntPtr(get_prev_func(ea));
}

static IntPtr ida_get_next_func(ea_t ea)
{
	return IntPtr(get_next_func(ea));
}

static ea_t ida_get_func_ranges(IntPtr ranges, IntPtr pfn)
{
	return get_func_ranges((rangeset_t*)(ranges.ToPointer()), (func_t*)(pfn.ToPointer()));
}

static ssize_t ida_get_func_cmt(IntPtr buf, IntPtr pfn, bool repeatable)
{
	qstring out;
   	ssize_t len = get_func_cmt(&out, (const func_t*)(pfn.ToPointer()), repeatable);
	if (buf != IntPtr::Zero)
	{
		::ConvertQstringToIntPtr(out, buf, len);
	}
	return len;
}

static bool ida_set_func_cmt(IntPtr pfn, IntPtr cmt, bool repeatable)
{
	return set_func_cmt((const func_t*)(pfn.ToPointer()), (const char*)(cmt.ToPointer()), repeatable);
}

static bool ida_update_func(IntPtr pfn)
{
	return update_func((func_t*)(pfn.ToPointer()));
}

static bool ida_add_func_ex(IntPtr pfn)
{
	return add_func_ex((func_t*)(pfn.ToPointer()));
}

static bool ida_add_func(ea_t ea1, ea_t ea2)
{
	func_t fn(ea1, ea2);
	return add_func_ex(&fn);
}

static bool ida_del_func(ea_t ea)
{
	return del_func(ea);
}

static int ida_set_func_start(ea_t ea, ea_t newstart)
{
	return set_func_start(ea, newstart);
}

static bool ida_set_func_end(ea_t ea, ea_t newend)
{
	return set_func_end(ea, newend);
}

static void ida_reanalyze_function(IntPtr pfn, ea_t ea1, ea_t ea2, bool analyze_parents)
{
	reanalyze_function((func_t*)(pfn.ToPointer()), ea1, ea2, analyze_parents);
}

static int ida_find_func_bounds(IntPtr nfn, int flags)
{
	return find_func_bounds((func_t*)(nfn.ToPointer()), flags);
}

static ssize_t ida_get_func_name(IntPtr out, ea_t ea)
{
	qstring buf;
	ssize_t len = get_func_name(&buf, ea);
	if (out != IntPtr::Zero)
	{
		::ConvertQstringToIntPtr(buf, out, len);
	}
	return len;
}

static asize_t ida_calc_func_size(IntPtr pfn)
{
	return calc_func_size((func_t*)(pfn.ToPointer()));
}

static int ida_get_func_bitness(IntPtr pfn)
{
	return get_func_bitness((func_t*)(pfn.ToPointer()));
}

static int ida_get_func_bits(IntPtr pfn)
{
	return 1 << (get_func_bitness((func_t*)(pfn.ToPointer())) + 4);
}

static int ida_get_func_bytes(IntPtr pfn)
{
	return get_func_bits((func_t*)(pfn.ToPointer())) / 8;
}

static bool ida_is_visible_func(IntPtr pfn)
{
	return is_visible_func((func_t*)(pfn.ToPointer()));
}

static bool ida_is_finally_visible_func(IntPtr pfn)
{
	return is_finally_visible_func((func_t*)(pfn.ToPointer()));
}

static void ida_set_visible_func(IntPtr pfn, bool visible)
{
	return set_visible_func((func_t*)(pfn.ToPointer()), visible);
}

static int ida_set_func_name_if_jumpfunc(IntPtr pfn, char* oldname)
{
	return set_func_name_if_jumpfunc((func_t*)(pfn.ToPointer()), oldname);
}

static ea_t ida_calc_thunk_func_target(IntPtr pfn, IntPtr fptr)
{
	return calc_thunk_func_target((func_t*)(pfn.ToPointer()), (ea_t*)(fptr.ToPointer()));
}

static bool ida_func_does_return(ea_t callee)
{
	return func_does_return(callee);
}

static bool ida_reanalyze_noret_flag(ea_t ea)
{
	return reanalyze_noret_flag(ea);
}

static bool ida_set_noret_insn(ea_t insn_ea, bool noret)
{
	return set_noret_insn(insn_ea, noret);
}

static IntPtr ida_get_fchunk(ea_t ea)
{
	auto fchunk = get_fchunk(ea);
	return IntPtr(fchunk);
}

static IntPtr ida_get_fchunk(int n)
{
	auto fchunk = get_fchunk(n);
	return IntPtr(fchunk);
}

static size_t ida_get_fchunk_qty()
{
	return get_fchunk_qty();
}

static int ida_get_fchunk_num(ea_t ea)
{
	return get_fchunk_num(ea);
}

static IntPtr ida_get_prev_fchunk(ea_t ea)
{
	auto fchunk = get_prev_fchunk(ea);
	return IntPtr(fchunk);
}

static IntPtr ida_get_next_fchunk(ea_t ea)
{
	auto fchunk = get_next_fchunk(ea);
	return IntPtr(fchunk);
}

static bool ida_append_func_tail(IntPtr pfn, ea_t ea1, ea_t ea2)
{
	return append_func_tail((func_t*)(pfn.ToPointer()), ea1, ea2);
}

static bool ida_remove_func_tail(IntPtr pfn, ea_t tail_ea)
{
	return remove_func_tail((func_t*)(pfn.ToPointer()), tail_ea);
}

static bool ida_set_tail_owner(IntPtr fnt, ea_t func_start)
{
	return set_tail_owner((func_t*)(fnt.ToPointer()), func_start);
}

static bool ida_func_tail_iterator_set(IntPtr fti, IntPtr pfn, ea_t ea)
{
	return func_tail_iterator_set((func_tail_iterator_t*)(fti.ToPointer()), (func_t*)(pfn.ToPointer()), ea);
}

static bool ida_func_tail_iterator_set_ea(IntPtr fti, ea_t ea)
{
	return func_tail_iterator_set_ea((func_tail_iterator_t*)(fti.ToPointer()), ea);
}

static bool ida_func_parent_iterator_set(IntPtr fpi, IntPtr pfn)
{
	return func_parent_iterator_set((func_parent_iterator_t*)(fpi.ToPointer()), (func_t*)(pfn.ToPointer()));
}

static bool ida_func_item_iterator_next(IntPtr fii, IntPtr testf, IntPtr ud)
{
	return func_item_iterator_next((func_item_iterator_t*)(fii.ToPointer()), (testf_t*)(testf.ToPointer()), (void*)(ud.ToPointer()));
}

static bool ida_func_item_iterator_prev(IntPtr fii, IntPtr testf, IntPtr ud)
{
	return func_item_iterator_prev((func_item_iterator_t*)(fii.ToPointer()), (testf_t*)(testf.ToPointer()), (void*)(ud.ToPointer()));
}

static bool ida_func_item_iterator_decode_prev_insn(IntPtr fii, IntPtr out)
{
	return func_item_iterator_decode_prev_insn((func_item_iterator_t*)(fii.ToPointer()), (insn_t*)(out.ToPointer()));
}

static bool ida_func_item_iterator_decode_preceding_insn(IntPtr fii, IntPtr visited, IntPtr p_farref, IntPtr out)
{
	return func_item_iterator_decode_preceding_insn((func_item_iterator_t*)(fii.ToPointer()), (eavec_t*)(visited.ToPointer()), (bool*)(p_farref.ToPointer()), (insn_t*)(out.ToPointer()));
}

static bool ida_func_item_iterator_succ(IntPtr fii, IntPtr testf, IntPtr ud)
{
	return func_item_iterator_succ((func_item_iterator_t*)(fii.ToPointer()), (testf_t*)(testf.ToPointer()), (void*)(ud.ToPointer()));
}

static bool ida_f_any(flags_t f, IntPtr p)
{
	return true;
}

static void ida_iterate_func_chunks(IntPtr pfn, Action_UInt64_UInt64___IntPtr^ func, IntPtr ud, bool include_parents)
{
	iterate_func_chunks((func_t*)(pfn.ToPointer()), static_cast<void (*)(ea_t, ea_t, void*)>(::System::Runtime::InteropServices::Marshal::GetFunctionPointerForDelegate(func).ToPointer()), (void*)(ud.ToPointer()), include_parents);
}

static ea_t ida_get_prev_func_addr(IntPtr pfn, ea_t ea)
{
	return get_prev_func_addr((func_t*)(pfn.ToPointer()), ea);
}

static ea_t ida_get_next_func_addr(IntPtr pfn, ea_t ea)
{
	return get_next_func_addr((func_t*)(pfn.ToPointer()), ea);
}

static void ida_read_regargs(IntPtr pfn)
{
	return read_regargs((func_t*)(pfn.ToPointer()));
}

static void ida_add_regarg(IntPtr pfn, int reg, IntPtr tif, IntPtr name)
{
	return add_regarg((func_t*)(pfn.ToPointer()), reg, *(tinfo_t*)(tif.ToPointer()), (char*)(name.ToPointer()));
}

static int ida_plan_to_apply_idasgn(IntPtr fname)
{
	return plan_to_apply_idasgn((char*)(fname.ToPointer()));
}

static int ida_apply_idasgn_to(IntPtr signame, ea_t ea, bool is_startup)
{
	return apply_idasgn_to((char*)(signame.ToPointer()), ea, is_startup);
}

static int ida_get_idasgn_qty()
{
	return get_idasgn_qty();
}

static int ida_get_current_idasgn()
{
	return get_current_idasgn();
}

static int ida_calc_idasgn_state(int n)
{
	return calc_idasgn_state(n);
}

static int ida_del_idasgn(int n)
{
	return del_idasgn(n);
}

static int32 ida_get_idasgn_desc(IntPtr signame, IntPtr optlibs, int n)
{
	qstring buf;
	qstring buf1;
	auto ret = get_idasgn_desc(&buf, &buf1, n);
	if (signame != IntPtr::Zero)
	{
		::ConvertQstringToIntPtr(buf, signame, buf.size() - 1);
	}
	if (optlibs != IntPtr::Zero)
	{
		::ConvertQstringToIntPtr(buf1, optlibs, buf1.size() - 1);
	}
	return ret;
}

static IntPtr ida_get_idasgn_header_by_short_name(IntPtr name)
{
	return IntPtr((void*)get_idasgn_header_by_short_name((const char*)(name.ToPointer())));
}

static ssize_t ida_get_idasgn_title(IntPtr buf, IntPtr name)
{
	qstring out;
	auto size = get_idasgn_title(&out, (const char*)(name.ToPointer()));
	if (buf != IntPtr::Zero)
	{
		::ConvertQstringToIntPtr(out, buf, size);
	}
	return size;
}

static void ida_determine_rtl()
{
	return determine_rtl();
}

static bool ida_apply_startup_sig(ea_t ea, IntPtr startup)
{
	return apply_startup_sig(ea, (char*)(startup.ToPointer()));
}

static int ida_try_to_add_libfunc(ea_t ea)
{
	return try_to_add_libfunc(ea);
}

static void ida_save_signatures()
{
}

//static bool ida_invalidate_sp_analysis(ea_t ea)
//{
//	return invalidate_sp_analysis(get_func(ea));
//}

// marshaling
static size_t ida_func_t_size()
{
	return sizeof(func_t);
}

static ea_t ida_get_func_start_ea(IntPtr func)
{
	func_t* f = (func_t*)(func.ToPointer());
	return f->start_ea;
}

static ea_t ida_get_func_end_ea(IntPtr func)
{
	func_t* f = (func_t*)(func.ToPointer());
	return f->end_ea;
}

static UInt64 ida_get_func_flags(IntPtr func)
{
	func_t* f = (func_t*)(func.ToPointer());
	return f->flags;
}

static asize_t ida_get_func_size(IntPtr func)
{
	func_t* f = (func_t*)(func.ToPointer());
	return calc_func_size(f);
}

static int ida_get_tail_refqty(IntPtr pfn)
{
	auto f = (func_t*)(pfn.ToPointer());
	return f->refqty;
}
