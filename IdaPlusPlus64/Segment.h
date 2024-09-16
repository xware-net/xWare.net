#pragma once

// complete

static bool ida_is_visible_segm(IntPtr s) 
{
	auto segP = (segment_t*)(s.ToPointer());
	return segP != nullptr && segP->is_visible_segm();
}

static bool ida_is_finally_visible_segm(IntPtr s)
{
	auto segP = (segment_t*)(s.ToPointer());
	return (inf_get_cmtflg() & 128) != 0 || is_visible_segm(segP);
}

static void ida_set_visible_segm(IntPtr s, bool visible)
{
	set_visible_segm((segment_t*)(s.ToPointer()), visible);
}

static bool ida_is_spec_segm(uchar seg_type)
{
	return is_spec_segm(seg_type);
}

static bool ida_is_spec_ea(ea_t ea)
{
	return is_spec_ea(ea);
}

static void ida_lock_segm(IntPtr segm, bool lock)
{
	lock_segm((const segment_t*)(segm.ToPointer()), lock);
}

static bool ida_is_segm_locked(IntPtr segm)
{
	return is_segm_locked((const segment_t*)(segm.ToPointer()));
}

static bool ida_getn_selector(IntPtr sel, IntPtr base, int n)
{
	return getn_selector((sel_t*)(sel.ToPointer()), (ea_t*)(base.ToPointer()), n);
}

static size_t ida_get_selector_qty()
{
	return get_selector_qty();
}

static sel_t ida_setup_selector(ea_t segbase)
{
	return setup_selector(segbase);
}

static sel_t ida_allocate_selector(ea_t segbase)
{
	return allocate_selector(segbase);
}

static sel_t ida_find_free_selector()
{
	return find_free_selector();
}

static int ida_set_selector(sel_t selector, ea_t paragraph)
{
	return set_selector(selector, paragraph);
}

static void ida_del_selector(sel_t selector)
{
	return del_selector(selector);
}

static ea_t ida_sel2para(sel_t selector)
{
	return sel2para(selector);
}

static ea_t ida_sel2ea(sel_t selector)
{
	if (selector == sel_t(-1))
		return ea_t(-1);
	return to_ea(sel2para(selector), 0);
}

static sel_t ida_find_selector(ea_t base)
{
	return find_selector(base);
}

static int ida_enumerate_selectors(IntPtr func)
{
	auto fptr = (int(__stdcall*)(unsigned long long sel, unsigned long long para))(func.ToPointer());
	return enumerate_selectors(fptr);
}

static ea_t ida_enumerate_segments_with_selector(sel_t selector, IntPtr func, IntPtr ud)
{
	auto fptr = (ea_t(__stdcall*)(segment_t* s, void* ud))(func.ToPointer());
	return enumerate_segments_with_selector(selector, fptr, (void*)(ud.ToPointer()));
}

static IntPtr ida_get_segm_by_sel(sel_t selector)
{
	return IntPtr((void*)get_segm_by_sel(selector));
}

static bool ida_add_segm_ex(IntPtr s, IntPtr name, IntPtr sclass, int flags)
{
	return add_segm_ex((segment_t*)(s.ToPointer()), (const char*)(name.ToPointer()), (const char*)(sclass.ToPointer()), flags);
}

static bool ida_add_segm(ea_t para, ea_t start, ea_t end, IntPtr name, IntPtr sclass, int flags)
{
	return add_segm(para, start, end, (const char*)(name.ToPointer()), (const char*)(sclass.ToPointer()), flags);
}

static bool ida_del_segm(ea_t ea, int flags)
{
	return del_segm(ea, flags);
}

static int ida_get_segm_qty()
{
	return get_segm_qty();
}

static IntPtr ida_getseg(ea_t ea)
{
	segment_t* segP = getseg(ea);
	return IntPtr(segP);
}

static IntPtr ida_getnseg(int n)
{
	segment_t* segP = getnseg(n);
	return IntPtr(segP);
}

static int ida_get_segm_num(ea_t ea)
{
	return get_segm_num(ea);
}

static IntPtr ida_get_next_seg(ea_t ea)
{
	return IntPtr((void*)get_next_seg(ea));
}

static IntPtr ida_get_prev_seg(ea_t ea)
{
	return IntPtr((void*)get_prev_seg(ea));
}

static IntPtr ida_get_first_seg()
{
	return IntPtr((void*)get_first_seg());
}

static IntPtr ida_get_last_seg()
{
	return IntPtr((void*)get_last_seg());
}

static IntPtr ida_get_segm_by_name(IntPtr name)
{
	return IntPtr((void*)get_segm_by_name((const char*)(name.ToPointer())));
}

static bool ida_set_segm_end(ea_t ea, ea_t newend, int flags)
{
	return set_segm_end(ea, newend, flags);
}

static bool ida_set_segm_start(ea_t ea, ea_t newstart, int flags)
{
	return set_segm_start(ea, newstart, flags);
}

static bool ida_move_segm_start(ea_t ea, ea_t newstart, int mode)
{
	return move_segm_start(ea, newstart, mode);
}

static IntPtr ida_move_segm_strerror(move_segm_code_t code)
{
	return IntPtr((void*)move_segm_strerror(code));
}

static move_segm_code_t ida_move_segm(IntPtr s, ea_t to, int flags)
{
	return move_segm((segment_t*)(s.ToPointer()), to, flags);
}

static move_segm_code_t ida_rebase_program(adiff_t delta, int flags)
{
	return rebase_program(delta, flags);
}

static int ida_change_segment_status(IntPtr s, bool is_deb_segm)
{
	return change_segment_status((segment_t*)(s.ToPointer()), is_deb_segm);
}

static bool ida_take_memory_snapshot(bool only_loader_segs)
{
	return take_memory_snapshot(only_loader_segs);
}

static bool ida_is_miniidb()
{
	return is_miniidb();
}

static bool ida_set_segm_base(IntPtr s, ea_t newbase)
{
	return set_segm_base((segment_t*)(s.ToPointer()), newbase);
}

static int ida_set_group_selector(sel_t grp, sel_t sel)
{
	return set_group_selector(grp, sel);
}

static sel_t ida_get_group_selector(sel_t grpsel)
{
	return get_group_selector(grpsel);
}

static bool ida_add_segment_translation(ea_t segstart, ea_t mappedseg)
{
	return add_segment_translation(segstart, mappedseg);
}

static bool ida_set_segment_translations(ea_t segstart, IntPtr transmap)
{
	return set_segment_translations(segstart, (const eavec_t&)transmap);
}

static void ida_del_segment_translations(ea_t segstart)
{
	return del_segment_translations(segstart);
}

static bool ida_get_segment_translations(IntPtr transmap, ea_t segstart)
{
	return get_segment_translations((eavec_t*)(transmap.ToPointer()), segstart);
}

static ssize_t ida_get_segment_cmt(IntPtr buf, IntPtr segP, bool repeatable)
{
	qstring buffer;
	auto size = get_segment_cmt(&buffer, (segment_t*)(segP.ToPointer()), repeatable);
	if (buf == IntPtr::Zero)
	{
		// look how long is the segment name
		return size;
	}

	::ConvertQstringToIntPtr(buffer, buf, size);
	return size;
}

static void ida_set_segment_cmt(IntPtr s, IntPtr cmt, bool repeatable)
{
	set_segment_cmt((const segment_t*)(s.ToPointer()), (const char*)(cmt.ToPointer()), repeatable);
}

static int ida_set_segm_name(IntPtr s, IntPtr name, int flags)
{
	return set_segm_name((segment_t*)(s.ToPointer()), (const char*)(name.ToPointer()), flags);
}

// see ida_get_segm_name
static ssize_t ida_get_segm_name(IntPtr name, Int32 num, int flags)
{
	segment_t* segP = getnseg(num);
	qstring buffer;
	auto size = get_segm_name(&buffer, segP, flags);
	if (name == IntPtr::Zero)
	{
		// look how long is the segment name
		return size;
	}

	::ConvertQstringToIntPtr(buffer, name, size);
	return size;
}

// see ida_get_segm_name
static ssize_t ida_get_segm_name(IntPtr name, IntPtr segP, int flags)
{
	qstring buffer;
	auto size = get_segm_name(&buffer, (segment_t*)(segP.ToPointer()), flags);
	if (name == IntPtr::Zero)
	{
		// look how long is the segment name
		return size;
	}

	::ConvertQstringToIntPtr(buffer, name, size);
	return size;
}

static ssize_t ida_get_visible_segm_name(IntPtr buf, IntPtr s)
{
	return ida_get_segm_name(buf, s, 1);
}

static ssize_t ida_get_segm_class(IntPtr cls, Int32 num)
{
	segment_t* segP = getnseg(num);
	qstring buffer;
	auto size = get_segm_class(&buffer, segP);
	if (cls == IntPtr::Zero)
	{
		// look how long is the segment sclass
		return size;
	}

	::ConvertQstringToIntPtr(buffer, cls, size);
	return size;
}

static ssize_t ida_get_segm_class(IntPtr cls, IntPtr segP)
{
	qstring buffer;
	auto size = get_segm_class(&buffer, (segment_t*)(segP.ToPointer()));
	if (cls == IntPtr::Zero)
	{
		// look how long is the segment sclass
		return size;
	}

	::ConvertQstringToIntPtr(buffer, cls, size);
	return size;
}

static int ida_set_segm_class(IntPtr segP, IntPtr sclass, int flags)
{
	return set_segm_class((segment_t*)(segP.ToPointer()), (const char*)(sclass.ToPointer()), flags);
}

static uchar ida_segtype(ea_t ea)
{
	return segtype(ea);
}

static IntPtr ida_get_segment_alignment(uchar align)
{
	return IntPtr((void*)get_segment_alignment(align));
}

static IntPtr ida_get_segment_combination(uchar comb)
{
	return IntPtr((void*)get_segment_combination(comb));
}

static ea_t ida_get_segm_para(IntPtr s)
{
	return get_segm_para((segment_t*)(s.ToPointer()));
}

static ea_t ida_get_segm_base(IntPtr s)
{
	return get_segm_base((segment_t*)(s.ToPointer()));
}

static bool ida_set_segm_addressing(IntPtr s, size_t bitness)
{
	return set_segm_addressing((segment_t*)(s.ToPointer()), bitness);
}

static bool ida_is_debugger_segm(ea_t ea)
{
	segment_t* segP = getseg(ea);
	return segP != NULL && segP->is_debugger_segm();
}

static bool ida_is_ephemeral_segm(ea_t ea)
{
	segment_t* segP = getseg(ea);
	return segP != NULL && segP->is_ephemeral_segm();
}

static ea_t ida_correct_address(ea_t ea, ea_t from, ea_t to, ea_t size, bool skip_check)
{
	if (skip_check || (ea >= from && ea < from + size))
		ea += to - from;
	return ea;
}

static bool ida_update_segm(IntPtr s)
{
	return update_segm((segment_t*)(s.ToPointer()));
}

static adiff_t ida_segm_adjust_diff(IntPtr s, adiff_t delta)
{
	return segm_adjust_diff((segment_t*)(s.ToPointer()), delta);
}

static ea_t ida_segm_adjust_ea(IntPtr s, ea_t ea)
{
	return segm_adjust_ea((segment_t*)(s.ToPointer()), ea);
}

// extras

static ea_t ida_get_segm_start_ea(Int32 num)
{
	segment_t* segP = getnseg(num);
	return segP->start_ea;
}

static ea_t ida_get_segm_start_ea(IntPtr segP)
{
	return ((segment_t*)(segP.ToPointer()))->start_ea;
}

static uval_t ida_get_segm_orgbase(Int32 num)
{
	segment_t* segP = getnseg(num);
	return segP->orgbase;
}

static uval_t ida_get_segm_orgbase(IntPtr segP)
{
	return ((segment_t*)(segP.ToPointer()))->orgbase;
}

static ea_t ida_get_segm_end_ea(Int32 num)
{
	segment_t* segP = getnseg(num);
	return segP->end_ea;
}

static ea_t ida_get_segm_end_ea(IntPtr segP)
{
	return ((segment_t*)(segP.ToPointer()))->end_ea;
}

static byte ida_get_segm_align(Int32 num)
{
	segment_t* segP = getnseg(num);
	return segP->align;
}

static byte ida_get_segm_align(IntPtr segP)
{
	return ((segment_t*)(segP.ToPointer()))->align;
}

static byte ida_get_segm_comb(Int32 num)
{
	segment_t* segP = getnseg(num);
	return segP->comb;
}

static byte ida_get_segm_comb(IntPtr segP)
{
	return ((segment_t*)(segP.ToPointer()))->comb;
}

static byte ida_get_segm_perm(Int32 num)
{
	segment_t* segP = getnseg(num);
	return segP->perm;
}

static byte ida_get_segm_perm(IntPtr segP)
{
	return ((segment_t*)(segP.ToPointer()))->perm;
}

static byte ida_get_segm_bitness(Int32 num)
{
	segment_t* segP = getnseg(num);
	return segP->bitness;
}

static byte ida_get_segm_bitness(IntPtr segP)
{
	return ((segment_t*)(segP.ToPointer()))->bitness;
}

static ushort ida_get_segm_flags(Int32 num)
{
	segment_t* segP = getnseg(num);
	return segP->flags;
}

static ushort ida_get_segm_flags(IntPtr segP)
{
	return ((segment_t*)(segP.ToPointer()))->flags;
}

static byte ida_get_segm_type(Int32 num)
{
	segment_t* segP = getnseg(num);
	return segP->type;
}

static byte ida_get_segm_type(IntPtr segP)
{
	return ((segment_t*)(segP.ToPointer()))->type;
}

static int ida_segm_is_16bit(Int32 num)
{
	segment_t* segP = getnseg(num);
	return segP->is_16bit();
}

static int ida_segm_is_32bit(Int32 num)
{
	segment_t* segP = getnseg(num);
	return segP->is_32bit();
}

static int ida_segm_is_64bit(Int32 num)
{
	segment_t* segP = getnseg(num);
	return segP->is_64bit();
}


