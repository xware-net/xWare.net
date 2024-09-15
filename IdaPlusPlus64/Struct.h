#pragma once

static size_t ida_get_struc_qty()
{
	return get_struc_qty();
}

static uval_t ida_get_first_struc_idx()
{
	return get_first_struc_idx();
}

static uval_t ida_get_last_struc_idx()
{
	return get_last_struc_idx();
}

static uval_t ida_get_prev_struc_idx(uval_t idx)
{
	return idx == BADNODE ? idx : idx - 1;
}

static uval_t ida_get_next_struc_idx(uval_t idx)
{
	return get_next_struc_idx(idx);
}

static uval_t ida_get_struc_idx(tid_t id)
{
	return get_struc_idx(id);
}

static tid_t ida_get_struc_by_idx(uval_t idx)
{
	return get_struc_by_idx(idx);
}

static IntPtr ida_get_struc(tid_t id)
{
	return IntPtr((void*)get_struc(id));
}

static tid_t ida_get_struc_id(IntPtr name)
{
	return get_struc_id((char*)(name.ToPointer()));
}

static ssize_t ida_get_struc_name(IntPtr out, tid_t id, int flags)
{
	qstring str;
	ssize_t len = get_struc_name(&str, id, flags);
	if (out == IntPtr::Zero)
	{
		return len;
	}

	::ConvertQstringToIntPtr(str, out, len);
	return len;
}

static qstring ida_get_struc_name(tid_t id, int flags)	// ???
{
	qstring name;
	get_struc_name(&name, id, flags);
	return name;
}

static ssize_t ida_get_struc_cmt(IntPtr buf, tid_t id, bool repeatable)
{
	qstring str;
	ssize_t len = getnode(id).supstr(&str, repeatable != 0);
	if (buf == IntPtr::Zero)
		return len;
	::ConvertQstringToIntPtr(str, buf, len);
	return len;
}

static asize_t ida_get_struc_size(IntPtr ptr)
{
	struc_t* sptr = (struc_t*)(ptr.ToPointer());
	return get_struc_size(sptr);
}

static asize_t ida_get_struc_size(tid_t id)
{
	return get_struc_size(get_struc(id));
}

static ea_t ida_get_struc_prev_offset(IntPtr sptr, ea_t offset)
{
	return get_struc_prev_offset((const ::struc_t*)(sptr.ToPointer()), offset);
}

static ea_t ida_get_struc_next_offset(IntPtr sptr, ea_t offset)
{
	return get_struc_next_offset((const ::struc_t*)(sptr.ToPointer()), offset);
}

static ea_t ida_get_struc_last_offset(IntPtr sptr)
{
	return get_struc_last_offset((const ::struc_t*)(sptr.ToPointer()));
}

static ea_t ida_get_struc_first_offset(IntPtr sptr)
{
	return get_struc_first_offset((const ::struc_t*)(sptr.ToPointer()));
}

static ea_t ida_get_max_offset(IntPtr ptr)
{
	struc_t* sptr = (struc_t*)(ptr.ToPointer());
	if (sptr == nullptr)
		return 0; // just to avoid GPF
	return sptr->is_union()
		? sptr->memqty
		: get_struc_size(sptr);
}

static bool ida_is_varstr(tid_t id)
{
	struc_t* sptr = get_struc(id);
	return sptr != NULL && sptr->is_varstr();
}

static bool ida_is_union(tid_t id)
{
	struc_t* sptr = get_struc(id);
	return sptr != NULL && sptr->is_union();
}

static IntPtr ida_get_member_struc(IntPtr fullname)
{
	return IntPtr((void*)get_member_struc((const char*)(fullname.ToPointer())));
}

static IntPtr ida_get_sptr(IntPtr mptr)
{
	return IntPtr((void*)get_sptr((const ::member_t*)(mptr.ToPointer())));
}

static IntPtr ida_get_member(IntPtr sptr, unsigned long long offset)
{
	return IntPtr((void*)get_member((const ::struc_t*)(sptr.ToPointer()), offset));
}

static tid_t ida_get_member_id(IntPtr ptr, asize_t offset)
{
	struc_t* sptr = (struc_t*)(ptr.ToPointer());
	member_t* mptr = get_member(sptr, offset);
	return mptr != NULL ? mptr->id : BADADDR;
}

static IntPtr ida_get_innermost_member(IntPtr sptr, IntPtr offset)
{
	return IntPtr((void*)get_innermost_member((::struc_t**)(sptr.ToPointer()), (unsigned long long*)(offset.ToPointer())));
}

static IntPtr ida_get_member_by_name(IntPtr sptr, IntPtr membername)
{
	return IntPtr((void*)get_member_by_name((const ::struc_t*)(sptr.ToPointer()), (const char*)(membername.ToPointer())));
}

static IntPtr ida_get_member_by_fullname(IntPtr sptr_place, IntPtr fullname)
{
	return IntPtr((void*)get_member_by_fullname((::struc_t**)(sptr_place.ToPointer()), (const char*)(fullname.ToPointer())));
}

static ssize_t ida_get_member_fullname(IntPtr out, tid_t mid)
{
	qstring str;
	ssize_t len = get_member_fullname(&str, mid);
	if (out == IntPtr::Zero)
		return len;
	::ConvertQstringToIntPtr(str, out, len);
	return len;
}

static ssize_t ida_get_member_name(IntPtr out, tid_t mid)
{
	qstring str;
	ssize_t len = get_member_name(&str, mid);
	if (out == IntPtr::Zero)
		return len;
	::ConvertQstringToIntPtr(str, out, len);
	return len;
}

static qstring ida_get_member_name(tid_t mid) // ???
{
	qstring name;
	get_member_name(&name, mid);
	return name;
}

static ssize_t ida_get_member_cmt(IntPtr buf, tid_t mid, bool repeatable)
{
	qstring str;
	ssize_t len = getnode(mid).supstr(&str, repeatable != 0);
	if (buf == IntPtr::Zero)
		return len;
	::ConvertQstringToIntPtr(str, buf, len);
	return len;
}

static asize_t ida_get_member_size(IntPtr ptr)
{
	member_t* mptr = (member_t*)(ptr.ToPointer());
	return mptr->unimem() ? mptr->eoff : (mptr->eoff - mptr->soff);
}

static bool ida_is_varmember(IntPtr ptr)
{
	member_t* mptr = (member_t*)(ptr.ToPointer());
	return is_varmember(mptr);
}

static IntPtr ida_get_best_fit_member(IntPtr ptr, asize_t offset)
{
	struc_t* sptr = (struc_t*)(ptr.ToPointer());
	return IntPtr(get_best_fit_member(sptr, offset));
}

static ssize_t ida_get_next_member_idx(IntPtr ptr, asize_t off)
{
	struc_t* sptr = (struc_t*)(ptr.ToPointer());
	return get_next_member_idx(sptr, off);
}

static ssize_t ida_get_prev_member_idx(IntPtr ptr, asize_t off)
{
	struc_t* sptr = (struc_t*)(ptr.ToPointer());
	return get_prev_member_idx(sptr, off);
}

static tid_t ida_add_struc(uval_t idx, IntPtr name, bool is_union)
{
	return add_struc(idx, (const char*)(name.ToPointer()), is_union);
}

static bool ida_del_struc(IntPtr ptr)
{
	struc_t* sptr = (struc_t*)(ptr.ToPointer());
	return del_struc(sptr);
}

static bool ida_set_struc_idx(IntPtr ptr, uval_t idx)
{
	struc_t* sptr = (struc_t*)(ptr.ToPointer());
	return set_struc_idx(sptr, idx);
}

static bool ida_set_struc_align(IntPtr ptr, int shift)
{
	struc_t* sptr = (struc_t*)(ptr.ToPointer());
	return set_struc_align(sptr, shift);
}

static bool ida_set_struc_name(tid_t id, IntPtr name)
{
	return set_struc_name(id, (char*)(name.ToPointer()));
}

static bool ida_set_struc_cmt(tid_t id, IntPtr cmt, bool repeatable)
{
	return set_struc_cmt(id, (char*)(cmt.ToPointer()), repeatable);
}

static int ida_add_struc_member(IntPtr sptr, IntPtr fieldname, ea_t offset, flags64_t flag, IntPtr mt, asize_t nbytes)
{
	return add_struc_member((::struc_t*)(sptr.ToPointer()), (const char*)(fieldname.ToPointer()), offset, flag, (const ::opinfo_t*)(mt.ToPointer()), nbytes);
}

static bool ida_del_struc_member(IntPtr sptr, ea_t offset)
{
	return del_struc_member((struc_t*)(sptr.ToPointer()), offset);
}

static int ida_del_struc_members(IntPtr sptr, ea_t off1, ea_t off2)
{
	return del_struc_members((struc_t*)(sptr.ToPointer()), off1, off2);
}

static bool ida_set_member_name(IntPtr sptr, ea_t offset, IntPtr name)
{
	return set_member_name((::struc_t*)(sptr.ToPointer()), offset, (const char*)(name.ToPointer()));
}

static bool ida_set_member_type(IntPtr sptr, ea_t offset, flags_t flag, IntPtr mt, asize_t nbytes)
{
	return set_member_type((::struc_t*)(sptr.ToPointer()), offset, flag, (const ::opinfo_t*)(mt.ToPointer()), nbytes);
}

static bool ida_set_member_cmt(IntPtr mptr, IntPtr cmt, bool repeatable)
{
	return set_member_cmt((::member_t*)(mptr.ToPointer()), (const char*)(cmt.ToPointer()), repeatable);
}

static bool ida_expand_struc(IntPtr sptr, ea_t offset, adiff_t delta, bool recalc)
{
	return expand_struc((::struc_t*)(sptr.ToPointer()), offset, delta, recalc);
}

static void ida_save_struc(IntPtr sptr, bool may_update_ltypes)
{
	return save_struc((::struc_t*)(sptr.ToPointer()), may_update_ltypes);
}

// 7.7
static void ida_set_struc_hidden(IntPtr sptr, bool is_hidden)
{
	return set_struc_hidden((::struc_t*)(sptr.ToPointer()), is_hidden);
}

// 7.7
static void ida_set_struc_listed(IntPtr sptr, bool is_listed)
{
	return set_struc_listed((::struc_t*)(sptr.ToPointer()), is_listed);
}

static bool ida_get_member_tinfo(IntPtr tif, IntPtr mptr)
{
	return get_member_tinfo((::tinfo_t*)(tif.ToPointer()), (const ::member_t*)(mptr.ToPointer()));
}

static bool ida_del_member_tinfo(IntPtr sptr, IntPtr mptr)
{
	return del_member_tinfo((::struc_t*)(sptr.ToPointer()), (::member_t*)(mptr.ToPointer()));
}

static smt_code_t ida_set_member_tinfo(IntPtr sptr, IntPtr mptr, uval_t memoff, IntPtr tif, int flags)
{
	return set_member_tinfo((::struc_t*)(sptr.ToPointer()), (::member_t*)(mptr.ToPointer()), memoff, *(const ::tinfo_t*)(tif.ToPointer()), flags);
}

static bool ida_get_or_guess_member_tinfo(IntPtr tif, IntPtr mptr)
{
	return get_or_guess_member_tinfo((::tinfo_t*)(tif.ToPointer()), (const ::member_t*)(mptr.ToPointer()));
}

static opinfo_t* ida_retrieve_member_info(opinfo_t* buf, member_t* mptr)
{
	if (mptr == nullptr)
		return nullptr;
	return get_opinfo(buf, mptr->id, 0, mptr->flag);
}

static bool ida_is_anonymous_member_name(IntPtr nam)
{
	char* name = (char*)(nam.ToPointer());
	return name == nullptr
		|| strncmp(name, "anonymous", 9) == 0;
}

static bool ida_is_dummy_member_name(IntPtr nam)
{
	char* name = (char*)(nam.ToPointer());
	return name == nullptr
		|| strncmp(name, "arg_", 4) == 0
		|| strncmp(name, "var_", 4) == 0
		|| is_anonymous_member_name(name);
}

static member_t* ida_get_member_by_id(IntPtr out_mname, tid_t mid, struc_t** sptr_place)
{
	//auto len = ida_get_member_fullname(out_mname, mid);
	//if (out_mname == IntPtr::Zero)
	//{

	//}
	//if (ida_get_member_fullname(out_mname, mid) > 0)
	//	return get_member_by_fullname(sptr_place, out_mname->begin());
	return nullptr;

	//qstring str;
	//auto member_t_ptr = get_member_by_id(&str, mid, sptr_place);
	//if (out_mname == IntPtr::Zero)
	//	return len;
	//::ConvertQstringToIntPtr(str, out, len);
	//return len;
}

static IntPtr ida_get_member_by_id(tid_t mid, IntPtr sptr_place)
{
	return IntPtr((void*)get_member_by_id(mid, (::struc_t**)(sptr_place.ToPointer())));
}

// 7.7
static bool ida_is_member_id(tid_t mid)
{
	return is_member_id(mid);
}

static bool ida_is_special_member(tid_t id)
{
	return is_special_member(id);
}

static flags_t ida_visit_stroff_fields(IntPtr sfv, IntPtr path, int plen, IntPtr disp, bool appzero)
{
	return visit_stroff_fields(*(::struct_field_visitor_t*)(sfv.ToPointer()), (const tid_t*)(path.ToPointer()), plen, (adiff_t*)(disp.ToPointer()), appzero);
}

static bool ida_stroff_as_size(int plen, IntPtr ptr, asize_t value)
{
	struc_t* sptr = (struc_t*)(ptr.ToPointer());
	return plen == 1
		&& value > 0
		&& sptr != nullptr
		&& !sptr->is_varstr()
		&& value == get_struc_size(sptr);
}

static void ida_save_structs()
{
	save_structs();
}

