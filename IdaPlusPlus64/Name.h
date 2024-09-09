#pragma once

static bool ida_set_name(ea_t ea, IntPtr name, int flags)
{
	return set_name(ea, (char*)(name.ToPointer()), flags);
}

static bool ida_force_name(ea_t ea, IntPtr name, int flags)
{
	return set_name(ea, (char*)(name.ToPointer()), flags | SN_FORCE | SN_NODUMMY);
}

static bool ida_del_global_name(ea_t ea)
{
	return set_name(ea, "", SN_NOWARN);
}

static bool ida_del_local_name(ea_t ea)
{
	return set_name(ea, "", SN_LOCAL | SN_NOWARN);
}

static bool ida_set_dummy_name(ea_t from, ea_t ea)
{
	return set_dummy_name(from, ea);
}

static bool ida_make_name_auto(ea_t ea)
{
	return make_name_auto(ea);
}

static bool ida_make_name_user(ea_t ea)
{
	return make_name_user(ea);
}

static bool ida_validate_name(IntPtr name, nametype_t type, int flags)
{
	qstring qstr = qstring((char*)(name.ToPointer()));
	auto ret = validate_name(&qstr, type, flags);
	::ConvertQstringToIntPtr(qstr, name, qstr.size() - 1);
	return ret;
}

static bool ida_is_valid_cp(wchar32_t cp, nametype_t kind, IntPtr data)
{
	return is_valid_cp(cp, kind, (void*)(data.ToPointer()));
}

static void ida_set_cp_validity(ucdr_kind_t kind, wchar32_t cp, wchar32_t endcp, bool valid)
{
	return set_cp_validity(kind, cp, endcp, valid);
}

static bool ida_get_cp_validity(ucdr_kind_t kind, wchar32_t cp, wchar32_t endcp)
{
	return get_cp_validity(kind, cp, endcp);
}

static bool ida_is_ident_cp(wchar32_t cp)
{
	return is_valid_cp(cp, VNT_IDENT);
}

static bool ida_is_strlit_cp(wchar32_t cp, IntPtr specific_ranges)
{
	return is_valid_cp(cp, VNT_STRLIT, (void*)(specific_ranges.ToPointer()));
}

static bool ida_is_visible_cp(wchar32_t cp)
{
	return is_valid_cp(cp, VNT_VISIBLE);
}

static bool ida_is_ident(IntPtr name)
{
	return is_ident((char*)(name.ToPointer()));
}

static bool ida_is_uname(IntPtr name)
{
	return is_uname((char*)(name.ToPointer()));
}

static bool ida_is_valid_typename(IntPtr name)
{
	return is_valid_typename((char*)(name.ToPointer()));
}

static ea_t ida_dummy_name_ea(IntPtr name)
{
	return dummy_name_ea((char*)(name.ToPointer()));
}

static ssize_t ida_extract_name(IntPtr out, char* line, int x)
{
	qstring qstr;
	auto len = extract_name(&qstr, line, x);
	if (out == IntPtr::Zero)
	{
		return len;
	}

	::ConvertQstringToIntPtr(qstr, out, len);
	return len;
}

static void ida_hide_name(ea_t ea)
{
	return hide_name(ea);
}

static void ida_show_name(ea_t ea)
{
	return show_name(ea);
}

static ea_t ida_get_name_ea(ea_t from, IntPtr name)
{
	return get_name_ea(from, (const char*)(name.ToPointer()));
}

static ea_t ida_get_name_base_ea(ea_t from, ea_t to)
{
	return get_name_base_ea(from, to);
}

static int ida_get_name_value(IntPtr value, ea_t from, IntPtr name)
{
	return get_name_value((uval_t*)(value.ToPointer()), from, (const char*)(name.ToPointer()));
}

static ssize_t ida_get_ea_name(IntPtr out, ea_t ea, int gtn_flags, IntPtr gtni)
{
	qstring pout;
	auto size = get_ea_name(&pout, ea, gtn_flags, (getname_info_t*)(gtni.ToPointer()));
	if (out != IntPtr::Zero)
	{
		::ConvertQstringToIntPtr(pout, out, size);
	}

	return size;
}

static ssize_t ida_get_name(IntPtr out, ea_t ea, int gtn_flags)
{
	return ida_get_ea_name(out, ea, gtn_flags, IntPtr::Zero);
}

static ssize_t ida_get_short_name(IntPtr out, ea_t ea, int gtn_flags)
{
	return ida_get_ea_name(out, ea, GN_VISIBLE | GN_DEMANGLED | GN_SHORT | gtn_flags, IntPtr::Zero);
}

static ssize_t ida_get_long_name(IntPtr out, ea_t ea, int gtn_flags)
{
	return ida_get_ea_name(out, ea, GN_VISIBLE | GN_DEMANGLED | GN_LONG | gtn_flags, IntPtr::Zero);
}

static ssize_t ida_get_colored_short_name(IntPtr out, ea_t ea, int gtn_flags)
{
	return ida_get_ea_name(out, ea, GN_VISIBLE | GN_COLORED | GN_DEMANGLED | GN_SHORT | gtn_flags, IntPtr::Zero);
}

static ssize_t ida_get_colored_long_name(IntPtr out, ea_t ea, int gtn_flags)
{
	return ida_get_ea_name(out, ea, GN_VISIBLE | GN_COLORED | GN_DEMANGLED | GN_LONG | gtn_flags, IntPtr::Zero);
}

static ssize_t ida_get_demangled_name(IntPtr out, ea_t ea, int32 inhibitor, int demform, int gtn_flags)
{
	getname_info_t gtni;
	gtni.inhibitor = inhibitor;
	gtni.demform = demform;
	gtn_flags |= GN_VISIBLE | GN_DEMANGLED;
	return ida_get_ea_name(out, ea, gtn_flags, IntPtr(&gtni));
}

static ssize_t ida_get_colored_demangled_name(IntPtr out, ea_t ea, int32 inhibitor, int demform, int gtn_flags)
{
	return ida_get_demangled_name(out, ea, inhibitor, demform, gtn_flags | GN_COLORED);
}

static size_t ida_get_demangled_name_(IntPtr demNamePtr, ea_t ea, int32 inhibitor, int demform, int gtn_flags)
{
	qstring demangled_name = get_demangled_name(ea, inhibitor, demform, gtn_flags);
	if (demNamePtr != IntPtr::Zero)
	{
		const char* dem_name = demangled_name.c_str();
		demNamePtr = IntPtr((void*)dem_name);
	}

	return demangled_name.size();
}

static size_t ida_get_colored_demangled_name_(IntPtr demNamePtr, ea_t ea, int32 inhibitor, int demform, int gtn_flags)
{
	qstring demangled_name = get_demangled_name(ea, inhibitor, demform, GN_COLORED | gtn_flags);
	if (demNamePtr != IntPtr::Zero)
	{
		const char* dem_name = demangled_name.c_str();
		demNamePtr = IntPtr((void*)dem_name);
	}

	return demangled_name.size();
}

static int ida_calc_gtn_flags(ea_t from, ea_t ea)
{
	return func_contains(get_func(from), ea) ? GN_LOCAL : 0;
}

static color_t ida_get_name_color(ea_t from, ea_t ea)
{
	return get_name_color(from, ea);
}

static ssize_t ida_get_name_expr(IntPtr out, ea_t from, int n, ea_t ea, uval_t off, int flags)
{
	qstring qstr;
	auto len = get_name_expr(&qstr, from, n, ea, off, flags);
	if (out == IntPtr::Zero)
	{
		return len;
	}

	::ConvertQstringToIntPtr(qstr, out, len);
	return len;
}

static ssize_t ida_get_nice_colored_name(IntPtr buf, ea_t ea, int flags)
{
	qstring qstr;
	auto len = get_nice_colored_name(&qstr, ea, flags);
	if (buf == IntPtr::Zero)
	{
		return len;
	}

	::ConvertQstringToIntPtr(qstr, buf, len);
	return len;
}

static flags_t ida_append_struct_fields(IntPtr out, IntPtr disp, int n, IntPtr path, int plen, flags_t flags, adiff_t delta, bool appzero)
{
	qstring qstr = qstring((const char*)(out.ToPointer()));
	auto flgs = append_struct_fields(&qstr, (adiff_t*)(disp.ToPointer()), n, (const tid_t*)(path.ToPointer()), plen, flags, delta, appzero);
	if (out == IntPtr::Zero)
	{
		return flgs;
	}

	::ConvertQstringToIntPtr(qstr, out, qstr.size() - 1);
	return flgs;
}

static int ida_get_struct_operand(IntPtr disp, IntPtr delta, IntPtr path, ea_t ea, int n)
{
	return get_struct_operand((adiff_t*)(disp.ToPointer()), (adiff_t*)(delta.ToPointer()), (tid_t*)(path.ToPointer()), ea, n);
}

static bool ida_is_public_name(ea_t ea)
{
	return is_public_name(ea);
}

static void ida_make_name_public(ea_t ea)
{
	return make_name_public(ea);
}

static void ida_make_name_non_public(ea_t ea)
{
	return make_name_non_public(ea);
}

static bool ida_is_weak_name(ea_t ea)
{
	return is_weak_name(ea);
}

static void ida_make_name_weak(ea_t ea)
{
	return make_name_weak(ea);
}

static void ida_make_name_non_weak(ea_t ea)
{
	return make_name_non_weak(ea);
}

static size_t ida_get_nlist_size()
{
	return get_nlist_size();
}

static size_t ida_get_nlist_idx(ea_t ea)
{
	return get_nlist_idx(ea);
}

static bool ida_is_in_nlist(ea_t ea)
{
	return is_in_nlist(ea);
}

static ea_t ida_get_nlist_ea(size_t idx)
{
	return get_nlist_ea(idx);
}

static IntPtr ida_get_nlist_name(size_t idx)
{
	return IntPtr((void*)get_nlist_name(idx));
}

static void ida_rebuild_nlist()
{
	return rebuild_nlist();
}

static void ida_reorder_dummy_names()
{
	return reorder_dummy_names();
}

static int ida_set_debug_names(IntPtr addrs, IntPtr names, int qty)
{
	return set_debug_names((const unsigned long long*)(addrs.ToPointer()), (const char* const*)(names.ToPointer()), qty);
}

static bool ida_set_debug_name(ea_t ea, IntPtr name)
{
	return set_debug_name(ea, (char*)(name.ToPointer()));
}

static ssize_t ida_get_debug_name(IntPtr out, IntPtr ea_ptr, debug_name_how_t how)
{
	qstring qstr;
	auto len = get_debug_name(&qstr, (ea_t*)(ea_ptr.ToPointer()), how);
	if (out == IntPtr::Zero)
	{
		return len;
	}

	::ConvertQstringToIntPtr(qstr, out, len);
	return len;
}

static void ida_del_debug_names(ea_t ea1, ea_t ea2)
{
	return del_debug_names(ea1, ea2);
}

static ea_t ida_get_debug_name_ea(IntPtr name)
{
	return get_debug_name_ea((char*)(name.ToPointer()));
}

static void ida_get_debug_names(cliext::vector<cliext::pair<ea_t, String^>>^ namesList, ea_t ea1, ea_t ea2)
{
	ea_name_vec_t names;
	get_debug_names(&names, ea1, ea2);
	namesList = gcnew cliext::vector<cliext::pair<ea_t, String^>>();
	namesList->resize(names.size());
	int i = 0;
	for (auto name : names)
	{
		auto nameStr = ::ConvertQstringToString(names[i].name);
		auto namePair = gcnew cliext::pair<ea_t, String^>(names[i].ea, nameStr);
		namesList->at(i) = *namePair;
		i++;
	}
}

static int32 ida_demangle_name(IntPtr out, IntPtr name, uint32 disable_mask, int demreq)
{
	qstring qstr;
	auto ret = demangle_name(&qstr, (char*)(name.ToPointer()), disable_mask, (demreq_type_t)demreq);
	if (out == IntPtr::Zero)
	{
		return ret;
	}

	::ConvertQstringToIntPtr(qstr, out, qstr.size());
	return ret;
}

static String^ ida_demangle_name(IntPtr name, uint32 disable_mask, demreq_type_t demreq)
{
	qstring qstr;
	qstr = demangle_name((const char*)(name.ToPointer()), disable_mask, demreq);
	return ::ConvertQstringToString(qstr);
}

static int32 ida_detect_compiler_using_demangler(IntPtr name)
{
	return demangle_name(nullptr, (char*)(name.ToPointer()), 0, DQT_COMPILER);
}

static bool ida_is_name_defined_locally(IntPtr pfn, IntPtr name, ignore_name_def_t ignore_name_def, ea_t ea1, ea_t ea2)
{
	return is_name_defined_locally((func_t*)(pfn.ToPointer()), (char*)(name.ToPointer()), ignore_name_def, ea1, ea2);
}

static bool ida_cleanup_name(IntPtr out, ea_t ea, char* name, uint32 flags)
{
	qstring qstr = qstring((char*)(out.ToPointer()));
	auto ret = cleanup_name(&qstr, ea, name, flags);
	::ConvertQstringToIntPtr(qstr, out, qstr.size() - 1);
	return ret;
}

