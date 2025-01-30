#pragma once

// static IDASDK::TinfoT^ ida_remove_pointer(IntPtr tif)
//{
//    tinfo_t r;
//    r.typid = get_tinfo_property(tif.typid, tinfo_t::GTA_SAFE_PTR_OBJ);
//    return r;
//}

static bool ida_is_type_const(type_t t)
{
	return (t & BTM_CONST) != 0;
}

static bool ida_is_type_volatile(type_t t)
{
	return (t & BTM_VOLATILE) != 0;
}

static type_t ida_get_base_type(type_t t)
{
	return (t & TYPE_BASE_MASK);
}

static type_t ida_get_type_flags(type_t t)
{
	return (t & TYPE_FLAGS_MASK);
}

static type_t ida_get_full_type(type_t t)
{
	return (t & TYPE_FULL_MASK);
}

static bool ida_is_typeid_last(type_t t)
{
	return (get_base_type(t) <= _BT_LAST_BASIC);
}

static bool ida_is_type_partial(type_t t)
{
	return (get_base_type(t) <= BT_VOID) && get_type_flags(t) != 0;
}

static bool ida_is_type_void(type_t t)
{
	return (get_full_type(t) == BTF_VOID);
}

static bool ida_is_type_unknown(type_t t)
{
	return (get_full_type(t) == BT_UNKNOWN);
}

static bool ida_is_type_ptr(type_t t)
{
	return (get_base_type(t) == BT_PTR);
}

static bool ida_is_type_complex(type_t t)
{
	return (get_base_type(t) == BT_COMPLEX);
}

static bool ida_is_type_func(type_t t)
{
	return (get_base_type(t) == BT_FUNC);
}

static bool ida_is_type_array(type_t t)
{
	return (get_base_type(t) == BT_ARRAY);
}

static bool ida_is_type_typedef(type_t t)
{
	return (get_full_type(t) == BTF_TYPEDEF);
}

static bool ida_is_type_sue(type_t t)
{
	return is_type_complex(t) && !is_type_typedef(t);
}

static bool ida_is_type_struct(type_t t)
{
	return (get_full_type(t) == BTF_STRUCT);
}

static bool ida_is_type_union(type_t t)
{
	return (get_full_type(t) == BTF_UNION);
}

static bool ida_is_type_struni(type_t t)
{
	return (is_type_struct(t) || is_type_union(t));
}

static bool ida_is_type_enum(type_t t)
{
	return (get_full_type(t) == BTF_ENUM);
}

static bool ida_is_type_bitfld(type_t t)
{
	return (get_base_type(t) == BT_BITFIELD);
}

static bool ida_is_type_int(type_t bt)
{
	bt = get_base_type(bt);
	return bt >= BT_INT8 && bt <= BT_INT;
}

static bool ida_is_type_int128(type_t t)
{
	return get_full_type(t) == (BT_INT128 | BTMT_UNKSIGN) || get_full_type(t) == (BT_INT128 | BTMT_SIGNED);
}

static bool ida_is_type_int64(type_t t)
{
	return get_full_type(t) == (BT_INT64 | BTMT_UNKSIGN) || get_full_type(t) == (BT_INT64 | BTMT_SIGNED);
}

static bool ida_is_type_int32(type_t t)
{
	return get_full_type(t) == (BT_INT32 | BTMT_UNKSIGN) || get_full_type(t) == (BT_INT32 | BTMT_SIGNED);
}

static bool ida_is_type_int16(type_t t)
{
	return get_full_type(t) == (BT_INT16 | BTMT_UNKSIGN) || get_full_type(t) == (BT_INT16 | BTMT_SIGNED);
}

static bool ida_is_type_char(type_t t)
{
	return get_full_type(t) == (BT_INT8 | BTMT_CHAR) || get_full_type(t) == (BT_INT8 | BTMT_SIGNED);
}

static bool ida_is_type_paf(type_t t)
{
	t = get_base_type(t);
	return t >= BT_PTR && t <= BT_FUNC;
}

static bool ida_is_type_ptr_or_array(type_t t)
{
	t = get_base_type(t);
	return t == BT_PTR || t == BT_ARRAY;
}

static bool ida_is_type_floating(type_t t)
{
	return get_base_type(t) == BT_FLOAT;
}

static bool ida_is_type_integral(type_t t)
{
	return get_full_type(t) > BT_VOID && get_base_type(t) <= BT_BOOL;
}

static bool ida_is_type_ext_integral(type_t t)
{
	return is_type_integral(t) || is_type_enum(t);
}

static bool ida_is_type_arithmetic(type_t t)
{
	return get_full_type(t) > BT_VOID && get_base_type(t) <= BT_FLOAT;
}

static bool ida_is_type_ext_arithmetic(type_t t)
{
	return is_type_arithmetic(t) || is_type_enum(t);
}

static bool ida_is_type_uint(type_t t)
{
	return get_full_type(t) == BTF_UINT;
}

static bool ida_is_type_uchar(type_t t)
{
	return get_full_type(t) == BTF_UCHAR;
}

static bool ida_is_type_uint16(type_t t)
{
	return get_full_type(t) == BTF_UINT16;
}

static bool ida_is_type_uint32(type_t t)
{
	return get_full_type(t) == BTF_UINT32;
}

static bool ida_is_type_uint64(type_t t)
{
	return get_full_type(t) == BTF_UINT64;
}

static bool ida_is_type_uint128(type_t t)
{
	return get_full_type(t) == BTF_UINT128;
}

static bool ida_is_type_ldouble(type_t t)
{
	return get_full_type(t) == BTF_LDOUBLE;
}

static bool ida_is_type_double(type_t t)
{
	return get_full_type(t) == BTF_DOUBLE;
}

static bool ida_is_type_float(type_t t)
{
	return get_full_type(t) == BTF_FLOAT;
}

static bool ida_is_type_tbyte(type_t t)
{
	return get_full_type(t) == BTF_TBYTE;
}

static bool ida_is_type_bool(type_t t)
{
	return get_base_type(t) == BT_BOOL;
}

static bool ida_is_tah_byte(type_t t)
{
	return t == TAH_BYTE;
}

static bool ida_is_sdacl_byte(type_t t)
{
	return ((t & ~TYPE_FLAGS_MASK) ^ TYPE_MODIF_MASK) <= BT_VOID;
}

//static bool operator<(IntPtr v1Ptr, IntPtr v2Ptr)
//{
//	auto v1 = *(const bytevec_t*)(v1Ptr.ToPointer());
//	auto v2 = *(const bytevec_t*)(v2Ptr.ToPointer());
//	size_t n = ((v1.size()) < (v2.size()) ? (v1.size()) : (v2.size()));
//	for (size_t i = 0; i < n; i++) 
//	{
//		uchar k1 = v1[i];
//		uchar k2 = v2[i];
//		if (k1 < k2)
//			return true;
//		if (k1 > k2)
//			return false;
//	}
//	return v1.size() < v2.size();
//}

static bool ida_append_argloc(IntPtr out, IntPtr vloc)
{
	return append_argloc((qtype*)(out.ToPointer()), *(const argloc_t*)(vloc.ToPointer()));
}

static bool ida_extract_argloc(IntPtr vloc, IntPtr ptype, bool forbid_stkoff)
{
	return extract_argloc((argloc_t*)(vloc.ToPointer()), (const type_t**)(ptype.ToPointer()), forbid_stkoff);
}

static IntPtr ida_resolve_typedef(IntPtr til, IntPtr type)
{
	return IntPtr((void*)resolve_typedef((const til_t*)(til.ToPointer()), (const type_t*)(type.ToPointer())));
}

static bool ida_is_restype_void(IntPtr tilPtr, IntPtr typePtr)
{
	auto til = (const til_t*)(tilPtr.ToPointer());
	auto type = (const type_t*)(typePtr.ToPointer());
	type = resolve_typedef(til, type);
	return type != nullptr && is_type_void(*type);
}

static bool ida_is_restype_enum(IntPtr tilPtr, IntPtr typePtr)
{
	auto til = (const til_t*)(tilPtr.ToPointer());
	auto type = (const type_t*)(typePtr.ToPointer());
	type = resolve_typedef(til, type);
	return type != nullptr && is_type_enum(*type);
}

static bool ida_is_restype_struni(IntPtr tilPtr, IntPtr typePtr)
{
	auto til = (const til_t*)(tilPtr.ToPointer());
	auto type = (const type_t*)(typePtr.ToPointer());
	type = resolve_typedef(til, type);
	return type != nullptr && is_type_struni(*type);
}

static bool ida_is_restype_struct(IntPtr tilPtr, IntPtr typePtr)
{
	auto til = (const til_t*)(tilPtr.ToPointer());
	auto type = (const type_t*)(typePtr.ToPointer());
	type = resolve_typedef(til, type);
	return type != nullptr && is_type_struct(*type);
}

static type_t ida_get_scalar_bt(int size)
{
	return get_scalar_bt(size);
}

static IntPtr ida_new_til(IntPtr name, IntPtr desc)
{
	return IntPtr((void*)new_til((const char*)(name.ToPointer()), (const char*)(desc.ToPointer())));
}

static int ida_add_base_tils(IntPtr errbuf, IntPtr ti, IntPtr tildir, IntPtr bases, bool gen_events)
{
	qstring qstr;
	auto ret = add_base_tils(&qstr, (til_t*)(ti.ToPointer()), (const char*)(tildir.ToPointer()), (const char*)(bases.ToPointer()), gen_events);
	if (errbuf != IntPtr::Zero)
	{
		::ConvertQstringToIntPtr(qstr, errbuf, qstr.size() - 1);
	}

	return ret;
}

static IntPtr ida_load_til(IntPtr name, IntPtr errbuf, IntPtr tildir)
{
	qstring qstr;
	auto til = load_til((const char*)(name.ToPointer()), &qstr, (const char*)(tildir.ToPointer()));
	if (errbuf == IntPtr::Zero)
	{
		::ConvertQstringToIntPtr(qstr, errbuf, qstr.size() == 0 ? 0 : qstr.size() - 1);
	}

	return IntPtr((void*)til);
}

static bool ida_sort_til(IntPtr ti)
{
	return sort_til((til_t*)(ti.ToPointer()));
}

static bool ida_compact_til(IntPtr ti)
{
	return compact_til((til_t*)(ti.ToPointer()));
}

static bool ida_store_til(IntPtr ti, IntPtr tildir, IntPtr name)
{
	return store_til((til_t*)(ti.ToPointer()), (const char*)(tildir.ToPointer()), (const char*)(name.ToPointer()));
}

static void ida_free_til(IntPtr ti)
{
	free_til((til_t*)(ti.ToPointer()));
}

static IntPtr ida_load_til_header(IntPtr tildir, IntPtr name, IntPtr errbuf)
{
	qstring qstr;
	auto til = load_til_header((const char*)(tildir.ToPointer()), (const char*)(name.ToPointer()), &qstr);
	if (errbuf == IntPtr::Zero)
	{
		::ConvertQstringToIntPtr(qstr, errbuf, qstr.size() - 1);
	}

	return IntPtr((void*)til);
}

static bool ida_is_code_far(cm_t cm)
{
	return ((cm & 4) != 0);
}

static bool ida_is_data_far(cm_t cm)
{
	return ((cm &= CM_M_MASK) && cm != CM_M_FN);
}

static int ida_install_custom_argloc(IntPtr custloc)
{
	return install_custom_argloc((const custloc_desc_t*)(custloc.ToPointer()));
}

static bool ida_remove_custom_argloc(int idx)
{
	return remove_custom_argloc(idx);
}

static IntPtr ida_retrieve_custom_argloc(int idx)
{
	return IntPtr((void*)retrieve_custom_argloc(idx));
}

static int ida_verify_argloc(IntPtr vloc, int size, IntPtr gaps)
{
	return verify_argloc(*(argloc_t*)(vloc.ToPointer()), size, (const rangeset_t*)(gaps.ToPointer()));
}

static bool ida_optimize_argloc(IntPtr vloc, int size, IntPtr gaps)
{
	return optimize_argloc((argloc_t*)(vloc.ToPointer()), size, (const rangeset_t*)(gaps.ToPointer()));
}

static size_t ida_print_argloc(IntPtr buf, size_t bufsize, IntPtr vloc, int size, int vflags)
{
	return print_argloc((char*)(buf.ToPointer()), bufsize, *(const argloc_t*)(vloc.ToPointer()), size, vflags);
}

static int ida_for_all_arglocs(IntPtr vv, IntPtr vloc, int size, int off)
{
	return for_all_arglocs(*(aloc_visitor_t*)(vv.ToPointer()), *(argloc_t*)(vloc.ToPointer()), size, off);
}

static int ida_for_all_const_arglocs(IntPtr vv, IntPtr vloc, int size, int off)
{
	return for_all_arglocs(*(aloc_visitor_t*)(vv.ToPointer()), *(argloc_t*)(vloc.ToPointer()), size, off);
}

static cm_t ida_get_cc(cm_t cm)
{
	return (cm & CM_CC_MASK);
}

static cm_t ida_get_effective_cc(cm_t cm)
{
	cm_t ret = get_cc(cm);
	if (ret <= CM_CC_UNKNOWN)
		ret = get_cc(inf_get_cc_cm());
	return ret;
}

static bool ida_is_user_cc(cm_t cm)
{
	return get_cc(cm) >= CM_CC_SPECIALE;
}

static bool ida_is_vararg_cc(cm_t cm)
{
	return get_cc(cm) == CM_CC_ELLIPSIS || get_cc(cm) == CM_CC_SPECIALE;
}

static bool ida_is_purging_cc(cm_t cm)
{
	return get_cc(cm) == CM_CC_STDCALL || get_cc(cm) == CM_CC_PASCAL || get_cc(cm) == CM_CC_SPECIALP || get_cc(cm) == CM_CC_FASTCALL || get_cc(cm) == CM_CC_THISCALL || get_cc(cm) == CM_CC_SWIFT;
}

static bool ida_is_golang_cc(cm_t cc)
{
	return get_cc(cc) == CM_CC_GOLANG;
}

static bool ida_is_swift_cc(cm_t cc)
{
	return get_cc(cc) == CM_CC_SWIFT;
}

static comp_t ida_get_comp(comp_t comp)
{
	return (comp & COMP_MASK);
}

static IntPtr ida_get_compiler_name(comp_t id)
{
	const char* compilerName = get_compiler_name(id);
	return IntPtr((void*)compilerName);
}

static IntPtr ida_get_compiler_abbr(comp_t id)
{
	return IntPtr((void*)get_compiler_abbr(id));
}

static void ida_get_compilers(IntPtr ids, IntPtr names, IntPtr abbrs)
{
	get_compilers((compvec_t*)(ids.ToPointer()), (qstrvec_t*)(names.ToPointer()), (qstrvec_t*)(abbrs.ToPointer()));
}

static comp_t ida_is_comp_unsure(comp_t comp)
{
	return (comp & COMP_UNSURE);
}

static comp_t ida_default_compiler()
{
	return get_comp(inf_get_cc_id());
}

static bool ida_is_gcc()
{
	return default_compiler() == COMP_GNU;
}

static bool ida_is_gcc32()
{
	return is_gcc() && !inf_is_64bit();
}

static bool ida_is_gcc64()
{
	return is_gcc() && inf_is_64bit();
}

static bool ida_gcc_layout()
{
	return is_gcc() || (inf_get_abibits() & 128) != 0;
}

static bool ida_set_compiler(IntPtr cc, int flags, IntPtr abiname)
{
	return set_compiler(*(compiler_info_t*)(cc.ToPointer()), flags, (const char*)(abiname.ToPointer()));
}

static bool ida_set_compiler_id(comp_t id, IntPtr abiname)
{
	compiler_info_t cc;
	cc.id = id;
	return set_compiler(cc, SETCOMP_ONLY_ID, (const char*)(abiname.ToPointer()));
}

static bool ida_set_abi_name(IntPtr abiname, bool user_level)
{
	compiler_info_t cc;
	cc.id = 0;
	int flags = SETCOMP_ONLY_ABI | (user_level ? SETCOMP_BY_USER : 0);
	return set_compiler(cc, flags, (const char*)(abiname.ToPointer()));
}

static ssize_t ida_get_abi_name(IntPtr out)
{
	qstring buf;
	auto len = get_abi_name(&buf);
	if (out != IntPtr::Zero)
		::ConvertQstringToIntPtr(buf, out, len);
	return len;
}

static bool ida_append_abi_opts(IntPtr abi_opts, bool user_level)
{
	return append_abi_opts((const char*)(abi_opts.ToPointer()), user_level);
}

static bool ida_remove_abi_opts(IntPtr abi_opts, bool user_level)
{
	return remove_abi_opts((const char*)(abi_opts.ToPointer()), user_level);
}

static bool ida_set_compiler_string(IntPtr compstr, bool user_level)
{
	return set_compiler_string((const char*)(compstr.ToPointer()), user_level);
}

static bool ida_use_golang_cc()
{
	return is_golang_cc(inf_get_cc_cm());
}

static void ida_switch_to_golang()
{
	cm_t cm = inf_get_cc_cm() & ~CM_CC_MASK;
	inf_set_cc_cm(cm | CM_CC_GOLANG);
	if (default_compiler() == COMP_UNK)
		set_compiler_id(COMP_GNU);
}

static int ida_h2ti(IntPtr ti, IntPtr lx, IntPtr input, int flags, IntPtr type_cb, IntPtr var_cb, IntPtr print_cb, IntPtr _cb_data, abs_t _isabs)
{
	return h2ti((til_t*)(ti.ToPointer()), (lexer_t*)(lx.ToPointer()), (const char*)(input.ToPointer()), flags, (h2ti_type_cb*)(type_cb.ToPointer()), (h2ti_type_cb*)(var_cb.ToPointer()), (printer_t*)(print_cb.ToPointer()), (void*)(_cb_data.ToPointer()), _isabs);
}

static bool ida_parse_decl(IntPtr tif, IntPtr out, IntPtr til, IntPtr decl, int flags)
{
	return parse_decl((tinfo_t*)(tif.ToPointer()), (qstring*)(out.ToPointer()), (til_t*)(til.ToPointer()), (const char*)(decl.ToPointer()), flags);
}

static int ida_convert_pt_flags_to_hti(int pt_flags)
{
	return ((pt_flags >> 4) & 31) << 12;
}

static int ida_parse_decls(IntPtr til, IntPtr input, IntPtr printer, int hti_flags)
{
	return parse_decls((til_t*)(til.ToPointer()), (const char*)(input.ToPointer()), (printer_t*)(printer.ToPointer()), hti_flags);
}

static bool ida_print_type(IntPtr out, ea_t ea, int prtype_flags)
{
	return print_type((qstring*)(out.ToPointer()), ea, prtype_flags);
}

static int ida_get_named_type(IntPtr ti, IntPtr name, int ntf_flags, IntPtr type, IntPtr fields, IntPtr cmt, IntPtr fieldcmts, IntPtr sclass, IntPtr value)
{
	return get_named_type((const til_t*)(ti.ToPointer()), (const char*)(name.ToPointer()), ntf_flags, (const type_t**)(type.ToPointer()), (const p_list**)(fields.ToPointer()), (const char**)(cmt.ToPointer()), (const p_list**)(fieldcmts.ToPointer()), (sclass_t*)(sclass.ToPointer()), (uint32*)(value.ToPointer()));
}

static int ida_get_named_type64(IntPtr ti, IntPtr name, int ntf_flags, IntPtr type, IntPtr fields, IntPtr cmt, IntPtr fieldcmts, IntPtr sclass, IntPtr value)
{
	return get_named_type((const til_t*)(ti.ToPointer()), (const char*)(name.ToPointer()), ntf_flags | 64, (const type_t**)(type.ToPointer()), (const p_list**)(fields.ToPointer()), (const char**)(cmt.ToPointer()), (const p_list**)(fieldcmts.ToPointer()), (sclass_t*)(sclass.ToPointer()), (uint32*)(value.ToPointer()));
}

static bool ida_del_named_type(IntPtr ti, IntPtr name, int ntf_flags)
{
	return del_named_type((til_t*)(ti.ToPointer()), (const char*)(name.ToPointer()), ntf_flags);
}

static IntPtr ida_first_named_type(IntPtr ti, int ntf_flags)
{
	return IntPtr((void*)first_named_type((const til_t*)(ti.ToPointer()), ntf_flags));
}

static IntPtr ida_next_named_type(IntPtr ti, IntPtr name, int ntf_flags)
{
	return IntPtr((void*)next_named_type((const til_t*)(ti.ToPointer()), (const char*)(name.ToPointer()), ntf_flags));
}

static uint32 ida_copy_named_type(IntPtr dsttil, IntPtr srctil, IntPtr name)
{
	return copy_named_type((til_t*)(dsttil.ToPointer()), (const til_t*)(srctil.ToPointer()), (const char*)(name.ToPointer()));
}

static bool ida_decorate_name(IntPtr out, IntPtr name, bool mangle, cm_t cc, IntPtr type)
{
	return decorate_name((qstring*)(out.ToPointer()), (const char*)(name.ToPointer()), mangle, cc, (const tinfo_t*)(type.ToPointer()));
}

static bool ida_gen_decorate_name(IntPtr out, IntPtr name, bool mangle, cm_t cc, IntPtr type)
{
	return gen_decorate_name((qstring*)(out.ToPointer()), (const char*)(name.ToPointer()), mangle, cc, (const tinfo_t*)(type.ToPointer()));
}

static ssize_t ida_calc_c_cpp_name(IntPtr out, IntPtr name, IntPtr type, int ccn_flags)
{
	return calc_c_cpp_name((qstring*)(out.ToPointer()), (const char*)(name.ToPointer()), (const tinfo_t*)(type.ToPointer()), ccn_flags);
}

static bool ida_enable_numbered_types(IntPtr ti, bool enable)
{
	return enable_numbered_types((til_t*)(ti.ToPointer()), enable);
}

static bool ida_get_numbered_type(IntPtr ti, uint32 ordinal, IntPtr type, IntPtr fields, IntPtr cmt, IntPtr fieldcmts, IntPtr sclass)
{
	return get_numbered_type((const til_t*)(ti.ToPointer()), ordinal, (const type_t**)(type.ToPointer()), (const p_list**)(fields.ToPointer()), (const char**)(cmt.ToPointer()), (const p_list**)(fieldcmts.ToPointer()), (sclass_t*)(sclass.ToPointer()));
}

static uint32 ida_alloc_type_ordinals(IntPtr ti, int qty)
{
	return alloc_type_ordinals((til_t*)(ti.ToPointer()), qty);
}

static uint32 ida_alloc_type_ordinal(IntPtr ti)
{
	return alloc_type_ordinals((til_t*)(ti.ToPointer()), 1);
}

static uint32 ida_get_ordinal_qty(IntPtr ti)
{
	return get_ordinal_qty((const til_t*)(ti.ToPointer()));
}

static tinfo_code_t ida_set_numbered_type(IntPtr ti, uint32 ordinal, int ntf_flags, IntPtr name, IntPtr type, IntPtr fields, IntPtr cmt, IntPtr fldcmts, IntPtr sclass)
{
	return set_numbered_type((til_t*)(ti.ToPointer()), ordinal, ntf_flags, (const char*)(name.ToPointer()), (const type_t*)(type.ToPointer()), (const p_list*)(fields.ToPointer()), (const char*)(cmt.ToPointer()), (const p_list*)(fldcmts.ToPointer()), (sclass_t*)(sclass.ToPointer()));
}

static bool ida_del_numbered_type(IntPtr ti, uint32 ordinal)
{
	return del_numbered_type((til_t*)(ti.ToPointer()), ordinal);
}

static bool ida_set_type_alias(IntPtr ti, uint32 src_ordinal, uint32 dst_ordinal)
{
	return set_type_alias((til_t*)(ti.ToPointer()), src_ordinal, dst_ordinal);
}

static uint32 ida_get_alias_target(IntPtr ti, uint32 ordinal)
{
	return get_alias_target((const til_t*)(ti.ToPointer()), ordinal);
}

static int32 ida_get_type_ordinal(IntPtr ti, IntPtr name)
{
	return get_type_ordinal((const til_t*)(ti.ToPointer()), (const char*)(name.ToPointer()));
}

static IntPtr ida_get_numbered_type_name(IntPtr ti, uint32 ordinal)
{
	return IntPtr((void*)get_numbered_type_name((const til_t*)(ti.ToPointer()), ordinal));
}

static ssize_t ida_create_numbered_type_name(IntPtr buf, int32 ord)
{
	return create_numbered_type_name((qstring*)(buf.ToPointer()), ord);
}

static bool ida_is_ordinal_name(IntPtr name, IntPtr ord)
{
	return is_ordinal_name((const char*)(name.ToPointer()), (uint32*)(ord.ToPointer()));
}

static int ida_get_ordinal_from_idb_type(IntPtr name, IntPtr type)
{
	return get_ordinal_from_idb_type((const char*)(name.ToPointer()), (const type_t*)(type.ToPointer()));
}

static bool ida_is_autosync(IntPtr name, IntPtr type)
{
	return get_ordinal_from_idb_type((const char*)(name.ToPointer()), (const type_t*)(type.ToPointer())) != -1;
}

static bool ida_is_autosync1(IntPtr name, IntPtr tifPtr)
{
	auto tif = *(tinfo_t*)(tifPtr.ToPointer());
	type_t decl_type = tif.get_decltype();
	return get_ordinal_from_idb_type((const char*)(name.ToPointer()), &decl_type) != -1;
}

static void ida_build_anon_type_name(IntPtr buf, IntPtr type, IntPtr fields)
{
	build_anon_type_name((qstring*)(buf.ToPointer()), (const type_t*)(type.ToPointer()), (const p_list*)(fields.ToPointer()));
}

static int ida_compact_numbered_types(IntPtr ti, uint32 min_ord, IntPtr p_ordmap, int flags)
{
	return compact_numbered_types((til_t*)(ti.ToPointer()), min_ord, (intvec_t*)(p_ordmap.ToPointer()), flags);
}

static ea_t ida_get_vftable_ea(uint32 ordinal)
{
	return get_vftable_ea(ordinal);
}

static uint32 ida_get_vftable_ordinal(ea_t vftable_ea)
{
	return get_vftable_ordinal(vftable_ea);
}

static bool ida_set_vftable_ea(uint32 ordinal, ea_t vftable_ea)
{
	return set_vftable_ea(ordinal, vftable_ea);
}

static bool ida_del_vftable_ea(uint32 ordinal)
{
	return set_vftable_ea(ordinal, ea_t(-1));
}

static size_t ida_get_default_align()
{
	return inf_get_cc_defalign();
}

static void ida_align_size(IntPtr cur_tot_size, size_t elem_size, size_t algn)
{
	size_t al = elem_size;
	if (algn != 0 && algn < al)
		al = algn;
	*(size_t*)(cur_tot_size.ToPointer()) = align_up(*(size_t*)(cur_tot_size.ToPointer()), al);
}

static bool ida_deref_ptr(IntPtr eaPtr, IntPtr tifPtr, IntPtr closeure_objPtr)
{
	return deref_ptr((ea_t*)(eaPtr.ToPointer()), *(tinfo_t*)(tifPtr.ToPointer()), (ea_t*)(closeure_objPtr.ToPointer()));
}

static bool ida_remove_tinfo_pointer(IntPtr tif, IntPtr pname, IntPtr til)
{
	return remove_tinfo_pointer((tinfo_t*)(tif.ToPointer()), (const char**)(pname.ToPointer()), (const til_t*)(til.ToPointer()));
}

static tid_t ida_import_type(IntPtr til, int idx, IntPtr name, int flags)
{
	return import_type((const til_t*)(til.ToPointer()), idx, (const char*)(name.ToPointer()), flags);
}

static int ida_add_til(IntPtr name, int flags)
{
	return add_til((const char*)(name.ToPointer()), flags);
}

static bool ida_del_til(IntPtr name)
{
	return del_til((const char*)(name.ToPointer()));
}

static bool ida_apply_named_type(ea_t ea, IntPtr name)
{
	return apply_named_type(ea, (const char*)(name.ToPointer()));
}

static bool ida_apply_tinfo(ea_t ea, IntPtr tifPtr, uint32 flags)
{
	return apply_tinfo(ea, *(tinfo_t*)(tifPtr.ToPointer()), flags);
}

static bool ida_apply_cdecl(IntPtr til, ea_t ea, IntPtr decl, int flags)
{
	return apply_cdecl((til_t*)(til.ToPointer()), ea, (const char*)(decl.ToPointer()), flags);
}

static bool ida_apply_callee_tinfo(ea_t caller, IntPtr tifPtr)
{
	return apply_callee_tinfo(caller, *(tinfo_t*)(tifPtr.ToPointer()));
}

static bool ida_get_arg_addrs(IntPtr out, ea_t caller)
{
	return get_arg_addrs((eavec_t*)(out.ToPointer()), caller);
}

static bool ida_apply_once_tinfo_and_name(ea_t dea, IntPtr tifPtr, IntPtr name)
{
	return apply_once_tinfo_and_name(dea, *(tinfo_t*)(tifPtr.ToPointer()), (const char*)(name.ToPointer()));
}

static int ida_guess_tinfo(IntPtr tif, tid_t id)
{
	return guess_tinfo((tinfo_t*)(tif.ToPointer()), id);
}

static void ida_set_c_header_path(IntPtr incdir)
{
	setinf_buf(INF_H_PATH, (const void*)(incdir.ToPointer()));
}

static ssize_t ida_get_c_header_path(IntPtr buf)
{
	qstring out;
	auto len = getinf_str(&out, INF_H_PATH);
	if (buf == IntPtr::Zero)
	{
		::ConvertQstringToIntPtr(out, buf, len);
	}

	return len;
}

static void ida_set_c_macros(IntPtr macros)
{
	setinf_buf(INF_C_MACROS, (const void*)(macros.ToPointer()));
}

static ssize_t ida_get_c_macros(IntPtr buf)
{
	qstring out;
	auto len = getinf_str(&out, INF_C_MACROS);
	if (buf == IntPtr::Zero)
	{
		::ConvertQstringToIntPtr(out, buf, len);
	}

	return len;
}

static IntPtr ida_get_idati()
{
	return IntPtr((void*)get_idati());
}

static bool ida_get_idainfo_by_type(IntPtr out_size, IntPtr out_flags, IntPtr out_mt, IntPtr tifPtr, IntPtr out_alsize)
{
	return get_idainfo_by_type((size_t*)(out_size.ToPointer()), (flags_t*)(out_flags.ToPointer()), (opinfo_t*)(out_mt.ToPointer()), *(tinfo_t*)(tifPtr.ToPointer()), (size_t*)(out_alsize.ToPointer()));
}

static bool ida_get_idainfo64_by_type(IntPtr out_size, IntPtr out_flags, IntPtr out_mt, IntPtr tifPtr, IntPtr out_alsize)
{
	return get_idainfo64_by_type((size_t*)(out_size.ToPointer()), (flags64_t*)(out_flags.ToPointer()), (opinfo_t*)(out_mt.ToPointer()), *(tinfo_t*)(tifPtr.ToPointer()), (size_t*)(out_alsize.ToPointer()));
}

static void ida_copy_tinfo_t(IntPtr _this, IntPtr r)
{
	return copy_tinfo_t((tinfo_t*)(_this.ToPointer()), *(tinfo_t*)(r.ToPointer()));
}

static void ida_clear_tinfo_t(IntPtr _this)
{
	return clear_tinfo_t((tinfo_t*)(_this.ToPointer()));
}

static bool ida_create_tinfo(IntPtr _this, type_t bt, type_t bt2, IntPtr ptr)
{
	return create_tinfo((tinfo_t*)(_this.ToPointer()), bt, bt2, (void*)(ptr.ToPointer()));
}

static int ida_verify_tinfo(uint32 typid)
{
	return verify_tinfo(typid);
}

static bool ida_get_tinfo_details(uint32 typid, type_t bt2, IntPtr buf)
{
	qstring out;
	auto ret = get_tinfo_details(typid, bt2, &out);
	if (buf != IntPtr::Zero)
	{
		::ConvertQstringToIntPtr(out, buf, out.size() - 1);
	}

	return ret;
}

static size_t ida_get_tinfo_size(IntPtr p_effalign, uint32 typid, int gts_code)
{
	return get_tinfo_size((uint32*)(p_effalign.ToPointer()), typid, gts_code);
}

static size_t ida_get_tinfo_pdata(IntPtr outptr, uint32 typid, int what)
{
	return get_tinfo_pdata((void*)(outptr.ToPointer()), typid, what);
}

static size_t ida_get_tinfo_property(uint32 typid, int gta_prop)
{
	return get_tinfo_property(typid, gta_prop);
}

static size_t ida_set_tinfo_property(IntPtr tif, int sta_prop, size_t x)
{
	return set_tinfo_property((tinfo_t*)(tif.ToPointer()), sta_prop, x);
}

static bool ida_serialize_tinfo(qtype* type, qtype* fields, qtype* fldcmts, const tinfo_t* tif, int sudt_flags)
{
	// ???
	return true;
}

static bool ida_deserialize_tinfo(IntPtr tifPtr, IntPtr tilPtr, IntPtr ptype, IntPtr pfields, IntPtr pfldcmts)
{
	return deserialize_tinfo((tinfo_t*)(tifPtr.ToPointer()), (til_t*)(tilPtr.ToPointer()), (const type_t**)(ptype.ToPointer()), (const p_list**)(pfields.ToPointer()), (const p_list**)(pfldcmts.ToPointer()));
}

static int  ida_find_tinfo_udt_member(IntPtr udmPtr, uint32 typid, int strmem_flags)
{
	return find_tinfo_udt_member((udt_member_t*)(udmPtr.ToPointer()), typid, strmem_flags);
}

static bool ida_print_tinfo(IntPtr result, IntPtr prefix, int indent, int cmtindent, int flags, IntPtr tif, IntPtr name, IntPtr cmt)
{
	qstring out;
	auto ret = print_tinfo(&out, (const char*)(prefix.ToPointer()), indent, cmtindent, flags, (const tinfo_t*)(tif.ToPointer()), (const char*)(name.ToPointer()), (const char*)(cmt.ToPointer()));
	if (result != IntPtr::Zero)
	{
		::ConvertQstringToIntPtr(out, result, out.size() - 1);
	}

	return ret;
}

static IntPtr ida_dstr_tinfo(IntPtr tifPtr)
{
	return IntPtr((void*)dstr_tinfo((const tinfo_t*)(tifPtr.ToPointer())));
}

static int  ida_visit_subtypes(IntPtr visitor, IntPtr out, IntPtr tif, IntPtr name, IntPtr cmt)
{
	return visit_subtypes((tinfo_visitor_t*)(visitor.ToPointer()), (type_mods_t*)(out.ToPointer()), *(const tinfo_t*)(tif.ToPointer()), (const char*)(name.ToPointer()), (const char*)(cmt.ToPointer()));
}

static bool ida_compare_tinfo(uint32 t1, uint32 t2, int tcflags)
{
	return compare_tinfo(t1, t2, tcflags);
}

static int  ida_lexcompare_tinfo(uint32 t1, uint32 t2, int _0)
{
	return lexcompare_tinfo(t1, t2, _0);
}

static bool ida_get_stock_tinfo(IntPtr tif, stock_type_id_t id)
{
	return get_stock_tinfo((tinfo_t*)(tif.ToPointer()), id);
}

static uint64 ida_read_tinfo_bitfield_value(uint32 typid, uint64 v, int bitoff)
{
	return read_tinfo_bitfield_value(typid, v, bitoff);
}

static uint64 ida_write_tinfo_bitfield_value(uint32 typid, uint64 dst, uint64 v, int bitoff)
{
	return write_tinfo_bitfield_value(typid, dst, v, bitoff);
}

static bool ida_get_tinfo_attr(uint32 typid, String^ key, IntPtr bvPtr, bool all_attrs)
{
	std::string temp = marshal_as<std::string>(key);
	qstring qkey(temp.c_str());
	return get_tinfo_attr(typid, qkey, (bytevec_t*)(bvPtr.ToPointer()), all_attrs);
}

static bool ida_set_tinfo_attr(IntPtr tifPtr, IntPtr taPtr, bool may_overwrite)
{
	return set_tinfo_attr((tinfo_t*)(tifPtr.ToPointer()), *(type_attr_t*)(taPtr.ToPointer()), may_overwrite);
}

static bool ida_del_tinfo_attr(IntPtr tifPtr, String^ key, bool make_copy)
{
	std::string temp = marshal_as<std::string>(key);
	qstring qkey(temp.c_str());
	return del_tinfo_attr((tinfo_t*)(tifPtr.ToPointer()), qkey, make_copy);
}

static bool ida_get_tinfo_attrs(uint32 typid, IntPtr tavPtr, bool include_ref_attrs)
{
	return get_tinfo_attrs(typid, (type_attrs_t*)(tavPtr.ToPointer()), include_ref_attrs);
}

static bool ida_set_tinfo_attrs(IntPtr tifPtr, IntPtr taPtr)
{
	return set_tinfo_attrs((tinfo_t*)(tifPtr.ToPointer()), (type_attrs_t*)(taPtr.ToPointer()));
}

static uint32 ida_score_tinfo(IntPtr tifPtr)
{
	return score_tinfo((tinfo_t*)(tifPtr.ToPointer()));
}

static tinfo_code_t ida_save_tinfo(IntPtr tifPtr, IntPtr tilPtr, size_t ord, IntPtr name, int ntf_flags)
{
	return save_tinfo((tinfo_t*)(tifPtr.ToPointer()), (til_t*)(tilPtr.ToPointer()), ord, (const char*)(name.ToPointer()), ntf_flags);
}

static tinfo_code_t ida_save_tinfo2(IntPtr tifPtr, IntPtr tilPtr, size_t ord, IntPtr name, IntPtr cmt, int ntf_flags)
{
	return save_tinfo2((tinfo_t*)(tifPtr.ToPointer()), (til_t*)(tilPtr.ToPointer()), ord, (const char*)(name.ToPointer()), (const char*)(cmt.ToPointer()), ntf_flags);
}

static bool ida_append_tinfo_covered(IntPtr out, uint32 typid, uint64 offset)
{
	return append_tinfo_covered((rangeset_t*)(out.ToPointer()), typid, offset);
}

static bool ida_calc_tinfo_gaps(IntPtr out, uint32 typid)
{
	return calc_tinfo_gaps((rangeset_t*)(out.ToPointer()), typid);
}

static bool ida_name_requires_qualifier(IntPtr out, uint32 typid, IntPtr name, uint64 offset)
{
	qstring buf;
	auto ret = name_requires_qualifier(&buf, typid, (const char*)(name.ToPointer()), offset);
	if (out == IntPtr::Zero)
	{
		::ConvertQstringToIntPtr(buf, out, buf.size() - 1);
	}

	return ret;
}

/*
static bool ida_enum_type_data_t__set_bf(IntPtr _this, bool bf)
{
	// does not exists in freeware version 8.3, 8.4
	return enum_type_data_t__set_bf((enum_type_data_t*)_this.ToPointer(), bf);
}
*/

static cm_t ida_guess_func_cc(IntPtr ftiPtr, int npurged, int cc_flags)
{
	return guess_func_cc(*(const func_type_data_t*)(ftiPtr.ToPointer()), npurged, cc_flags);
}

static bool ida_dump_func_type_data(IntPtr buf, IntPtr ftiPtr, int praloc_bits)
{
	qstring out;
	auto ret = dump_func_type_data(&out, *(const func_type_data_t*)(ftiPtr.ToPointer()), praloc_bits);
	if (buf != IntPtr::Zero)
	{
		::ConvertQstringToIntPtr(out, buf, out.size() - 1);
	}

	return ret;
}

static bool ida_inf_pack_stkargs(cm_t cc)
{
	return is_golang_cc(get_effective_cc(cc)) || inf_pack_stkargs();
}

static bool ida_inf_big_arg_align(cm_t cc)
{
	return !is_golang_cc(get_effective_cc(cc)) && inf_big_arg_align();
}

static bool ida_inf_huge_arg_align(cm_t cc)
{
	return !is_golang_cc(get_effective_cc(cc)) && inf_huge_arg_align();
}

static int ida_get_arg_align(int type_align, int slotsize, cm_t cc)
{
	do
		if (!(is_pow2(type_align)))
			interr(2858);
	while (0);
	if (type_align > slotsize * 2) {
		if (inf_huge_arg_align(cc))
			return type_align;
		type_align = slotsize * 2;
	}
	return type_align < slotsize ? inf_pack_stkargs(cc) ? type_align : slotsize : inf_big_arg_align(cc) ? type_align : slotsize;
}

static int ida_get_arg_align(IntPtr tifPtr, int slotsize, cm_t cc)
{
	auto tif = *(tinfo_t*)(tifPtr.ToPointer());
	uint32 align = 0;
	tif.get_size(&align);
	return get_arg_align(align, slotsize, cc);
}

static sval_t ida_align_stkarg_up(sval_t spoff, int type_align, int slotsize, cm_t cc)
{
	uint32 align = get_arg_align(type_align, slotsize, cc);
	return align_up(spoff, align);
}

static long long ida_align_stkarg_up(sval_t spoff, IntPtr tifPtr, int slotsize, cm_t cc)
{
	auto tif = *(tinfo_t*)(tifPtr.ToPointer());
	uint32 align = get_arg_align(tif, slotsize, cc);
	return align_up(spoff, align);
}

static error_t ida_unpack_idcobj_from_idb(IntPtr objPtr, IntPtr tifPtr, ea_t ea, IntPtr off0Ptr, int pio_flags)
{
	return unpack_idcobj_from_idb((idc_value_t*)(objPtr.ToPointer()), *(tinfo_t*)(tifPtr.ToPointer()), ea, (const bytevec_t*)(off0Ptr.ToPointer()), pio_flags);
}

static error_t ida_unpack_idcobj_from_bv(IntPtr objPtr, IntPtr tifPtr, IntPtr bytesPtr, int pio_flags)
{
	return unpack_idcobj_from_bv((idc_value_t*)(objPtr.ToPointer()), *(tinfo_t*)(tifPtr.ToPointer()), *(const bytevec_t*)(bytesPtr.ToPointer()), pio_flags);
}

static error_t ida_pack_idcobj_to_idb(IntPtr objPtr, IntPtr tifPtr, ea_t ea, int pio_flags)
{
	return pack_idcobj_to_idb((const idc_value_t*)(objPtr.ToPointer()), *(const tinfo_t*)(tifPtr.ToPointer()), ea, pio_flags);
}

static error_t ida_pack_idcobj_to_bv(IntPtr objPtr, IntPtr tifPtr, IntPtr bytesPtr, IntPtr objoffPtr, int pio_flags)
{
	return pack_idcobj_to_bv((const idc_value_t*)(objPtr.ToPointer()), *(const tinfo_t*)(tifPtr.ToPointer()), (relobj_t*)(bytesPtr.ToPointer()), (void*)(objoffPtr.ToPointer()), pio_flags);
}

static bool ida_apply_tinfo_to_stkarg(IntPtr insnPtr, IntPtr xPtr, uval_t v, IntPtr tifPtr, IntPtr namePtr)
{
	return apply_tinfo_to_stkarg(*(const insn_t*)(insnPtr.ToPointer()), *(op_t*)(xPtr.ToPointer()), v, *(tinfo_t*)(tifPtr.ToPointer()), (const char*)(namePtr.ToPointer()));
}

static void ida_gen_use_arg_tinfos2(IntPtr _this, ea_t caller, IntPtr fti, IntPtr rargs)
{
	gen_use_arg_tinfos2((argtinfo_helper_t*)(_this.ToPointer()), caller, (func_type_data_t*)(fti.ToPointer()), (funcargvec_t*)(rargs.ToPointer()));
}

static bool ida_func_has_stkframe_hole(ea_t ea, IntPtr ftiPtr)
{
	return func_has_stkframe_hole(ea, *(func_type_data_t*)(ftiPtr.ToPointer()));
}

static int ida_lower_type(IntPtr til, IntPtr tif, IntPtr name, IntPtr _helper)
{
	return lower_type((til_t*)(til.ToPointer()), (tinfo_t*)(tif.ToPointer()), (const char*)(name.ToPointer()), (lowertype_helper_t*)(_helper.ToPointer()));
}

static int ida_replace_ordinal_typerefs(IntPtr til, IntPtr tif)
{
	return replace_ordinal_typerefs((til_t*)(til.ToPointer()), (tinfo_t*)(tif.ToPointer()));
}

static void ida_begin_type_updating(update_type_t utp)
{
	begin_type_updating(utp);
}

static void ida_end_type_updating(update_type_t utp)
{
	end_type_updating(utp);
}

//static bool ida_format_cdata(IntPtr outvec,IntPtr idc_valuePtr, IntPtr tifPtr, IntPtr vtreePtr, IntPtr fdiPtr)
//{
//
//}

static int ida_print_cdata(IntPtr printerPtr, IntPtr idc_valuePtr, IntPtr tifPtr, IntPtr fdiPtr)
{
	return print_cdata(*(text_sink_t*)(printerPtr.ToPointer()), *(const idc_value_t*)(idc_valuePtr.ToPointer()), (tinfo_t*)(tifPtr.ToPointer()), (const format_data_info_t*)(fdiPtr.ToPointer()));
}

static int ida_print_decls(IntPtr printerPtr, IntPtr tilPtr, IntPtr ordinalsPtr, uint32 pdf_flags)
{
	return print_decls(*(text_sink_t*)(printerPtr.ToPointer()), (til_t*)(tilPtr.ToPointer()), (const ordvec_t*)(ordinalsPtr.ToPointer()), pdf_flags);
}

static int ida_calc_number_of_children(IntPtr locPtr, IntPtr tifPtr, bool dont_deref_ptr)
{
	return calc_number_of_children(*(const argloc_t*)(locPtr.ToPointer()), *(tinfo_t*)(tifPtr.ToPointer()), dont_deref_ptr);
}

static size_t ida_format_c_number(IntPtr buf, size_t bufsize, uint128 value, int size, int pcn)
{
	return format_c_number((char*)(buf.ToPointer()), bufsize, value, size, pcn);
}

static bool ida_get_enum_member_expr(IntPtr out, IntPtr tifPtr, int serial, uint64 value)
{
	qstring buf;
	auto ret = get_enum_member_expr(&buf, *(tinfo_t*)(tifPtr.ToPointer()), serial, value);
	if (out != IntPtr::Zero)
	{
		::ConvertQstringToIntPtr(buf, out, buf.size() - 1);
	}
	return ret;
}

static bool ida_choose_named_type(IntPtr out_sym, IntPtr root_til, IntPtr title, int ntf_flags, IntPtr predicate)
{
	return choose_named_type((til_symbol_t*)(out_sym.ToPointer()), (const til_t*)(root_til.ToPointer()), (const char*)(title.ToPointer()), ntf_flags, (predicate_t*)(predicate.ToPointer()));
}

static uint32 ida_choose_local_tinfo(IntPtr ti, IntPtr title, IntPtr func, uint32 def_ord, IntPtr ud)
{
	return choose_local_tinfo((const til_t*)(ti.ToPointer()), (const char*)(title.ToPointer()), (local_tinfo_predicate_t*)(func.ToPointer()), def_ord, (void*)(ud.ToPointer()));
}

static uint32 ida_choose_local_tinfo_and_delta(IntPtr delta, IntPtr ti, IntPtr title, IntPtr func, uint32 def_ord, IntPtr ud)
{
	return choose_local_tinfo_and_delta((int32*)(delta.ToPointer()), (const til_t*)(ti.ToPointer()), (const char*)(title.ToPointer()), (local_tinfo_predicate_t*)(func.ToPointer()), def_ord, (void*)(ud.ToPointer()));
}

// deprecated
//static void ida_gen_use_arg_tinfos(ea_t caller, IntPtr fti, IntPtr rargs, IntPtr set_optype, IntPtr is_stkarg_load, IntPtr has_delay_slot)
//{
//	gen_use_arg_tinfos(caller, (func_type_data_t*)(fti.ToPointer()), (funcargvec_t*)(rargs.ToPointer()), (set_op_tinfo_t*)(set_optype.ToPointer()), (is_stkarg_load_t*)(is_stkarg_load.ToPointer()), (has_delay_slot_t*)(has_delay_slot.ToPointer()));
//}
