#pragma once

/*

static bool ida_is_may_access(maymust_t maymust)
{

}

static bool ida_is_mcode_addsub(mcode_t mcode)
{

}

static bool ida_is_mcode_xdsu(mcode_t mcode)
{

}

static bool ida_is_mcode_set(mcode_t mcode)
{

}

static bool ida_is_mcode_set1(mcode_t mcode)
{

}

static bool ida_is_mcode_j1(mcode_t mcode)
{

}

static bool ida_is_mcode_jcond(mcode_t mcode)
{

}

static bool ida_is_mcode_convertible_to_jmp(mcode_t mcode)
{

}

static bool ida_is_mcode_convertible_to_set(mcode_t mcode)
{

}

static bool ida_is_mcode_call(mcode_t mcode)
{

}

static bool ida_is_mcode_fpu(mcode_t mcode)
{

}

static bool ida_is_mcode_commutative(mcode_t mcode)
{

}

static bool ida_is_mcode_shift(mcode_t mcode)
{

}

static bool ida_is_mcode_divmod(mcode_t op)
{

}

static bool ida_has_mcode_seloff(mcode_t op)
{

}

static mcode_t ida_set2jcnd(mcode_t code)
{

}

static mcode_t ida_jcnd2set(mcode_t code)
{

}

static bool ida_is_signed_mcode(mcode_t code)
{

}

static bool ida_is_unsigned_mcode(mcode_t code)
{

}

static bool ida_is_ptr_or_array(type_t t)
{

}

static bool ida_is_paf(type_t t)
{

}

static bool ida_is_inplace_def(ref tinfo_t type)
{

}

static tinfo_t ida_create_typedef(int n)
{

}

static bool ida_rename_lvar(ea_t func_ea, char* oldname, char* newname)
{

}

static minsn_t* ida_getf_reginsn(minsn_t* ins)
{

}

static minsn_t* ida_getb_reginsn(minsn_t* ins)
{

}

*/
static bool ida_op_uses_x(ctype_t op)
{
	return op_uses_x(op);
}

static bool ida_op_uses_y(ctype_t op)
{
	return op_uses_y(op);
}

static bool ida_op_uses_z(ctype_t op)
{
	return op_uses_z(op);
}

static bool ida_is_binary(ctype_t op)
{
	return is_binary(op);
}

static bool ida_is_unary(ctype_t op)
{
	return is_unary(op);
}

static bool ida_is_relational(ctype_t op)
{
	return is_relational(op);
}

static bool ida_is_assignment(ctype_t op)
{
	return is_assignment(op);
}

static bool ida_accepts_udts(ctype_t op)
{
	return accepts_udts(op);
}

static bool ida_is_prepost(ctype_t op)
{
	return is_prepost(op);
}

static bool ida_is_commutative(ctype_t op)
{
	return is_commutative(op);
}

static bool ida_is_additive(ctype_t op)
{
	return is_additive(op);
}

static bool ida_is_multiplicative(ctype_t op)
{
	return is_multiplicative(op);
}

static bool ida_is_bitop(ctype_t op)
{
	return is_bitop(op);
}

static bool ida_is_logical(ctype_t op)
{
	return is_logical(op);
}

static bool ida_is_loop(ctype_t op)
{
	return is_loop(op);
}

static bool ida_is_break_consumer(ctype_t op)
{
	return is_break_consumer(op);
}

static bool ida_is_lvalue(ctype_t op)
{
	return is_lvalue(op);
}

static bool ida_accepts_small_udts(ctype_t op)
{
	return accepts_small_udts(op);
}

/*
static cexpr_t* ida_create_helper(bool standalone, ref tinfo_t type, char* format, ...)
{

}

static cexpr_t* ida_call_helper(ref tinfo_t rettype, carglist_t* args, char* format, ...)
{

}

*/

static bool ida_decompile_func(ea_t ea)
{
	auto cfptrs = decompile_func(get_func(ea), nullptr, 0);
	return cfptrs != nullptr;
}

/*

static cfuncptr_t ida_decompile_snippet(ref rangevec_t ranges, hexrays_failure_t* hf, int decomp_flags)
{

}
*/
static bool ida_init_hexrays_plugin(int flags)
{
	return init_hexrays_plugin(flags);
}

static void ida_term_hexrays_plugin()
{
	term_hexrays_plugin();
}

/*
static operand_locator_t& ida_user_numforms_first(user_numforms_iterator_t p)
{

}

static number_format_t& ida_user_numforms_second(user_numforms_iterator_t p)
{

}

static user_numforms_iterator_t ida_user_numforms_find(user_numforms_t* map, ref operand_locator_t key)
{

}

static user_numforms_iterator_t ida_user_numforms_insert(user_numforms_t* map, ref operand_locator_t key, ref number_format_t val)
{

}

static user_numforms_iterator_t ida_user_numforms_begin(user_numforms_t* map)
{

}

static user_numforms_iterator_t ida_user_numforms_end(user_numforms_t* map)
{

}

static user_numforms_iterator_t ida_user_numforms_next(user_numforms_iterator_t p)
{

}

static user_numforms_iterator_t ida_user_numforms_prev(user_numforms_iterator_t p)
{

}

static void ida_user_numforms_erase(user_numforms_t* map, user_numforms_iterator_t p)
{

}

static void ida_user_numforms_clear(user_numforms_t* map)
{

}

static size_t ida_user_numforms_size(user_numforms_t* map)
{

}

static void ida_user_numforms_free(user_numforms_t* map)
{

}

static user_numforms_t* ida_user_numforms_new()
{

}

static lvar_locator_t& ida_lvar_mapping_first(lvar_mapping_iterator_t p)
{

}

static lvar_locator_t& ida_lvar_mapping_second(lvar_mapping_iterator_t p)
{

}

static lvar_mapping_iterator_t ida_lvar_mapping_find(lvar_mapping_t* map, ref lvar_locator_t key)
{

}

static lvar_mapping_iterator_t ida_lvar_mapping_insert(lvar_mapping_t* map, ref lvar_locator_t key, ref lvar_locator_t val)
{

}

static lvar_mapping_iterator_t ida_lvar_mapping_begin(lvar_mapping_t* map)
{

}

static lvar_mapping_iterator_t ida_lvar_mapping_end(lvar_mapping_t* map)
{

}

static lvar_mapping_iterator_t ida_lvar_mapping_next(lvar_mapping_iterator_t p)
{

}

static lvar_mapping_iterator_t ida_lvar_mapping_prev(lvar_mapping_iterator_t p)
{

}

static void ida_lvar_mapping_erase(lvar_mapping_t* map, lvar_mapping_iterator_t p)
{

}

static void ida_lvar_mapping_clear(lvar_mapping_t* map)
{

}

static size_t ida_lvar_mapping_size(lvar_mapping_t* map)
{

}

static void ida_lvar_mapping_free(lvar_mapping_t* map)
{

}

static lvar_mapping_t* ida_lvar_mapping_new()
{

}

static ea_t& ida_udcall_map_first(udcall_map_iterator_t p)
{

}

static udcall_t& ida_udcall_map_second(udcall_map_iterator_t p)
{

}

static udcall_map_iterator_t ida_udcall_map_find(udcall_map_t* map, ref ea_t key)
{

}

static udcall_map_iterator_t ida_udcall_map_insert(udcall_map_t* map, ref ea_t key, ref udcall_t val)
{

}

static udcall_map_iterator_t ida_udcall_map_begin(udcall_map_t* map)
{

}

static udcall_map_iterator_t ida_udcall_map_end(udcall_map_t* map)
{

}

static udcall_map_iterator_t ida_udcall_map_next(udcall_map_iterator_t p)
{

}

static udcall_map_iterator_t ida_udcall_map_prev(udcall_map_iterator_t p)
{

}

static void ida_udcall_map_erase(udcall_map_t* map, udcall_map_iterator_t p)
{

}

static void ida_udcall_map_clear(udcall_map_t* map)
{

}

static size_t ida_udcall_map_size(udcall_map_t* map)
{

}

static void ida_udcall_map_free(udcall_map_t* map)
{

}

static udcall_map_t* ida_udcall_map_new()
{

}

static treeloc_t& ida_user_cmts_first(user_cmts_iterator_t p)
{

}

static citem_cmt_t& ida_user_cmts_second(user_cmts_iterator_t p)
{

}

static user_cmts_iterator_t ida_user_cmts_find(user_cmts_t* map, ref treeloc_t key)
{

}

static user_cmts_iterator_t ida_user_cmts_insert(user_cmts_t* map, ref treeloc_t key, ref citem_cmt_t val)
{

}

static user_cmts_iterator_t ida_user_cmts_begin(user_cmts_t* map)
{

}

static user_cmts_iterator_t ida_user_cmts_end(user_cmts_t* map)
{

}

static user_cmts_iterator_t ida_user_cmts_next(user_cmts_iterator_t p)
{

}

static user_cmts_iterator_t ida_user_cmts_prev(user_cmts_iterator_t p)
{

}

static void ida_user_cmts_erase(user_cmts_t* map, user_cmts_iterator_t p)
{

}

static void ida_user_cmts_clear(user_cmts_t* map)
{

}

static size_t ida_user_cmts_size(user_cmts_t* map)
{

}

static void ida_user_cmts_free(user_cmts_t* map)
{

}

static user_cmts_t* ida_user_cmts_new()
{

}

static citem_locator_t& ida_user_iflags_first(user_iflags_iterator_t p)
{

}

static int32& ida_user_iflags_second(user_iflags_iterator_t p)
{

}

static user_iflags_iterator_t ida_user_iflags_find(user_iflags_t* map, ref citem_locator_t key)
{

}

static user_iflags_iterator_t ida_user_iflags_insert(user_iflags_t* map, ref citem_locator_t key, ref int32 val)
{

}

static user_iflags_iterator_t ida_user_iflags_begin(user_iflags_t* map)
{

}

static user_iflags_iterator_t ida_user_iflags_end(user_iflags_t* map)
{

}

static user_iflags_iterator_t ida_user_iflags_next(user_iflags_iterator_t p)
{

}

static user_iflags_iterator_t ida_user_iflags_prev(user_iflags_iterator_t p)
{

}

static void ida_user_iflags_erase(user_iflags_t* map, user_iflags_iterator_t p)
{

}

static void ida_user_iflags_clear(user_iflags_t* map)
{

}

static size_t ida_user_iflags_size(user_iflags_t* map)
{

}

static void ida_user_iflags_free(user_iflags_t* map)
{

}

static user_iflags_t* ida_user_iflags_new()
{

}

static ea_t& ida_user_unions_first(user_unions_iterator_t p)
{

}

static intvec_t& ida_user_unions_second(user_unions_iterator_t p)
{

}

static user_unions_iterator_t ida_user_unions_find(user_unions_t* map, ref ea_t key)
{

}

static user_unions_iterator_t ida_user_unions_insert(user_unions_t* map, ref ea_t key, ref intvec_t val)
{

}

static user_unions_iterator_t ida_user_unions_begin(user_unions_t* map)
{

}

static user_unions_iterator_t ida_user_unions_end(user_unions_t* map)
{

}

static user_unions_iterator_t ida_user_unions_next(user_unions_iterator_t p)
{

}

static user_unions_iterator_t ida_user_unions_prev(user_unions_iterator_t p)
{

}

static void ida_user_unions_erase(user_unions_t* map, user_unions_iterator_t p)
{

}

static void ida_user_unions_clear(user_unions_t* map)
{

}

static size_t ida_user_unions_size(user_unions_t* map)
{

}

static void ida_user_unions_free(user_unions_t* map)
{

}

static user_unions_t* ida_user_unions_new()
{

}

static int& ida_user_labels_first(user_labels_iterator_t p)
{

}

static qstring& ida_user_labels_second(user_labels_iterator_t p)
{

}

static user_labels_iterator_t ida_user_labels_find(user_labels_t* map, ref int key)
{

}

static user_labels_iterator_t ida_user_labels_insert(user_labels_t* map, ref int key, ref qstring val)
{

}

static user_labels_iterator_t ida_user_labels_begin(user_labels_t* map)
{

}

static user_labels_iterator_t ida_user_labels_end(user_labels_t* map)
{

}

static user_labels_iterator_t ida_user_labels_next(user_labels_iterator_t p)
{

}

static user_labels_iterator_t ida_user_labels_prev(user_labels_iterator_t p)
{

}

static void ida_user_labels_erase(user_labels_t* map, user_labels_iterator_t p)
{

}

static void ida_user_labels_clear(user_labels_t* map)
{

}

static size_t ida_user_labels_size(user_labels_t* map)
{

}

static void ida_user_labels_free(user_labels_t* map)
{

}

static user_labels_t* ida_user_labels_new()
{

}

static ea_t& ida_eamap_first(eamap_iterator_t p)
{

}

static cinsnptrvec_t& ida_eamap_second(eamap_iterator_t p)
{

}

static eamap_iterator_t ida_eamap_find(eamap_t* map, ref ea_t key)
{

}

static eamap_iterator_t ida_eamap_insert(eamap_t* map, ref ea_t key, ref cinsnptrvec_t val)
{

}

static eamap_iterator_t ida_eamap_begin(eamap_t* map)
{

}

static eamap_iterator_t ida_eamap_end(eamap_t* map)
{

}

static eamap_iterator_t ida_eamap_next(eamap_iterator_t p)
{

}

static eamap_iterator_t ida_eamap_prev(eamap_iterator_t p)
{

}

static void ida_eamap_erase(eamap_t* map, eamap_iterator_t p)
{

}

static void ida_eamap_clear(eamap_t* map)
{

}

static size_t ida_eamap_size(eamap_t* map)
{

}

static void ida_eamap_free(eamap_t* map)
{

}

static eamap_t* ida_eamap_new()
{

}

static cinsn_t*& ida_boundaries_first(boundaries_iterator_t p)
{

}

static rangeset_t& ida_boundaries_second(boundaries_iterator_t p)
{

}

static boundaries_iterator_t ida_boundaries_find(boundaries_t* map, ref cinsn_t* key)
{

}

static boundaries_iterator_t ida_boundaries_insert(boundaries_t* map, ref cinsn_t* key, ref rangeset_t val)
{

}

static boundaries_iterator_t ida_boundaries_begin(boundaries_t* map)
{

}

static boundaries_iterator_t ida_boundaries_end(boundaries_t* map)
{

}

static boundaries_iterator_t ida_boundaries_next(boundaries_iterator_t p)
{

}

static boundaries_iterator_t ida_boundaries_prev(boundaries_iterator_t p)
{

}

static void ida_boundaries_erase(boundaries_t* map, boundaries_iterator_t p)
{

}

static void ida_boundaries_clear(boundaries_t* map)
{

}

static size_t ida_boundaries_size(boundaries_t* map)
{

}

static void ida_boundaries_free(boundaries_t* map)
{

}

static boundaries_t* ida_boundaries_new()
{

}

static chain_t& ida_block_chains_get(block_chains_iterator_t p)
{

}

static block_chains_iterator_t ida_block_chains_find(block_chains_t* set, ref chain_t val)
{

}

static block_chains_iterator_t ida_block_chains_insert(block_chains_t* set, ref chain_t val)
{

}

static block_chains_iterator_t ida_block_chains_begin(block_chains_t* set)
{

}

static block_chains_iterator_t ida_block_chains_end(block_chains_t* set)
{

}

static block_chains_iterator_t ida_block_chains_next(block_chains_iterator_t p)
{

}

static block_chains_iterator_t ida_block_chains_prev(block_chains_iterator_t p)
{

}

static void ida_block_chains_erase(block_chains_t* set, block_chains_iterator_t p)
{

}

static void ida_block_chains_clear(block_chains_t* set)
{

}

static size_t ida_block_chains_size(block_chains_t* set)
{

}

static void ida_block_chains_free(block_chains_t* set)
{

}

static block_chains_t* ida_block_chains_new()
{

}

static void* ida_hexrays_alloc(size_t size)
{

}

static void ida_hexrays_free(void* ptr)
{

}

static ea_t ida_get_merror_desc(qstring* out, merror_t code, mba_t* mba)
{

}

static bool ida_must_mcode_close_block(mcode_t mcode, bool including_calls)
{

}

static bool ida_is_mcode_propagatable(mcode_t mcode)
{

}

static mcode_t ida_negate_mcode_relation(mcode_t code)
{

}

static mcode_t ida_swap_mcode_relation(mcode_t code)
{

}

static mcode_t ida_get_signed_mcode(mcode_t code)
{

}

static mcode_t ida_get_unsigned_mcode(mcode_t code)
{

}

static bool ida_mcode_modifies_d(mcode_t mcode)
{

}

static char* ida_dstr(tinfo_t* tif)
{

}

static bool ida_is_type_correct(type_t* ptr)
{

}

static bool ida_is_small_udt(ref tinfo_t tif)
{

}

static bool ida_is_nonbool_type(ref tinfo_t type)
{

}

static bool ida_is_bool_type(ref tinfo_t type)
{

}

static int ida_partial_type_num(ref tinfo_t type)
{

}

static tinfo_t ida_get_float_type(int width)
{

}

static tinfo_t ida_get_int_type_by_width_and_sign(int srcwidth, type_sign_t sign)
{

}

static tinfo_t ida_get_unk_type(int size)
{

}

static tinfo_t ida_dummy_ptrtype(int ptrsize, bool isfp)
{

}

static bool ida_get_member_type(member_t* mptr, tinfo_t* type)
{

}

static tinfo_t ida_make_pointer(ref tinfo_t type)
{

}

static tinfo_t ida_create_typedef(char* name)
{

}

static bool ida_get_type(uval_t id, tinfo_t* tif, type_source_t guess)
{

}

static bool ida_set_type(uval_t id, ref tinfo_t tif, type_source_t source, bool force)
{

}

static void ida_print_vdloc(qstring* vout, ref vdloc_t loc, int nbytes)
{

}

static bool ida_arglocs_overlap(ref vdloc_t loc1, size_t w1, ref vdloc_t loc2, size_t w2)
{

}

static bool ida_restore_user_lvar_settings(lvar_uservec_t* lvinf, ea_t func_ea)
{

}

static void ida_save_user_lvar_settings(ea_t func_ea, ref lvar_uservec_t lvinf)
{

}

static bool ida_modify_user_lvars(ea_t entry_ea, ref user_lvar_modifier_t mlv)
{

}

static bool ida_modify_user_lvar_info(ea_t func_ea, uint mli_flags, ref lvar_saved_info_t info)
{

}

static bool ida_locate_lvar(lvar_locator_t* out, ea_t func_ea, char* varname)
{

}

static bool ida_restore_user_defined_calls(udcall_map_t* udcalls, ea_t func_ea)
{

}

static void ida_save_user_defined_calls(ea_t func_ea, ref udcall_map_t udcalls)
{

}

static bool ida_parse_user_call(udcall_t* udc, char* decl, bool silent)
{

}

static merror_t ida_convert_to_user_call(ref udcall_t udc, ref codegen_t cdg)
{

}

static bool ida_install_microcode_filter(microcode_filter_t* filter, bool install)
{

}

static mlist_t& ida_get_temp_regs()
{

}

static bool ida_is_kreg(mreg_t r)
{

}

static mreg_t ida_reg2mreg(int reg)
{

}

static int ida_mreg2reg(mreg_t reg, int width)
{

}

static int ida_get_mreg_name(qstring* out, mreg_t reg, int width, void* ud)
{

}

static void ida_install_optinsn_handler(optinsn_t* opt)
{

}

static bool ida_remove_optinsn_handler(optinsn_t* opt)
{

}

static void ida_install_optblock_handler(optblock_t* opt)
{

}

static bool ida_remove_optblock_handler(optblock_t* opt)
{

}

static minsn_t* ida_getf_reginsn(minsn_t* ins)
{

}

static minsn_t* ida_getb_reginsn(minsn_t* ins)
{

}

static char* ida_get_hexrays_version()
{

}

static bool ida_checkout_hexrays_license(bool silent)
{

}

static vdui_t* ida_open_pseudocode(ea_t ea, int flags)
{

}

static bool ida_close_pseudocode(TWidget* f)
{

}

static vdui_t* ida_get_widget_vdui(TWidget* f)
{

}

static bool ida_decompile_many(char* outfile, eavec_t* funcaddrs, int flags)
{

}

static void ida_send_database(ref hexrays_failure_t err, bool silent)
{

}

static bool ida_get_current_operand(gco_info_t* out)
{

}

static void ida_remitem(citem_t* e)
{

}

static ctype_t ida_negated_relation(ctype_t op)
{

}

static ctype_t ida_swapped_relation(ctype_t op)
{

}

static type_sign_t ida_get_op_signness(ctype_t op)
{

}

static ctype_t ida_asgop(ctype_t cop)
{

}

static ctype_t ida_asgop_revert(ctype_t cop)
{

}

static cexpr_t* ida_lnot(cexpr_t* e)
{

}

static cinsn_t* ida_new_block()
{

}

static cexpr_t* ida_vcreate_helper(bool standalone, ref tinfo_t type, char* format, va_list va)
{

}

static cexpr_t* ida_vcall_helper(ref tinfo_t rettype, carglist_t* args, char* format, va_list va)
{

}

static cexpr_t* ida_make_num(uint64 n, cfunc_t* func, ea_t ea, int opnum, type_sign_t sign, int size)
{

}

static cexpr_t* ida_make_ref(cexpr_t* e)
{

}

static cexpr_t* ida_dereference(cexpr_t* e, int ptrsize, bool is_flt)
{

}

static void ida_save_user_labels(ea_t func_ea, user_labels_t* user_labels)
{

}

static void ida_save_user_labels2(ea_t func_ea, user_labels_t* user_labels, cfunc_t* func)
{

}

static void ida_save_user_cmts(ea_t func_ea, user_cmts_t* user_cmts)
{

}

static void ida_save_user_numforms(ea_t func_ea, user_numforms_t* numforms)
{

}

static void ida_save_user_iflags(ea_t func_ea, user_iflags_t* iflags)
{

}

static void ida_save_user_unions(ea_t func_ea, user_unions_t* unions)
{

}

static user_labels_t* ida_restore_user_labels(ea_t func_ea)
{

}

static user_labels_t* ida_restore_user_labels2(ea_t func_ea, cfunc_t* func)
{

}

static user_cmts_t* ida_restore_user_cmts(ea_t func_ea)
{

}

static user_numforms_t* ida_restore_user_numforms(ea_t func_ea)
{

}

static user_iflags_t* ida_restore_user_iflags(ea_t func_ea)
{

}

static user_unions_t* ida_restore_user_unions(ea_t func_ea)
{

}

static void ida_close_hexrays_waitbox()
{

}

static cfuncptr_t ida_decompile(ref mba_ranges_t mbr, hexrays_failure_t* hf, int decomp_flags)
{

}

static mba_t* ida_gen_microcode(ref mba_ranges_t mbr, hexrays_failure_t* hf, mlist_t* retlist, int decomp_flags, mba_maturity_t reqmat)
{

}

static cfuncptr_t ida_create_cfunc(mba_t* mba)
{

}

static bool ida_mark_cfunc_dirty(ea_t ea, bool close_views)
{

}

static void ida_clear_cached_cfuncs()
{

}

static bool ida_has_cached_cfunc(ea_t ea)
{

}

static char* ida_get_ctype_name(ctype_t op)
{

}

static qstring ida_create_field_name(ref tinfo_t type, uval_t offset)
{

}

static bool ida_install_hexrays_callback(hexrays_cb_t* callback, void* ud)
{

}

static int ida_remove_hexrays_callback(hexrays_cb_t* callback, void* ud)
{

}

static int ida_select_udt_by_offset(qvector* udts, ref ui_stroff_ops_t ops, ref ui_stroff_applicator_t applicator)
{

}

*/