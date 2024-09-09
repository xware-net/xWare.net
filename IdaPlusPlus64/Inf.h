#pragma once

#include <idp.hpp>

// getinf...
static size_t ida_getinf(inftag_t tag)
{
	return getinf(tag);
}

// getinf_buf
static ssize_t ida_getinf_buf(inftag_t tag, IntPtr ptr, size_t bufsize)
{
	void* buf = ptr.ToPointer();
	return getinf_buf(tag, buf, bufsize);
}

// getinf_str
static ssize_t ida_getinf_str(IntPtr ptr, int tag)
{
	qstring buf;
	auto size = getinf_str(&buf, (inftag_t)tag);
	// copy from buf to ptr
	::ConvertQstringToIntPtr(buf, ptr, size);
	return size;
}

// getinf_flag
static bool ida_getinf_flag(int tag, uint32 flag)
{
	return getinf_flag((inftag_t)tag, flag);
}

// various getinf_flag calls
static bool ida_inf_is_auto_enabled()
{
	return getinf_flag(INF_GENFLAGS, INFFL_AUTO);
}

static bool ida_inf_use_allasm()
{
	return getinf_flag(INF_GENFLAGS, INFFL_ALLASM);
}

static bool ida_inf_loading_idc()
{
	return getinf_flag(INF_GENFLAGS, INFFL_LOADIDC);
}

static bool ida_inf_no_store_user_info()
{
	return getinf_flag(INF_GENFLAGS, INFFL_NOUSER);
}

static bool ida_inf_readonly_idb()
{
	return getinf_flag(INF_GENFLAGS, INFFL_READONLY);
}

static bool ida_inf_check_manual_ops()
{
	return getinf_flag(INF_GENFLAGS, INFFL_CHKOPS);
}

static bool ida_inf_allow_non_matched_ops()
{
	return getinf_flag(INF_GENFLAGS, INFFL_NMOPS);
}

static bool ida_inf_is_graph_view()
{
	return getinf_flag(INF_GENFLAGS, INFFL_GRAPH_VIEW);
}

static uint32 ida_inf_get_lflags()
{
	return uint32(getinf(INF_LFLAGS));
}

static bool ida_inf_set_lflags(uint32 _v)
{
	return setinf(INF_LFLAGS, ssize_t(_v));
}

static bool ida_inf_decode_fpp()
{
	return getinf_flag(INF_LFLAGS, LFLG_PC_FPP);
}

static bool ida_inf_is_32bit_or_higher()
{
	return getinf_flag(INF_LFLAGS, LFLG_PC_FLAT);
}

static bool ida_inf_is_32bit_exactly()
{
	return (getinf(INF_LFLAGS) & (LFLG_PC_FLAT | LFLG_64BIT)) == LFLG_PC_FLAT;
}

static bool ida_inf_is_16bit()
{
	return !inf_is_32bit_or_higher();
}

static bool ida_inf_is_64bit()
{
	return getinf_flag(INF_LFLAGS, LFLG_64BIT);
}

static bool ida_inf_set_64bit(bool _v)
{
	return setinf_flag(INF_LFLAGS, LFLG_64BIT, _v);
}

static bool ida_inf_is_dll()
{
	return getinf_flag(INF_LFLAGS, LFLG_IS_DLL);
}

static bool ida_inf_set_dll(bool _v)
{
	return setinf_flag(INF_LFLAGS, LFLG_IS_DLL, _v);
}

static bool ida_inf_is_flat_off32()
{
	return getinf_flag(INF_LFLAGS, LFLG_FLAT_OFF32);
}

static bool ida_inf_set_flat_off32(bool _v)
{
	return setinf_flag(INF_LFLAGS, LFLG_FLAT_OFF32, _v);
}

static bool ida_inf_is_be()
{
	return getinf_flag(INF_LFLAGS, LFLG_MSF);
}

static bool ida_inf_set_be(bool _v)
{
	return setinf_flag(INF_LFLAGS, LFLG_MSF, _v);
}

static bool ida_inf_is_wide_high_byte_first()
{
	return getinf_flag(INF_LFLAGS, LFLG_WIDE_HBF);
}

static bool ida_inf_set_wide_high_byte_first(bool _v)
{
	return setinf_flag(INF_LFLAGS, LFLG_WIDE_HBF, _v);
}

static bool ida_inf_dbg_no_store_path()
{
	return getinf_flag(INF_LFLAGS, LFLG_DBG_NOPATH);
}

static bool ida_inf_set_dbg_no_store_path(bool _v)
{
	return setinf_flag(INF_LFLAGS, LFLG_DBG_NOPATH, _v);
}

static bool ida_inf_is_snapshot()
{
	return getinf_flag(INF_LFLAGS, LFLG_SNAPSHOT);
}

static bool ida_inf_set_snapshot(bool _v)
{
	return setinf_flag(INF_LFLAGS, LFLG_SNAPSHOT, _v);
}

static bool ida_inf_pack_idb()
{
	return getinf_flag(INF_LFLAGS, LFLG_PACK);
}

static bool ida_inf_set_pack_idb(bool _v)
{
	return setinf_flag(INF_LFLAGS, LFLG_PACK, _v);
}

static bool ida_inf_compress_idb()
{
	return getinf_flag(INF_LFLAGS, LFLG_COMPRESS);
}

static bool ida_inf_set_compress_idb(bool _v)
{
	return setinf_flag(INF_LFLAGS, LFLG_COMPRESS, _v);
}

static bool ida_inf_is_kernel_mode()
{
	return getinf_flag(INF_LFLAGS, LFLG_KERNMODE);
}

static bool ida_inf_set_kernel_mode(bool _v)
{
	return setinf_flag(INF_LFLAGS, LFLG_KERNMODE, _v);
}

static uint ida_inf_get_app_bitness()
{
	uint32 f = getinf(INF_LFLAGS) & (LFLG_PC_FLAT | LFLG_64BIT);
	return f == 0 ? 16 : f == LFLG_PC_FLAT ? 32 : 64;
}

//  setinf...
static bool ida_setinf(inftag_t tag, ssize_t value)
{
	return setinf(tag, value);
}

// setinf_flag
static bool ida_setinf_flag(inftag_t tag, uint32 flag, bool value)
{
	return setinf_flag(tag, flag, value);
}

// various setinf_flag calls
static bool ida_inf_set_auto_enabled()
{
	return setinf_flag(INF_GENFLAGS, INFFL_AUTO);
}

static bool ida_inf_set_auto_enabled(bool _v)
{
	return setinf_flag(INF_GENFLAGS, INFFL_AUTO, _v);
}

static bool ida_inf_set_use_allasm()
{
	return setinf_flag(INF_GENFLAGS, INFFL_ALLASM);
}

static bool ida_inf_set_use_allasm(bool _v)
{
	return setinf_flag(INF_GENFLAGS, INFFL_ALLASM, _v);
}

static bool ida_inf_set_loading_idc()
{
	return setinf_flag(INF_GENFLAGS, INFFL_LOADIDC);
}

static bool ida_inf_set_loading_idc(bool _v)
{
	return setinf_flag(INF_GENFLAGS, INFFL_LOADIDC, _v);
}

static bool ida_inf_set_no_store_user_info()
{
	return setinf_flag(INF_GENFLAGS, INFFL_NOUSER);
}

static bool ida_inf_set_no_store_user_info(bool _v)
{
	return setinf_flag(INF_GENFLAGS, INFFL_NOUSER, _v);
}

static bool ida_inf_set_readonly_idb()
{
	return setinf_flag(INF_GENFLAGS, INFFL_READONLY);
}

static bool ida_inf_set_readonly_idb(bool _v)
{
	return setinf_flag(INF_GENFLAGS, INFFL_READONLY, _v);
}

static bool ida_inf_set_check_manual_ops()
{
	return setinf_flag(INF_GENFLAGS, INFFL_CHKOPS);
}

static bool ida_inf_set_check_manual_ops(bool _v)
{
	return setinf_flag(INF_GENFLAGS, INFFL_CHKOPS, _v);
}

static bool ida_inf_set_allow_non_matched_ops()
{
	return setinf_flag(INF_GENFLAGS, INFFL_NMOPS);
}

static bool ida_inf_set_allow_non_matched_ops(bool _v)
{
	return setinf_flag(INF_GENFLAGS, INFFL_NMOPS, _v);
}

static bool ida_inf_set_graph_view()
{
	return setinf_flag(INF_GENFLAGS, INFFL_GRAPH_VIEW);
}

static bool ida_inf_set_graph_view(bool _v)
{
	return setinf_flag(INF_GENFLAGS, INFFL_GRAPH_VIEW, _v);
}

static bool ida_inf_set_decode_fpp()
{
	return setinf_flag(INF_LFLAGS, LFLG_PC_FPP);
}

static bool ida_inf_set_decode_fpp(bool _v)
{
	return setinf_flag(INF_LFLAGS, LFLG_PC_FPP, _v);
}

static bool ida_inf_set_32bit()
{
	return setinf_flag(INF_LFLAGS, LFLG_PC_FLAT);
}

static bool ida_inf_set_32bit(bool _v)
{
	return setinf_flag(INF_LFLAGS, LFLG_PC_FLAT, _v);
}

// version
static ushort ida_inf_get_version()
{
	return ushort(getinf(INF_VERSION));
}

static bool ida_inf_set_version(ushort _v)
{
	return setinf(INF_VERSION, ssize_t(_v));
}

// genflags
static ushort ida_inf_get_genflags()
{
	return ushort(getinf(INF_GENFLAGS));
}

static bool ida_inf_set_genflags(ushort _v)
{
	return setinf(INF_GENFLAGS, ssize_t(_v));
}

// remove an information
static bool ida_delinf(inftag_t tag)
{
	return delinf(tag);
}

// procname
static bool ida_inf_get_procname(IntPtr buf, size_t bufsize)
{
	return inf_get_procname((char*)(buf.ToPointer()), bufsize);
}

static String^ ida_inf_get_procname()
{
	char buf[IDAINFO_PROCNAME_SIZE];
	if (!getinf_buf(INF_PROCNAME, buf, sizeof(buf)))
		buf[0] = '\0';
	return ::ConvertQstringToString(qstring(buf));
}

static bool ida_inf_set_procname(IntPtr buf, size_t len)
{
	if (buf == IntPtr::Zero)
		return false;
	if (len == size_t(-1))
		len = strlen((char*)(buf.ToPointer()));
	return setinf_buf(INF_PROCNAME, (char*)(buf.ToPointer()), qmin(len, IDAINFO_PROCNAME_SIZE));
}

static bool ida_inf_get_strlit_pref(IntPtr buf, size_t bufsize)
{
	return inf_get_strlit_pref((char*)buf.ToPointer(), bufsize);
}

static String^ ida_inf_get_strlit_pref()
{
	char buf[IDAINFO_STRLIT_PREF_SIZE];
	if (!getinf_buf(INF_STRLIT_PREF, buf, sizeof(buf)))
		buf[0] = '\0';
	return ::ConvertQstringToString(qstring(buf));
}

static bool ida_inf_set_strlit_pref(IntPtr buf, size_t len)
{
	if (buf == IntPtr::Zero)
		return false;
	if (len == size_t(-1))
		len = strlen((char*)(buf.ToPointer()));
	return setinf_buf(INF_STRLIT_PREF, (char*)(buf.ToPointer()), qmin(len, IDAINFO_STRLIT_PREF_SIZE));
}

// database_change_count
static uint32 ida_inf_get_database_change_count()
{
	return uint32(getinf(INF_DATABASE_CHANGE_COUNT));
}

static bool ida_inf_set_database_change_count(uint32 _v)
{
	return setinf(INF_DATABASE_CHANGE_COUNT, ssize_t(_v));
}

// filetype
static ushort ida_inf_get_filetype()
{
	return ushort(getinf(INF_FILETYPE));
}

static bool ida_inf_set_filetype(filetype_t _v)
{
	return setinf(INF_FILETYPE, ssize_t(_v));
}

// ostype
static ushort ida_inf_get_ostype()
{
	return ushort(getinf(INF_OSTYPE));
}

static bool ida_inf_set_ostype(ushort _v)
{
	return setinf(INF_OSTYPE, ssize_t(_v));
}

// apptype
static ushort ida_inf_get_apptype()
{
	return ushort(getinf(INF_APPTYPE));
}

static bool ida_inf_set_apptype(ushort _v)
{
	return setinf(INF_APPTYPE, ssize_t(_v));
}

// asmtype
static uchar ida_inf_get_asmtype()
{
	return uchar(getinf(INF_ASMTYPE));
}

static bool ida_inf_set_asmtype(uchar _v)
{
	return setinf(INF_ASMTYPE, ssize_t(_v));
}

// specsegs
static uchar ida_inf_get_specsegs()
{
	return uchar(getinf(INF_SPECSEGS));
}

static bool ida_inf_set_specsegs(uchar _v)
{
	return setinf(INF_SPECSEGS, ssize_t(_v));
}

// af
static uint32 ida_inf_get_af()
{
	return uint32(getinf(INF_AF));
}

static bool ida_inf_set_af(uint32 _v)
{
	return setinf(INF_AF, ssize_t(_v));
}

static bool ida_inf_trace_flow()
{
	return getinf_flag(INF_AF, AF_CODE);
}

static bool ida_inf_set_trace_flow(bool _v)
{
	return setinf_flag(INF_AF, AF_CODE, _v);
}

static bool ida_inf_mark_code()
{
	return getinf_flag(INF_AF, AF_MARKCODE);
}

static bool ida_inf_set_mark_code(bool _v)
{
	return setinf_flag(INF_AF, AF_MARKCODE, _v);
}

static bool ida_inf_create_jump_tables()
{
	return getinf_flag(INF_AF, AF_JUMPTBL);
}

static bool ida_inf_set_create_jump_tables(bool _v)
{
	return setinf_flag(INF_AF, AF_JUMPTBL, _v);
}

static bool ida_inf_noflow_to_data()
{
	return getinf_flag(INF_AF, AF_PURDAT);
}

static bool ida_inf_set_noflow_to_data(bool _v)
{
	return setinf_flag(INF_AF, AF_PURDAT, _v);
}

static bool ida_inf_create_all_xrefs()
{
	return getinf_flag(INF_AF, AF_USED);
}

static bool ida_inf_set_create_all_xrefs(bool _v)
{
	return setinf_flag(INF_AF, AF_USED, _v);
}

static bool ida_inf_del_no_xref_insns()
{
	return getinf_flag(INF_AF, AF_UNK);
}

static bool ida_inf_set_del_no_xref_insns(bool _v)
{
	return setinf_flag(INF_AF, AF_UNK, _v);
}

static bool ida_inf_create_func_from_ptr()
{
	return getinf_flag(INF_AF, AF_PROCPTR);
}

static bool ida_inf_set_create_func_from_ptr(bool _v)
{
	return setinf_flag(INF_AF, AF_PROCPTR, _v);
}

static bool ida_inf_create_func_from_call()
{
	return getinf_flag(INF_AF, AF_PROC);
}

static bool ida_inf_set_create_func_from_call(bool _v)
{
	return setinf_flag(INF_AF, AF_PROC, _v);
}

static bool ida_inf_create_func_tails()
{
	return getinf_flag(INF_AF, AF_FTAIL);
}

static bool ida_inf_set_create_func_tails(bool _v)
{
	return setinf_flag(INF_AF, AF_FTAIL, _v);
}

static bool ida_inf_should_create_stkvars()
{
	return getinf_flag(INF_AF, AF_LVAR);
}

static bool ida_inf_set_should_create_stkvars(bool _v)
{
	return setinf_flag(INF_AF, AF_LVAR, _v);
}

static bool ida_inf_propagate_stkargs()
{
	return getinf_flag(INF_AF, AF_STKARG);
}

static bool ida_inf_set_propagate_stkargs(bool _v)
{
	return setinf_flag(INF_AF, AF_STKARG, _v);
}

static bool ida_inf_propagate_regargs()
{
	return getinf_flag(INF_AF, AF_REGARG);
}

static bool ida_inf_set_propagate_regargs(bool _v)
{
	return setinf_flag(INF_AF, AF_REGARG, _v);
}

static bool ida_inf_should_trace_sp()
{
	return getinf_flag(INF_AF, AF_TRACE);
}

static bool ida_inf_set_should_trace_sp(bool _v)
{
	return setinf_flag(INF_AF, AF_TRACE, _v);
}

static bool ida_inf_full_sp_ana()
{
	return getinf_flag(INF_AF, AF_VERSP);
}

static bool ida_inf_set_full_sp_ana(bool _v)
{
	return setinf_flag(INF_AF, AF_VERSP, _v);
}

static bool ida_inf_noret_ana()
{
	return getinf_flag(INF_AF, AF_ANORET);
}

static bool ida_inf_set_noret_ana(bool _v)
{
	return setinf_flag(INF_AF, AF_ANORET, _v);
}

static bool ida_inf_guess_func_type()
{
	return getinf_flag(INF_AF, AF_MEMFUNC);
}

static bool ida_inf_set_guess_func_type(bool _v)
{
	return setinf_flag(INF_AF, AF_MEMFUNC, _v);
}

static bool ida_inf_truncate_on_del()
{
	return getinf_flag(INF_AF, AF_TRFUNC);
}

static bool ida_inf_set_truncate_on_del(bool _v)
{
	return setinf_flag(INF_AF, AF_TRFUNC, _v);
}

static bool ida_inf_create_strlit_on_xref()
{
	return getinf_flag(INF_AF, AF_STRLIT);
}

static bool ida_inf_set_create_strlit_on_xref(bool _v)
{
	return setinf_flag(INF_AF, AF_STRLIT, _v);
}

static bool ida_inf_check_unicode_strlits()
{
	return getinf_flag(INF_AF, AF_CHKUNI);
}

static bool ida_inf_set_check_unicode_strlits(bool _v)
{
	return setinf_flag(INF_AF, AF_CHKUNI, _v);
}

static bool ida_inf_create_off_using_fixup()
{
	return getinf_flag(INF_AF, AF_FIXUP);
}

static bool ida_inf_set_create_off_using_fixup(bool _v)
{
	return setinf_flag(INF_AF, AF_FIXUP, _v);
}

static bool ida_inf_create_off_on_dref()
{
	return getinf_flag(INF_AF, AF_DREFOFF);
}

static bool ida_inf_set_create_off_on_dref(bool _v)
{
	return setinf_flag(INF_AF, AF_DREFOFF, _v);
}

static bool ida_inf_op_offset()
{
	return getinf_flag(INF_AF, AF_IMMOFF);
}

static bool ida_inf_set_op_offset(bool _v)
{
	return setinf_flag(INF_AF, AF_IMMOFF, _v);
}

static bool ida_inf_data_offset()
{
	return getinf_flag(INF_AF, AF_DATOFF);
}

static bool ida_inf_set_data_offset(bool _v)
{
	return setinf_flag(INF_AF, AF_DATOFF, _v);
}

static bool ida_inf_use_flirt()
{
	return getinf_flag(INF_AF, AF_FLIRT);
}

static bool ida_inf_set_use_flirt(bool _v)
{
	return setinf_flag(INF_AF, AF_FLIRT, _v);
}

static bool ida_inf_append_sigcmt()
{
	return getinf_flag(INF_AF, AF_SIGCMT);
}

static bool ida_inf_set_append_sigcmt(bool _v)
{
	return setinf_flag(INF_AF, AF_SIGCMT, _v);
}

static bool ida_inf_allow_sigmulti()
{
	return getinf_flag(INF_AF, AF_SIGMLT);
}

static bool ida_inf_set_allow_sigmulti(bool _v)
{
	return setinf_flag(INF_AF, AF_SIGMLT, _v);
}

static bool ida_inf_hide_libfuncs()
{
	return getinf_flag(INF_AF, AF_HFLIRT);
}

static bool ida_inf_set_hide_libfuncs(bool _v)
{
	return setinf_flag(INF_AF, AF_HFLIRT, _v);
}

static bool ida_inf_rename_jumpfunc()
{
	return getinf_flag(INF_AF, AF_JFUNC);
}

static bool ida_inf_set_rename_jumpfunc(bool _v)
{
	return setinf_flag(INF_AF, AF_JFUNC, _v);
}

static bool ida_inf_rename_nullsub()
{
	return getinf_flag(INF_AF, AF_NULLSUB);
}

static bool ida_inf_set_rename_nullsub(bool _v)
{
	return setinf_flag(INF_AF, AF_NULLSUB, _v);
}

static bool ida_inf_coagulate_data()
{
	return getinf_flag(INF_AF, AF_DODATA);
}

static bool ida_inf_set_coagulate_data(bool _v)
{
	return setinf_flag(INF_AF, AF_DODATA, _v);
}

static bool ida_inf_coagulate_code()
{
	return getinf_flag(INF_AF, AF_DOCODE);
}

static bool ida_inf_set_coagulate_code(bool _v)
{
	return setinf_flag(INF_AF, AF_DOCODE, _v);
}

static bool ida_inf_final_pass()
{
	return getinf_flag(INF_AF, AF_FINAL);
}

static bool ida_inf_set_final_pass(bool _v)
{
	return setinf_flag(INF_AF, AF_FINAL, _v);
}

// af2
static uint32 ida_inf_get_af2()
{
	return uint32(getinf(INF_AF2));
}

static bool ida_inf_set_af2(uint32 _v)
{
	return setinf(INF_AF2, ssize_t(_v));
}

static bool ida_inf_handle_eh()
{
	return getinf_flag(INF_AF2, AF2_DOEH);
}

static bool ida_inf_set_handle_eh(bool _v)
{
	return setinf_flag(INF_AF2, AF2_DOEH, _v);
}

static bool ida_inf_handle_rtti()
{
	return getinf_flag(INF_AF2, AF2_DORTTI);
}

static bool ida_inf_set_handle_rtti(bool _v)
{
	return setinf_flag(INF_AF2, AF2_DORTTI, _v);
}

static bool ida_inf_macros_enabled()
{
	return getinf_flag(INF_AF2, AF2_MACRO);
}

static bool ida_inf_set_macros_enabled(bool _v)
{
	return setinf_flag(INF_AF2, AF2_MACRO, _v);
}

// baseaddr
static uval_t ida_inf_get_baseaddr()
{
	return uval_t(getinf(INF_BASEADDR));
}

static bool ida_inf_set_baseaddr(uval_t _v)
{
	return setinf(INF_BASEADDR, ssize_t(_v));
}

// start_ss
static sel_t ida_inf_get_start_ss()
{
	return sel_t(getinf(INF_START_SS));
}

static bool ida_inf_set_start_ss(sel_t _v)
{
	return setinf(INF_START_SS, ssize_t(_v));
}

// start_cs
static sel_t ida_inf_get_start_cs()
{
	return sel_t(getinf(INF_START_CS));
}

static bool ida_inf_set_start_cs(sel_t _v)
{
	return setinf(INF_START_CS, ssize_t(_v));
}

// start_ip
static ea_t ida_inf_get_start_ip()
{
	return ea_t(getinf(INF_START_IP));
}

static bool ida_inf_set_start_ip(ea_t _v)
{
	return setinf(INF_START_IP, ssize_t(_v));
}

// start_ea
static ea_t ida_inf_get_start_ea()
{
	return ea_t(getinf(INF_START_EA));
}

static bool ida_inf_set_start_ea(ea_t _v)
{
	return setinf(INF_START_EA, ssize_t(_v));
}

// start_sp
static ea_t ida_inf_get_start_sp()
{
	return ea_t(getinf(INF_START_SP));
}

static bool ida_inf_set_start_sp(ea_t _v)
{
	return setinf(INF_START_SP, ssize_t(_v));
}

// main
static ea_t ida_inf_get_main()
{
	return ea_t(getinf(INF_MAIN));
}

static bool ida_inf_set_main(ea_t _v)
{
	return setinf(INF_MAIN, ssize_t(_v));
}

// min_ea
static ea_t ida_inf_get_min_ea()
{
	return ea_t(getinf(INF_MIN_EA));
}

static bool ida_inf_set_min_ea(ea_t _v)
{
	return setinf(INF_MIN_EA, ssize_t(_v));
}

// max_ea
static ea_t ida_inf_get_max_ea()
{
	return ea_t(getinf(INF_MAX_EA));
}

static bool ida_inf_set_max_ea(ea_t _v)
{
	return setinf(INF_MAX_EA, ssize_t(_v));
}

// omin_ea
static ea_t ida_inf_get_omin_ea()
{
	return ea_t(getinf(INF_OMIN_EA));
}

static bool ida_inf_set_omin_ea(ea_t _v)
{
	return setinf(INF_OMIN_EA, ssize_t(_v));
}

// omax_ea
static ea_t ida_inf_get_omax_ea()
{
	return ea_t(getinf(INF_OMAX_EA));
}

static bool ida_inf_set_omax_ea(ea_t _v)
{
	return setinf(INF_OMAX_EA, ssize_t(_v));
}

// lowoff
static ea_t ida_inf_get_lowoff()
{
	return ea_t(getinf(INF_LOWOFF));
}

static bool ida_inf_set_lowoff(ea_t _v)
{
	return setinf(INF_LOWOFF, ssize_t(_v));
}

// highoff
static ea_t ida_inf_get_highoff()
{
	return ea_t(getinf(INF_HIGHOFF));
}

static bool ida_inf_set_highoff(ea_t _v)
{
	return setinf(INF_HIGHOFF, ssize_t(_v));
}

// maxref
static uval_t ida_inf_get_maxref()
{
	return uval_t(getinf(INF_MAXREF));
}

static bool ida_inf_set_maxref(uval_t _v)
{
	return setinf(INF_MAXREF, ssize_t(_v));
}

// netdelta 
static sval_t ida_inf_get_netdelta()
{
	return sval_t(getinf(INF_NETDELTA));
}

static bool ida_inf_set_netdelta(sval_t _v)
{
	return setinf(INF_NETDELTA, ssize_t(_v));
}

// xrefnum
static uchar ida_inf_get_xrefnum()
{
	return uchar(getinf(INF_XREFNUM));
}

static bool ida_inf_set_xrefnum(uchar _v)
{
	return setinf(INF_XREFNUM, ssize_t(_v));
}

// type_xrefnum
static uchar ida_inf_get_type_xrefnum()
{
	return uchar(getinf(INF_TYPE_XREFNUM));
}

static bool ida_inf_set_type_xrefnum(uchar _v)
{
	return setinf(INF_TYPE_XREFNUM, ssize_t(_v));
}

// refcmtnum
static uchar ida_inf_get_refcmtnum()
{
	return uchar(getinf(INF_REFCMTNUM));
}

static bool ida_inf_set_refcmtnum(uchar _v)
{
	return setinf(INF_REFCMTNUM, ssize_t(_v));
}

// xrefflag
static uchar ida_inf_get_xrefflag()
{
	return uchar(getinf(INF_XREFFLAG));
}

static bool ida_inf_set_xrefflag(uchar _v)
{
	return setinf(INF_XREFFLAG, ssize_t(_v));
}

static bool ida_inf_show_xref_seg()
{
	return getinf_flag(INF_XREFFLAG, SW_SEGXRF);
}

static bool ida_inf_set_show_xref_seg(bool _v)
{
	return setinf_flag(INF_XREFFLAG, SW_SEGXRF, _v);
}

static bool ida_inf_show_xref_tmarks()
{
	return getinf_flag(INF_XREFFLAG, SW_XRFMRK);
}

static bool ida_inf_set_show_xref_tmarks(bool _v)
{
	return setinf_flag(INF_XREFFLAG, SW_XRFMRK, _v);
}

static bool ida_inf_show_xref_fncoff()
{
	return getinf_flag(INF_XREFFLAG, SW_XRFFNC);
}

static bool ida_inf_set_show_xref_fncoff(bool _v)
{
	return setinf_flag(INF_XREFFLAG, SW_XRFFNC, _v);
}

static bool ida_inf_show_xref_val()
{
	return getinf_flag(INF_XREFFLAG, SW_XRFVAL);
}

static bool ida_inf_set_show_xref_val(bool _v)
{
	return setinf_flag(INF_XREFFLAG, SW_XRFVAL, _v);
}

// max_autoname_len
static ushort ida_inf_get_max_autoname_len()
{
	return ushort(getinf(INF_MAX_AUTONAME_LEN));
}

static bool ida_inf_set_max_autoname_len(ushort _v)
{
	return setinf(INF_MAX_AUTONAME_LEN, ssize_t(_v));
}

// nametype
static char ida_inf_get_nametype()
{
	return char(getinf(INF_NAMETYPE));
}

static bool ida_inf_set_nametype(char _v)
{
	return setinf(INF_NAMETYPE, ssize_t(_v));
}

// short_demnames
static uint32 ida_inf_get_short_demnames()
{
	return uint32(getinf(INF_SHORT_DEMNAMES));
}

static bool ida_inf_set_short_demnames(uint32 _v)
{
	return setinf(INF_SHORT_DEMNAMES, ssize_t(_v));
}

// long_demnames
static uint32 ida_inf_get_long_demnames()
{
	return uint32(getinf(INF_LONG_DEMNAMES));
}

static bool ida_inf_set_long_demnames(uint32 _v)
{
	return setinf(INF_LONG_DEMNAMES, ssize_t(_v));
}

// demnames
static uchar ida_inf_get_demnames()
{
	return uchar(getinf(INF_DEMNAMES));
}

static bool ida_inf_set_demnames(uchar _v)
{
	return setinf(INF_DEMNAMES, ssize_t(_v));
}

// listnames
static uchar ida_inf_get_listnames()
{
	return uchar(getinf(INF_LISTNAMES));
}

static bool ida_inf_set_listnames(uchar _v)
{
	return setinf(INF_LISTNAMES, ssize_t(_v));
}

// ident
static uchar ida_inf_get_indent()
{
	return uchar(getinf(INF_INDENT));
}

static bool ida_inf_set_indent(uchar _v)
{
	return setinf(INF_INDENT, ssize_t(_v));
}

// comment
static uchar ida_inf_get_comment()
{
	return uchar(getinf(INF_CMT_INDENT));
}

static bool ida_inf_set_comment(uchar _v)
{
	return setinf(INF_CMT_INDENT, ssize_t(_v));
}

// margin
static ushort ida_inf_get_margin()
{
	return ushort(getinf(INF_MARGIN));
}

static bool ida_inf_set_margin(ushort _v)
{
	return setinf(INF_MARGIN, ssize_t(_v));
}

// lenxref
static ushort ida_inf_get_lenxref()
{
	return ushort(getinf(INF_LENXREF));
}

static bool ida_inf_set_lenxref(ushort _v)
{
	return setinf(INF_LENXREF, ssize_t(_v));
}

// outflags
static uint32 ida_inf_get_outflags()
{
	return uint32(getinf(INF_OUTFLAGS));
}

static bool ida_inf_set_outflags(uint32 _v)
{
	return setinf(INF_OUTFLAGS, ssize_t(_v));
}

static bool ida_inf_show_void()
{
	return getinf_flag(INF_OUTFLAGS, OFLG_SHOW_VOID);
}

static bool ida_inf_set_show_void(bool _v)
{
	return setinf_flag(INF_OUTFLAGS, OFLG_SHOW_VOID, _v);
}

static bool ida_inf_show_auto()
{
	return getinf_flag(INF_OUTFLAGS, OFLG_SHOW_AUTO);
}

static bool ida_inf_set_show_auto(bool _v)
{
	return setinf_flag(INF_OUTFLAGS, OFLG_SHOW_AUTO, _v);
}

static bool ida_inf_gen_null()
{
	return getinf_flag(INF_OUTFLAGS, OFLG_GEN_NULL);
}

static bool ida_inf_set_gen_null(bool _v)
{
	return setinf_flag(INF_OUTFLAGS, OFLG_GEN_NULL, _v);
}

static bool ida_inf_show_line_pref()
{
	return getinf_flag(INF_OUTFLAGS, OFLG_SHOW_PREF);
}

static bool ida_inf_set_show_line_pref(bool _v)
{
	return setinf_flag(INF_OUTFLAGS, OFLG_SHOW_PREF, _v);
}

static bool ida_inf_line_pref_with_seg()
{
	return getinf_flag(INF_OUTFLAGS, OFLG_PREF_SEG);
}

static bool ida_inf_set_line_pref_with_seg(bool _v)
{
	return setinf_flag(INF_OUTFLAGS, OFLG_PREF_SEG, _v);
}

static bool ida_inf_gen_lzero()
{
	return getinf_flag(INF_OUTFLAGS, OFLG_LZERO);
}

static bool ida_inf_set_gen_lzero(bool _v)
{
	return setinf_flag(INF_OUTFLAGS, OFLG_LZERO, _v);
}

static bool ida_inf_gen_org()
{
	return getinf_flag(INF_OUTFLAGS, OFLG_GEN_ORG);
}

static bool ida_inf_set_gen_org(bool _v)
{
	return setinf_flag(INF_OUTFLAGS, OFLG_GEN_ORG, _v);
}

static bool ida_inf_gen_assume()
{
	return getinf_flag(INF_OUTFLAGS, OFLG_GEN_ASSUME);
}

static bool ida_inf_set_gen_assume(bool _v)
{
	return setinf_flag(INF_OUTFLAGS, OFLG_GEN_ASSUME, _v);
}

static bool ida_inf_gen_tryblks()
{
	return getinf_flag(INF_OUTFLAGS, OFLG_GEN_TRYBLKS);
}

static bool ida_inf_set_gen_tryblks(bool _v)
{
	return setinf_flag(INF_OUTFLAGS, OFLG_GEN_TRYBLKS, _v);
}

// cmtflags
static uchar ida_inf_get_cmtflg()
{
	return uchar(getinf(INF_CMTFLG));
}

static bool ida_inf_set_cmtflg(uchar _v)
{
	return setinf(INF_CMTFLG, ssize_t(_v));
}

static bool ida_inf_show_repeatables()
{
	return getinf_flag(INF_CMTFLG, SCF_RPTCMT);
}

static bool ida_inf_set_show_repeatables(bool _v)
{
	return setinf_flag(INF_CMTFLG, SCF_RPTCMT, _v);
}

static bool ida_inf_show_all_comments()
{
	return getinf_flag(INF_CMTFLG, SCF_ALLCMT);
}

static bool ida_inf_set_show_all_comments(bool _v)
{
	return setinf_flag(INF_CMTFLG, SCF_ALLCMT, _v);
}

static bool ida_inf_hide_comments()
{
	return getinf_flag(INF_CMTFLG, SCF_NOCMT);
}

static bool ida_inf_set_hide_comments(bool _v)
{
	return setinf_flag(INF_CMTFLG, SCF_NOCMT, _v);
}

static bool ida_inf_show_src_linnum()
{
	return getinf_flag(INF_CMTFLG, SCF_LINNUM);
}

static bool ida_inf_set_show_src_linnum(bool _v)
{
	return setinf_flag(INF_CMTFLG, SCF_LINNUM, _v);
}

static bool ida_inf_test_mode()
{
	return getinf_flag(INF_CMTFLG, SCF_TESTMODE);
}

static bool ida_inf_show_hidden_insns()
{
	return getinf_flag(INF_CMTFLG, SCF_SHHID_ITEM);
}

static bool ida_inf_set_show_hidden_insns(bool _v)
{
	return setinf_flag(INF_CMTFLG, SCF_SHHID_ITEM, _v);
}

static bool ida_inf_show_hidden_funcs()
{
	return getinf_flag(INF_CMTFLG, SCF_SHHID_FUNC);
}

static bool ida_inf_set_show_hidden_funcs(bool _v)
{
	return setinf_flag(INF_CMTFLG, SCF_SHHID_FUNC, _v);
}

static bool ida_inf_show_hidden_segms()
{
	return getinf_flag(INF_CMTFLG, SCF_SHHID_SEGM);
}

static bool ida_inf_set_show_hidden_segms(bool _v)
{
	return setinf_flag(INF_CMTFLG, SCF_SHHID_SEGM, _v);
}

// limiter
static uchar ida_inf_get_limiter()
{
	return uchar(getinf(INF_LIMITER));
}

static bool ida_inf_set_limiter(uchar _v)
{
	return setinf(INF_LIMITER, ssize_t(_v));
}

static bool ida_inf_is_limiter_thin()
{
	return getinf_flag(INF_LIMITER, LMT_THIN);
}

static bool ida_inf_set_limiter_thin(bool _v)
{
	return setinf_flag(INF_LIMITER, LMT_THIN, _v);
}

static bool ida_inf_is_limiter_thick()
{
	return getinf_flag(INF_LIMITER, LMT_THICK);
}

static bool ida_inf_set_limiter_thick(bool _v)
{
	return setinf_flag(INF_LIMITER, LMT_THICK, _v);
}

static bool ida_inf_is_limiter_empty()
{
	return getinf_flag(INF_LIMITER, LMT_EMPTY);
}

static bool ida_inf_set_limiter_empty(bool _v)
{
	return setinf_flag(INF_LIMITER, LMT_EMPTY, _v);
}

// bin_prefix_size
static short ida_inf_get_bin_prefix_size()
{
	return short(getinf(INF_BIN_PREFIX_SIZE));
}

static bool ida_inf_set_bin_prefix_size(short _v)
{
	return setinf(INF_BIN_PREFIX_SIZE, ssize_t(_v));
}

// prefflag
static uchar ida_inf_get_prefflag()
{
	return uchar(getinf(INF_PREFFLAG));
}

static bool ida_inf_set_prefflag(uchar _v)
{
	return setinf(INF_PREFFLAG, ssize_t(_v));
}

static bool ida_inf_prefix_show_segaddr()
{
	return getinf_flag(INF_PREFFLAG, PREF_SEGADR);
}

static bool ida_inf_set_prefix_show_segaddr(bool _v)
{
	return setinf_flag(INF_PREFFLAG, PREF_SEGADR, _v);
}

static bool ida_inf_prefix_show_funcoff()
{
	return getinf_flag(INF_PREFFLAG, PREF_FNCOFF);
}

static bool ida_inf_set_prefix_show_funcoff(bool _v)
{
	return setinf_flag(INF_PREFFLAG, PREF_FNCOFF, _v);
}

static bool ida_inf_prefix_show_stack()
{
	return getinf_flag(INF_PREFFLAG, PREF_STACK);
}

static bool ida_inf_set_prefix_show_stack(bool _v)
{
	return setinf_flag(INF_PREFFLAG, PREF_STACK, _v);
}

static bool ida_inf_prefix_truncate_opcode_bytes()
{
	return getinf_flag(INF_PREFFLAG, PREF_PFXTRUNC);
}

static bool ida_inf_set_prefix_truncate_opcode_bytes(bool _v)
{
	return setinf_flag(INF_PREFFLAG, PREF_PFXTRUNC, _v);
}

// strlit_flags
static uchar ida_inf_get_strlit_flags()
{
	return uchar(getinf(INF_STRLIT_FLAGS));
}

static bool ida_inf_set_strlit_flags(uchar _v)
{
	return setinf(INF_STRLIT_FLAGS, ssize_t(_v));
}

static bool ida_inf_strlit_names()
{
	return getinf_flag(INF_STRLIT_FLAGS, STRF_GEN);
}

static bool ida_inf_set_strlit_names(bool _v)
{
	return setinf_flag(INF_STRLIT_FLAGS, STRF_GEN, _v);
}

static bool ida_inf_strlit_name_bit()
{
	return getinf_flag(INF_STRLIT_FLAGS, STRF_AUTO);
}

static bool ida_inf_set_strlit_name_bit(bool _v)
{
	return setinf_flag(INF_STRLIT_FLAGS, STRF_AUTO, _v);
}

static bool ida_inf_strlit_serial_names()
{
	return getinf_flag(INF_STRLIT_FLAGS, STRF_SERIAL);
}

static bool ida_inf_set_strlit_serial_names(bool _v)
{
	return setinf_flag(INF_STRLIT_FLAGS, STRF_SERIAL, _v);
}

static bool ida_inf_unicode_strlits()
{
	return getinf_flag(INF_STRLIT_FLAGS, STRF_UNICODE);
}

static bool ida_inf_set_unicode_strlits(bool _v)
{
	return setinf_flag(INF_STRLIT_FLAGS, STRF_UNICODE, _v);
}

static bool ida_inf_strlit_autocmt()
{
	return getinf_flag(INF_STRLIT_FLAGS, STRF_COMMENT);
}

static bool ida_inf_set_strlit_autocmt(bool _v)
{
	return setinf_flag(INF_STRLIT_FLAGS, STRF_COMMENT, _v);
}

static bool ida_inf_strlit_savecase()
{
	return getinf_flag(INF_STRLIT_FLAGS, STRF_SAVECASE);
}

static bool ida_inf_set_strlit_savecase(bool _v)
{
	return setinf_flag(INF_STRLIT_FLAGS, STRF_SAVECASE, _v);
}

// strlit_break
static uchar ida_inf_get_strlit_break()
{
	return uchar(getinf(INF_STRLIT_BREAK));
}

static bool ida_inf_set_strlit_break(uchar _v)
{
	return setinf(INF_STRLIT_BREAK, ssize_t(_v));
}

// strlit_zeroes
static char ida_inf_get_strlit_zeroes()
{
	return char(getinf(INF_STRLIT_ZEROES));
}

static bool ida_inf_set_strlit_zeroes(char _v)
{
	return setinf(INF_STRLIT_ZEROES, ssize_t(_v));
}

// strtype
static int32 ida_inf_get_strtype()
{
	return int32(getinf(INF_STRTYPE));
}

static bool ida_inf_set_strtype(int32 _v)
{
	return setinf(INF_STRTYPE, ssize_t(_v));
}

// strlit_sernum
static uval_t ida_inf_get_strlit_sernum()
{
	return uval_t(getinf(INF_STRLIT_SERNUM));
}

static bool ida_inf_set_strlit_sernum(uval_t _v)
{
	return setinf(INF_STRLIT_SERNUM, ssize_t(_v));
}

// datatypes
static uval_t ida_inf_get_datatypes()
{
	return uval_t(getinf(INF_DATATYPES));
}

static bool ida_inf_set_datatypes(uval_t _v)
{
	return setinf(INF_DATATYPES, ssize_t(_v));
}

// cc
static bool ida_inf_get_cc(IntPtr out)
{
	compiler_info_t cc;
	bool ret = inf_get_cc(&cc);
	// must copy cc to out
	return ret;
}

//static bool ida_inf_set_cc(ref compiler_info_t _v)
//{
//
//}


// abibits
static uint32 ida_inf_get_abibits()
{
	return uint32(getinf(INF_ABIBITS));
}

static bool ida_inf_set_abibits(uint32 _v)
{
	return setinf(INF_ABIBITS, ssize_t(_v));
}

static bool ida_inf_is_mem_aligned4()
{
	return getinf_flag(INF_ABIBITS, ABI_8ALIGN4);
}

static bool ida_inf_set_mem_aligned4(bool _v)
{
	return setinf_flag(INF_ABIBITS, ABI_8ALIGN4, _v);
}

static bool ida_inf_pack_stkargs()
{
	return getinf_flag(INF_ABIBITS, ABI_PACK_STKARGS);
}

static bool ida_inf_set_pack_stkargs(bool _v)
{
	return setinf_flag(INF_ABIBITS, ABI_PACK_STKARGS, _v);
}

static bool ida_inf_big_arg_align()
{
	return getinf_flag(INF_ABIBITS, ABI_BIGARG_ALIGN);
}

static bool ida_inf_set_big_arg_align(bool _v)
{
	return setinf_flag(INF_ABIBITS, ABI_BIGARG_ALIGN, _v);
}

static bool ida_inf_stack_ldbl()
{
	return getinf_flag(INF_ABIBITS, ABI_STACK_LDBL);
}

static bool ida_inf_set_stack_ldbl(bool _v)
{
	return setinf_flag(INF_ABIBITS, ABI_STACK_LDBL, _v);
}

static bool ida_inf_stack_varargs()
{
	return getinf_flag(INF_ABIBITS, ABI_STACK_VARARGS);
}

static bool ida_inf_set_stack_varargs(bool _v)
{
	return setinf_flag(INF_ABIBITS, ABI_STACK_VARARGS, _v);
}

static bool ida_inf_is_hard_float()
{
	return getinf_flag(INF_ABIBITS, ABI_HARD_FLOAT);
}

static bool ida_inf_set_hard_float(bool _v)
{
	return setinf_flag(INF_ABIBITS, ABI_HARD_FLOAT, _v);
}

static bool ida_inf_abi_set_by_user()
{
	return getinf_flag(INF_ABIBITS, ABI_SET_BY_USER);
}

static bool ida_inf_set_abi_set_by_user(bool _v)
{
	return setinf_flag(INF_ABIBITS, ABI_SET_BY_USER, _v);
}

static bool ida_inf_use_gcc_layout()
{
	return getinf_flag(INF_ABIBITS, ABI_GCC_LAYOUT);
}

static bool ida_inf_set_use_gcc_layout(bool _v)
{
	return setinf_flag(INF_ABIBITS, ABI_GCC_LAYOUT, _v);
}

static bool ida_inf_map_stkargs()
{
	return getinf_flag(INF_ABIBITS, ABI_MAP_STKARGS);
}

static bool ida_inf_set_map_stkargs(bool _v)
{
	return setinf_flag(INF_ABIBITS, ABI_MAP_STKARGS, _v);
}

static bool ida_inf_huge_arg_align()
{
	return getinf_flag(INF_ABIBITS, ABI_HUGEARG_ALIGN);
}

static bool ida_inf_set_huge_arg_align(bool _v)
{
	return setinf_flag(INF_ABIBITS, ABI_HUGEARG_ALIGN, _v);
}

// appcall_options
static uint32 ida_inf_get_appcall_options()
{
	return uint32(getinf(INF_APPCALL_OPTIONS));
}

static bool ida_inf_set_appcall_options(uint32 _v)
{
	return setinf(INF_APPCALL_OPTIONS, ssize_t(_v));
}

// privrange_start_ea
static ea_t ida_inf_get_privrange_start_ea()
{
	return ea_t(getinf(INF_PRIVRANGE_START_EA));
}

static bool ida_inf_set_privrange_start_ea(ea_t _v)
{
	return setinf(INF_PRIVRANGE_START_EA, ssize_t(_v));
}

// privrange_end_ea
static ea_t ida_inf_get_privrange_end_ea()
{
	return ea_t(getinf(INF_PRIVRANGE_END_EA));
}

static bool ida_inf_set_privrange_end_ea(ea_t _v)
{
	return setinf(INF_PRIVRANGE_END_EA, ssize_t(_v));
}

// cc_id
static comp_t ida_inf_get_cc_id()
{
	return comp_t(getinf(INF_CC_ID));
}

static bool ida_inf_set_cc_id(comp_t _v)
{
	return setinf(INF_CC_ID, ssize_t(_v));
}

// cc_cm
static cm_t ida_inf_get_cc_cm()
{
	return cm_t(getinf(INF_CC_CM));
}

static bool ida_inf_set_cc_cm(cm_t _v)
{
	return setinf(INF_CC_CM, ssize_t(_v));
}

// cc_size_i
static uchar ida_inf_get_cc_size_i()
{
	return uchar(getinf(INF_CC_SIZE_I));
}

static bool ida_inf_set_cc_size_i(uchar _v)
{
	return setinf(INF_CC_SIZE_I, ssize_t(_v));
}

// cc_size_b
static uchar ida_inf_get_cc_size_b()
{
	return uchar(getinf(INF_CC_SIZE_B));
}

static bool ida_inf_set_cc_size_b(uchar _v)
{
	return setinf(INF_CC_SIZE_B, ssize_t(_v));
}

// cc_size_e
static uchar ida_inf_get_cc_size_e()
{
	return uchar(getinf(INF_CC_SIZE_E));
}

static bool ida_inf_set_cc_size_e(uchar _v)
{
	return setinf(INF_CC_SIZE_E, ssize_t(_v));
}

// cc_defalign
static uchar ida_inf_get_cc_defalign()
{
	return uchar(getinf(INF_CC_DEFALIGN));
}

static bool ida_inf_set_cc_defalign(uchar _v)
{
	return setinf(INF_CC_DEFALIGN, ssize_t(_v));
}

// cc_size_s
static uchar ida_inf_get_cc_size_s()
{
	return uchar(getinf(INF_CC_SIZE_S));
}

static bool ida_inf_set_cc_size_s(uchar _v)
{
	return setinf(INF_CC_SIZE_S, ssize_t(_v));
}

// cc_size_l
static uchar ida_inf_get_cc_size_l()
{
	return uchar(getinf(INF_CC_SIZE_L));
}

static bool ida_inf_set_cc_size_l(uchar _v)
{
	return setinf(INF_CC_SIZE_L, ssize_t(_v));
}

// cc_size_ll
static uchar ida_inf_get_cc_size_ll()
{
	return uchar(getinf(INF_CC_SIZE_LL));
}

static bool ida_inf_set_cc_size_ll(uchar _v)
{
	return setinf(INF_CC_SIZE_LL, ssize_t(_v));
}

// cc_size_ldbl
static uchar ida_inf_get_cc_size_ldbl()
{
	return uchar(getinf(INF_CC_SIZE_LDBL));
}

static bool ida_inf_set_cc_size_ldbl(uchar _v)
{
	return setinf(INF_CC_SIZE_LDBL, ssize_t(_v));
}

// privrange
static bool ida_inf_get_privrange(IntPtr ptr)
{
	range_t* out = (range_t*)(ptr.ToPointer());
	return getinf_buf(INF_PRIVRANGE, out, sizeof(*out));
}

//static bool ida_inf_set_privrange(ref range_t _v)
//{
//
//}
//
//static range_t ida_inf_get_privrange()
//{
//
//}

/// Get/set low/high 16bit halves of inf.af
static ushort ida_inf_get_af_low()
{
	return inf_get_af() & 0xffff;
}

static void ida_inf_set_af_low(ushort saf)
{
	uint32 af = (inf_get_af() & 0xffff0000) | saf;
	inf_set_af(af);
}

static ushort ida_inf_get_af_high()
{
	return (inf_get_af() >> 16) & 0xffff;
}

static void ida_inf_set_af_high(ushort saf2)
{
	uint32 af = (inf_get_af() & 0xffff) | (saf2 << 16);
	inf_set_af(af);
}

/// Get/set low 16bit half of inf.af2
static ushort ida_inf_get_af2_low()
{
	return inf_get_af2() & 0xffff;
}

static void ida_inf_set_af2_low(ushort saf)
{
	uint32 af2 = (inf_get_af2() & 0xffff0000) | saf;
	inf_set_af2(af2);
}

static int ida_inf_get_pack_mode()
{
	uint32 lflags = inf_get_lflags();
	return (lflags & LFLG_COMPRESS) != 0 ? IDB_COMPRESSED
		: (lflags & LFLG_PACK) != 0 ? IDB_PACKED
		: IDB_UNPACKED;
}

static int ida_inf_set_pack_mode(int pack_mode)
{
	int old = inf_get_pack_mode();
	uint32 lflags = inf_get_lflags();
	setflag(lflags, LFLG_COMPRESS, pack_mode == IDB_COMPRESSED);
	setflag(lflags, LFLG_PACK, pack_mode == IDB_PACKED);
	inf_set_lflags(lflags);
	return old;
}

static void ida_inf_inc_database_change_count(int cnt)
{
	inf_set_database_change_count(inf_get_database_change_count() + cnt);
}

static uchar ida_inf_get_demname_form()
{
	return uchar(inf_get_demnames() & DEMNAM_MASK);
}

static uval_t ida_inf_postinc_strlit_sernum(uval_t cnt)
{
	uval_t was = inf_get_strlit_sernum();
	inf_set_strlit_sernum(was + cnt);
	return was;
}

static bool ida_inf_like_binary()
{
	return is_filetype_like_binary(inf_get_filetype());
}

static int ida_calc_default_idaplace_flags()
{
	return 0;
}

static ea_t ida_to_ea(sel_t reg_cs, uval_t reg_ip)
{
	return (reg_cs << 4) + reg_ip;
}

//typedef ssize_t idaapi hook_cb_t(void* user_data, int notification_code, va_list va);

//static bool ida_export hook_to_notification_point(
//	hook_type_t hook_type,
//	hook_cb_t* cb,
//	void* user_data = NULL);

//static int ida_export unhook_from_notification_point(
//	hook_type_t hook_type,
//	hook_cb_t* cb,
//	void* user_data = NULL);

static ssize_t ida_invoke_callbacks(hook_type_t hook_type, int notification_code, va_list va)
{
	return invoke_callbacks(hook_type, notification_code, va);
}

//struct post_event_visitor_t
//{
//	virtual ssize_t idaapi handle_post_event(
//		ssize_t code,
//		int notification_code,
//		va_list va) = 0;
//
//	virtual ~post_event_visitor_t() {}
//};

//
//idaman bool ida_export register_post_event_visitor(
//	hook_type_t hook_type,
//	post_event_visitor_t* visitor,
//	const plugmod_t* owner);
//
//
//idaman bool ida_export unregister_post_event_visitor(
//	hook_type_t hook_type,
//	post_event_visitor_t* visitor);



static ssize_t ida_get_dbctx_id()
{
	return get_dbctx_id();
}

static size_t ida_get_dbctx_qty()
{
	return get_dbctx_qty();
}

static IntPtr ida_switch_dbctx(size_t idx)
{
	return IntPtr(switch_dbctx(idx));
}
