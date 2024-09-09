#pragma once

[::System::Runtime::InteropServices::UnmanagedFunctionPointer(::System::Runtime::InteropServices::CallingConvention::Cdecl)]
delegate range_t* Func___IntPtr_intPtr(int* n);

[::System::Runtime::InteropServices::UnmanagedFunctionPointer(::System::Runtime::InteropServices::CallingConvention::Cdecl)]
delegate int Func_int_UInt64___IntPtr_int(unsigned long long ea, ::System::IntPtr buffer, int size);

static bool ida_run_requests()
{
	return callui(ui_dbg_run_requests).cnd;
}

static ui_notification_t ida_get_running_request()
{
	return (ui_notification_t)callui(ui_dbg_get_running_request).i;
}

static bool ida_is_request_running()
{
	return get_running_request() != ui_null;
}

static dbg_notification_t ida_get_running_notification()
{
	return (dbg_notification_t)callui(ui_dbg_get_running_notification).i;
}

static void ida_clear_requests_queue()
{
	callui(ui_dbg_clear_requests_queue);
}

static int ida_get_process_state()
{
	return callui(ui_dbg_get_process_state).i;
}

static bool ida_is_valid_dstate(int state)
{
	return state == -1 || state == 0 || state == 1;
}

static int ida_set_process_state(int newstate, IntPtr p_thid, int dbginv)
{
	return callui(ui_dbg_set_process_state, newstate, (thid_t *)(p_thid.ToPointer()), dbginv).i;
}

static int ida_invalidate_dbg_state(int dbginv)
{
	return set_process_state(DSTATE_NOTASK, nullptr, dbginv);
}

static int ida_start_process(IntPtr path, IntPtr args, IntPtr sdir)
{
	return callui(ui_dbg_start_process, (char*)(path.ToPointer()), (char*)(args.ToPointer()), (char*)(sdir.ToPointer())).i;
}

static int ida_request_start_process(IntPtr path, IntPtr args, IntPtr sdir)
{
	return callui(ui_dbg_request_start_process, (char*)(path.ToPointer()), (char*)(args.ToPointer()), (char*)(sdir.ToPointer())).i;
}

static bool ida_suspend_process()
{
	return callui(ui_dbg_suspend_process).cnd;
}

static bool ida_request_suspend_process()
{
	return callui(ui_dbg_request_suspend_process).cnd;
}

static bool ida_continue_process()
{
	return callui(ui_dbg_continue_process).cnd;
}

static bool ida_request_continue_process()
{
	return callui(ui_dbg_request_continue_process).cnd;
}

static bool ida_exit_process()
{
	return callui(ui_dbg_exit_process).cnd;
}

static bool ida_request_exit_process()
{
	return callui(ui_dbg_request_exit_process).cnd;
}

static ssize_t ida_get_processes(IntPtr proclist)
{
	return callui(ui_dbg_get_processes, (procinfo_vec_t *)(proclist.ToPointer())).ssize;
}

static int ida_attach_process(pid_t pid, int event_id)
{
	return callui(ui_dbg_attach_process, pid, event_id).i;
}

static int ida_request_attach_process(pid_t pid, int event_id)
{
	return callui(ui_dbg_request_attach_process, pid, event_id).i;
}

static bool ida_detach_process()
{
	return callui(ui_dbg_detach_process).cnd;
}

static bool ida_request_detach_process()
{
	return callui(ui_dbg_request_detach_process).cnd;
}

static bool ida_is_debugger_busy()
{
	return callui(ui_dbg_is_busy).cnd;
}

static int ida_get_thread_qty()
{
	return callui(ui_dbg_get_thread_qty).i;
}

static thid_t ida_getn_thread(int n)
{
	return (thid_t)callui(ui_dbg_getn_thread, n).i;
}

static thid_t ida_get_current_thread()
{
	return callui(ui_dbg_get_current_thread).i;
}

static IntPtr ida_getn_thread_name(int n)
{
	return IntPtr(callui(ui_dbg_getn_thread_name, n).cptr);
}

static bool ida_select_thread(thid_t tid)
{
	return callui(ui_dbg_select_thread, tid).cnd;
}

static bool ida_request_select_thread(thid_t tid)
{
	return callui(ui_dbg_request_select_thread, tid).cnd;
}

static int ida_suspend_thread(thid_t tid)
{
	return callui(ui_dbg_suspend_thread, tid).i;
}

static int ida_request_suspend_thread(thid_t tid)
{
	return callui(ui_dbg_request_suspend_thread, tid).i;
}

static int ida_resume_thread(thid_t tid)
{
	return callui(ui_dbg_resume_thread, tid).i;
}

static int ida_request_resume_thread(thid_t tid)
{
	return callui(ui_dbg_request_resume_thread, tid).i;
}

static bool ida_get_first_module(IntPtr modinfo)
{
	return callui(ui_dbg_get_first_module, (modinfo_t * )(modinfo.ToPointer())).cnd;
}

static bool ida_get_next_module(IntPtr modinfo)
{
	return callui(ui_dbg_get_next_module, (modinfo_t*)(modinfo.ToPointer())).cnd;
}

static bool ida_step_into()
{
	return callui(ui_dbg_step_into).cnd;
}

static bool ida_request_step_into()
{
	return callui(ui_dbg_request_step_into).cnd;
}

static bool ida_step_over()
{
	return callui(ui_dbg_step_over).cnd;
}

static bool ida_request_step_over()
{
	return callui(ui_dbg_request_step_over).cnd;
}

static bool ida_run_to(ea_t ea, pid_t pid, thid_t tid)
{
	return callui(ui_dbg_run_to, ea, pid, tid).cnd;
}

static bool ida_request_run_to(ea_t ea, pid_t pid, thid_t tid)
{
	return callui(ui_dbg_request_run_to, ea, pid, tid).cnd;
}

static bool ida_step_until_ret()
{
	return callui(ui_dbg_step_until_ret).cnd;
}

static bool ida_request_step_until_ret()
{
	return callui(ui_dbg_request_step_until_ret).cnd;
}

static bool ida_set_resume_mode(thid_t tid, resume_mode_t mode)
{
	return callui(ui_dbg_set_resume_mode, tid, mode).cnd;
}

static bool ida_request_set_resume_mode(thid_t tid, resume_mode_t mode)
{
	return callui(ui_dbg_request_set_resume_mode, tid, mode).cnd;
}

static bool ida_get_dbg_reg_info(IntPtr regname, IntPtr ri)
{
	return callui(ui_dbg_get_reg_info, (const char*)(regname.ToPointer()), (register_info_t*)(ri.ToPointer())).cnd;
}

static bool ida_get_reg_val(IntPtr regname, IntPtr regval)
{
	return callui(ui_dbg_get_reg_val, (const char*)(regname.ToPointer()), (regval_t*)(regval.ToPointer())).cnd;
}

static bool ida_get_reg_val_i(IntPtr regname, IntPtr ival)
{
	return callui(ui_dbg_get_reg_val_i, (const char*)(regname.ToPointer()), (uint64*)(ival.ToPointer())).cnd;
}

static bool ida_get_sp_val(IntPtr out)
{
	return callui(ui_dbg_get_sp_val, (ea_t*)(out.ToPointer())).cnd;
}

static bool ida_get_ip_val(IntPtr out)
{
	return callui(ui_dbg_get_ip_val, (ea_t*)(out.ToPointer())).cnd;
}

static bool ida_set_reg_val(IntPtr regname, IntPtr regval)
{
	return callui(ui_dbg_set_reg_val, (const char*)(regname.ToPointer()), (regval_t*)(regval.ToPointer())).cnd;
}

static bool ida_set_reg_val(IntPtr regname, uint64 ival)
{
	return callui(ui_dbg_set_reg_val_i, (const char*)(regname.ToPointer()), ival).cnd;
}

static bool ida_request_set_reg_val(IntPtr regname, IntPtr regval)
{
	return callui(ui_dbg_request_set_reg_val, (const char*)(regname.ToPointer()), (regval_t*)(regval.ToPointer())).cnd;
}

static bool ida_is_reg_integer(IntPtr regname)
{
	return callui(ui_dbg_get_reg_value_type, (const char*)(regname.ToPointer())).i - 2 == RVT_INT;
}

static bool ida_is_reg_float(IntPtr regname)
{
	return callui(ui_dbg_get_reg_value_type, (const char*)(regname.ToPointer())).i - 2 == RVT_FLOAT;
}

static bool ida_is_reg_custom(IntPtr regname)
{
	return callui(ui_dbg_get_reg_value_type, (const char*)(regname.ToPointer())).i >= 2;
}

static int ida_set_bptloc_string(IntPtr s)
{
	return callui(ui_dbg_set_bptloc_string, (const char*)(s.ToPointer())).i;
}

static IntPtr ida_get_bptloc_string(int i)
{
	return IntPtr((void*)callui(ui_dbg_get_bptloc_string, i).cptr);
}

static int ida_get_bpt_qty()
{
	return callui(ui_dbg_get_bpt_qty).i;
}

static bool ida_getn_bpt(int n, IntPtr bpt)
{
	return callui(ui_dbg_getn_bpt, n, (bpt_t*)(bpt.ToPointer())).cnd;
}

static bool ida_get_bpt(ea_t ea, IntPtr bpt)
{
	return callui(ui_dbg_get_bpt, ea, (bpt_t*)(bpt.ToPointer())).cnd;
}

static bool ida_exist_bpt(ea_t ea)
{
	return get_bpt(ea, nullptr);
}

static bool ida_add_bpt(ea_t ea, asize_t size, bpttype_t type)
{
	return callui(ui_dbg_add_oldbpt, ea, size, type).cnd;
}

static bool ida_request_add_bpt(ea_t ea, asize_t size, bpttype_t type)
{
	return callui(ui_dbg_request_add_oldbpt, ea, size, type).cnd;
}

static bool ida_add_bpt(IntPtr bpt)
{
	return callui(ui_dbg_add_bpt, (const bpt_t*)(bpt.ToPointer())).cnd;
}

static bool ida_request_add_bpt(IntPtr bpt)
{
	return callui(ui_dbg_request_add_bpt, (const bpt_t*)(bpt.ToPointer())).cnd;
}

static bool ida_del_bpt(ea_t ea)
{
	return callui(ui_dbg_del_oldbpt, ea).cnd;
}

static bool ida_request_del_bpt(ea_t ea)
{
	return callui(ui_dbg_request_del_oldbpt, ea).cnd;
}

static bool ida_del_bpt(IntPtr bptloc)
{
	return callui(ui_dbg_del_bpt, (const bpt_location_t*)(bptloc.ToPointer())).cnd;
}

static bool ida_request_del_bpt(IntPtr bptloc)
{
	return callui(ui_dbg_request_del_bpt, (const bpt_location_t*)(bptloc.ToPointer())).cnd;
}

static bool ida_update_bpt(IntPtr bpt)
{
	return callui(ui_dbg_update_bpt, (const bpt_t*)(bpt.ToPointer())).cnd;
}

static bool ida_find_bpt(IntPtr bptloc, IntPtr bpt)
{
	return callui(ui_dbg_find_bpt, (const bpt_location_t*)(bptloc.ToPointer()), (bpt_t*)(bpt.ToPointer())).cnd;
}

static int ida_change_bptlocs(IntPtr movinfo, IntPtr codes, bool del_hindering_bpts)
{
	return callui(ui_dbg_change_bptlocs, (const movbpt_infos_t*)(movinfo.ToPointer()), (movbpt_codes_t*)(codes.ToPointer()), del_hindering_bpts).i;
}

static bool ida_enable_bpt(ea_t ea, bool enable)
{
	return callui(ui_dbg_enable_oldbpt, ea, enable).cnd;
}

static bool ida_enable_bpt(IntPtr bptloc, bool enable)
{
	return callui(ui_dbg_enable_bpt, (const bpt_location_t*)(bptloc.ToPointer()), enable).cnd;
}

static bool ida_disable_bpt(ea_t ea)
{
	return enable_bpt(ea, false);
}

static bool ida_disable_bpt(IntPtr bptloc)
{
	return enable_bpt(*(const bpt_location_t*)(bptloc.ToPointer()), false);
}

static bool ida_request_enable_bpt(ea_t ea, bool enable)
{
	return callui(ui_dbg_request_enable_oldbpt, ea, enable).cnd;
}

static bool ida_request_disable_bpt(ea_t ea)
{
	return request_enable_bpt(ea, false);
}

static bool ida_request_disable_bpt(IntPtr bptloc)
{
	return request_enable_bpt(*(const bpt_location_t*)(bptloc.ToPointer()), false);
}

static int ida_check_bpt(ea_t ea)
{
	return callui(ui_dbg_check_bpt, ea).i;
}

static bool ida_set_trace_size(int size)
{
	return callui(ui_dbg_set_trace_size, size).cnd;
}

static void ida_clear_trace()
{
	callui(ui_dbg_clear_trace);
}

static void ida_request_clear_trace()
{
	callui(ui_dbg_request_clear_trace);
}

static bool ida_is_step_trace_enabled()
{
	return callui(ui_dbg_is_step_trace_enabled).cnd;
}

static bool ida_enable_step_trace(int enable)
{
	return callui(ui_dbg_enable_step_trace, enable).cnd;
}

static bool ida_disable_step_trace()
{
	return enable_step_trace(0);
}

static bool ida_request_enable_step_trace(int enable)
{
	return callui(ui_dbg_request_enable_step_trace, enable).cnd;
}

static bool ida_request_disable_step_trace()
{
	return request_enable_step_trace(false);
}

static int ida_get_step_trace_options()
{
	return callui(ui_dbg_get_step_trace_options).i;
}

static void ida_set_step_trace_options(int options)
{
	callui(ui_dbg_set_step_trace_options, options);
}

static void ida_request_set_step_trace_options(int options)
{
	callui(ui_dbg_request_set_step_trace_options, options);
}

static bool ida_is_insn_trace_enabled()
{
	return callui(ui_dbg_is_insn_trace_enabled).cnd;
}

static bool ida_enable_insn_trace(bool enable)
{
	return callui(ui_dbg_enable_insn_trace, enable).cnd;
}

static bool ida_disable_insn_trace()
{
	return enable_insn_trace(false);
}

static bool ida_request_enable_insn_trace(bool enable)
{
	return callui(ui_dbg_request_enable_insn_trace, enable).cnd;
}

static bool ida_request_disable_insn_trace()
{
	return request_enable_insn_trace(false);
}

static int ida_get_insn_trace_options()
{
	return callui(ui_dbg_get_insn_trace_options).i;
}

static void ida_set_insn_trace_options(int options)
{
	callui(ui_dbg_set_insn_trace_options, options);
}

static void ida_request_set_insn_trace_options(int options)
{
	callui(ui_dbg_request_set_insn_trace_options, options);
}

static bool ida_is_func_trace_enabled()
{
	return callui(ui_dbg_is_func_trace_enabled).cnd;
}

static bool ida_enable_func_trace(bool enable)
{
	return callui(ui_dbg_enable_func_trace, enable).cnd;
}

static bool ida_disable_func_trace()
{
	return enable_func_trace(false);
}

static bool ida_request_enable_func_trace(bool enable)
{
	return callui(ui_dbg_request_enable_func_trace, enable).cnd;
}

static bool ida_request_disable_func_trace()
{
	return request_enable_func_trace(false);
}

static int ida_get_func_trace_options()
{
	return callui(ui_dbg_get_func_trace_options).i;
}

static void ida_set_func_trace_options(int options)
{
	callui(ui_dbg_set_func_trace_options, options);
}

static void ida_request_set_func_trace_options(int options)
{
	callui(ui_dbg_request_set_func_trace_options, options);
}

static bool ida_enable_bblk_trace(bool enable)
{
	return callui(ui_dbg_enable_bblk_trace, enable).cnd;
}

static bool ida_disable_bblk_trace()
{
	return enable_bblk_trace(false);
}

static bool ida_request_enable_bblk_trace(bool enable)
{
	return callui(ui_dbg_request_enable_bblk_trace, enable).cnd;
}

static bool ida_request_disable_bblk_trace()
{
	return request_enable_bblk_trace(false);
}

static bool ida_is_bblk_trace_enabled()
{
	return callui(ui_dbg_is_bblk_trace_enabled).cnd;
}

static int ida_get_bblk_trace_options()
{
	return callui(ui_dbg_get_bblk_trace_options).i;
}

static void ida_set_bblk_trace_options(int options)
{
	callui(ui_dbg_set_bblk_trace_options, options);
}

static void ida_request_set_bblk_trace_options(int options)
{
	callui(ui_dbg_request_set_bblk_trace_options, options);
}

static int ida_get_tev_qty()
{
	return callui(ui_dbg_get_tev_qty).i;
}

static bool ida_get_tev_info(int n, IntPtr tev_info)
{
	return callui(ui_dbg_get_tev_info, n, (tev_info_t*)(tev_info.ToPointer())).cnd;
}

static bool ida_get_insn_tev_reg_val(int n, IntPtr regname, IntPtr regval)
{
	return callui(ui_dbg_get_insn_tev_reg_val, n, (const char*)(regname.ToPointer()), (regval_t*)(regval.ToPointer())).cnd;
}

static bool ida_get_insn_tev_reg_val_i(int n, IntPtr regname, IntPtr ival)
{
	return callui(ui_dbg_get_insn_tev_reg_val_i, n, (const char*)(regname.ToPointer()), (uint64*)(ival.ToPointer())).cnd;
}

static bool ida_get_insn_tev_reg_mem(int n, IntPtr memmap)
{
	return callui(ui_dbg_get_insn_tev_reg_mem, n, (memreg_infos_t*)(memmap.ToPointer())).cnd;
}

static bool ida_get_insn_tev_reg_result(int n, IntPtr regname, IntPtr regval)
{
	return callui(ui_dbg_get_insn_tev_reg_result, n, (const char*)(regname.ToPointer()), (regval_t*)(regval.ToPointer())).cnd;
}

static bool ida_get_insn_tev_reg_result_i(int n, IntPtr regname, IntPtr ival)
{
	return callui(ui_dbg_get_insn_tev_reg_result_i, n, (const char*)(regname.ToPointer()), (uint64*)(ival.ToPointer())).cnd;
}

static ea_t ida_get_call_tev_callee(int n)
{
	ea_t ea;
	callui(ui_dbg_get_call_tev_callee, n, &ea);
	return ea;
}

static ea_t ida_get_ret_tev_return(int n)
{
	ea_t ea;
	callui(ui_dbg_get_ret_tev_return, n, &ea);
	return ea;
}

static ea_t ida_get_bpt_tev_ea(int n)
{
	ea_t ea;
	callui(ui_dbg_get_bpt_tev_ea, n, &ea);
	return ea;
}

static bool ida_get_tev_memory_info(int n, IntPtr mi)
{
	return callui(ui_dbg_get_tev_memory_info, n, (meminfo_vec_t*)(mi.ToPointer())).cnd;
}

static bool ida_get_tev_event(int n, IntPtr d)
{
	return callui(ui_dbg_get_tev_event, n, (debug_event_t*)(d.ToPointer())).cnd;
}

static ea_t ida_get_trace_base_address()
{
	ea_t ea;
	callui(ui_dbg_get_trace_base_address, &ea);
	return ea;
}

static void ida_set_trace_base_address(ea_t ea)
{
	callui(ui_dbg_set_trace_base_address, ea);
}

static void ida_dbg_add_thread(thid_t tid)
{
	callui(ui_dbg_add_thread, tid);
}

static void ida_dbg_del_thread(thid_t tid)
{
	callui(ui_dbg_del_thread, tid);
}

static void ida_dbg_add_tev(tev_type_t type, thid_t tid, ea_t address)
{
	callui(ui_dbg_add_tev, type, tid, address);
}

static bool ida_dbg_add_many_tevs(IntPtr new_tevs)
{
	return callui(ui_dbg_add_many_tevs, new_tevs).cnd;
}

static bool ida_dbg_add_insn_tev(thid_t tid, ea_t ea, save_reg_values_t save)
{
	return callui(ui_dbg_add_insn_tev, tid, ea, save).cnd;
}

static bool ida_dbg_add_bpt_tev(thid_t tid, ea_t ea, ea_t bp)
{
	return callui(ui_dbg_add_bpt_tev, tid, ea, bp).cnd;
}

static void ida_dbg_add_call_tev(thid_t tid, ea_t caller, ea_t callee)
{
	callui(ui_dbg_add_call_tev, tid, caller, callee);
}

static void ida_dbg_add_ret_tev(thid_t tid, ea_t ret_insn, ea_t return_to)
{
	callui(ui_dbg_add_ret_tev, tid, ret_insn, return_to);
}

static void ida_dbg_add_debug_event(IntPtr event)
{
	callui(ui_dbg_add_debug_event, event);
}

static bool ida_load_trace_file(IntPtr buf, IntPtr filename)
{
	return callui(ui_dbg_load_trace_file, buf, filename).cnd;
}

static bool ida_save_trace_file(IntPtr filename, IntPtr description)
{
	return callui(ui_dbg_save_trace_file, filename, description).cnd;
}

static bool ida_is_valid_trace_file(IntPtr filename)
{
	return callui(ui_dbg_is_valid_trace_file, filename).cnd;
}

static bool ida_set_trace_file_desc(IntPtr filename, IntPtr description)
{
	return callui(ui_dbg_set_trace_file_desc, filename, description).cnd;
}

static bool ida_get_trace_file_desc(IntPtr buf, IntPtr filename)
{
	return callui(ui_dbg_get_trace_file_desc, buf, filename).cnd;
}

static bool ida_choose_trace_file(IntPtr buf)
{
	return callui(ui_dbg_choose_trace_file, buf).cnd;
}

static bool ida_diff_trace_file(const char* filename)
{
	return callui(ui_dbg_diff_trace_file, filename).cnd;
}

static bool ida_graph_trace()
{
	return callui(ui_dbg_graph_trace).cnd;
}

static void ida_set_highlight_trace_options(bool hilight, bgcolor_t color, bgcolor_t diff)
{
	callui(ui_dbg_set_highlight_trace_options, hilight, color, diff);
}

static void ida_set_trace_platform(IntPtr platform)
{
	callui(ui_dbg_set_trace_platform, platform);
}

static IntPtr ida_get_trace_platform()
{
	return IntPtr((void*)callui(ui_dbg_get_trace_platform).cptr);
}

static void ida_set_trace_dynamic_register_set(IntPtr idaregs)
{
    callui(ui_dbg_set_trace_dynamic_register_set, *(dynamic_register_set_t*)(idaregs.ToPointer()));
}

static void ida_get_trace_dynamic_register_set(IntPtr idaregs)
{
	callui(ui_dbg_get_trace_dynamic_register_set, *(dynamic_register_set_t*)(idaregs.ToPointer()));
}

static dbg_event_code_t ida_wait_for_next_event(int wfne, int timeout)
{
	return dbg_event_code_t(callui(ui_dbg_wait_for_next_event, wfne, timeout).i);
}

static IntPtr ida_get_debug_event()
{
	return IntPtr((void*)(const debug_event_t *)callui(ui_dbg_get_debug_event).vptr);
}

static uint ida_set_debugger_options(uint options)
{
	return callui(ui_dbg_set_debugger_options, options).i;
}

static void ida_set_remote_debugger(IntPtr host, IntPtr pass, int port)
{
	callui(ui_dbg_set_remote_debugger, host, pass, port);
}

static void ida_get_process_options(IntPtr path, IntPtr args, IntPtr sdir, IntPtr host, IntPtr pass, IntPtr port)
{
	callui(ui_dbg_get_process_options, path, args, sdir, host, pass, port);
}

static void ida_set_process_options(IntPtr path, IntPtr args, IntPtr sdir, IntPtr host, IntPtr pass, int port)
{
	callui(ui_dbg_set_process_options, path, args, sdir, host, pass, port);
}

static IntPtr ida_retrieve_exceptions()
{
	return IntPtr((excvec_t *)callui(ui_dbg_retrieve_exceptions).vptr);
}

static bool ida_store_exceptions()
{
	return callui(ui_dbg_store_exceptions).cnd;
}

static IntPtr ida_define_exception(uint code, IntPtr name, IntPtr desc, int flags)
{
	return IntPtr((void*)callui(ui_dbg_define_exception, code, (const char*)(name.ToPointer()), (const char*)(desc.ToPointer()), flags).cptr);
}

static bool ida_have_set_options(IntPtr _dbg)
{
	auto debuggerp = (debugger_t*)(_dbg.ToPointer());
	return debuggerp != nullptr && debuggerp->set_dbg_options != nullptr;
}

static IntPtr ida_set_dbg_options(IntPtr _dbg, IntPtr keyword, int pri, int value_type, IntPtr value)
{
	const char* code = IDPOPT_BADKEY;
	if (have_set_options((debugger_t*)(_dbg.ToPointer())))
	{
		auto debuggerp = (debugger_t*)(_dbg.ToPointer());
		code = debuggerp->set_dbg_options((const char*)(keyword.ToPointer()), pri, value_type, (const void*)(value.ToPointer()));
	}
	return (IntPtr)((void*)code);
}

static IntPtr ida_set_dbg_default_options(IntPtr _dbg, IntPtr keyword, int value_type, IntPtr value)
{
	auto debuggerp = (debugger_t*)(_dbg.ToPointer());
	return (IntPtr((void*)set_dbg_options(debuggerp, (const char*)(keyword.ToPointer()), 1, value_type, (const void*)(value.ToPointer()))));
}

static IntPtr ida_set_int_dbg_options(IntPtr _dbg, IntPtr keyword, int32 value)
{
	sval_t sv = value;
	return IntPtr((void*)set_dbg_default_options((debugger_t*)(_dbg.ToPointer()), (const char*)(keyword.ToPointer()), 2, &sv));
}

static IntPtr ida_set_dbg_options(IntPtr keyword, int pri, int value_type, IntPtr value)
{
	return IntPtr((void*)set_dbg_options(dbg, (const char*)(keyword.ToPointer()), pri, value_type, (const void*)(value.ToPointer())));
}

static IntPtr ida_set_dbg_default_options(IntPtr keyword, int value_type, IntPtr value)
{
	return IntPtr((void*)set_dbg_options((const char*)(keyword.ToPointer()), 1, value_type, (const void*)(value.ToPointer())));
}

static IntPtr ida_set_int_dbg_options(IntPtr keyword, int32 value)
{
	sval_t sv = value;
	return IntPtr((void*)set_dbg_default_options((const char*)(keyword.ToPointer()), 2, &sv));
}

static bool ida_register_srcinfo_provider(IntPtr sp)
{
	return callui(ui_dbg_register_provider, sp).cnd;
}

static bool ida_unregister_srcinfo_provider(IntPtr sp)
{
	return callui(ui_dbg_unregister_provider, sp).cnd;
}

static IntPtr ida_create_source_viewer(IntPtr out_ccv, IntPtr parent, IntPtr custview, source_file_ptr sf, IntPtr lines, int lnnum, int colnum, int flags)
{
	return IntPtr((void*)(source_view_t *)callui(ui_create_source_viewer, out_ccv, parent, custview, &sf, lines, lnnum, colnum, flags).vptr);
}

static bool ida_get_dbg_byte(IntPtr out, ea_t ea)
{
	return get_dbg_byte((uint32*)(out.ToPointer()), ea);
}

static bool ida_put_dbg_byte(ea_t ea, uint32 x)
{
	return put_dbg_byte(ea, x);
}

static void ida_set_dbgmem_source(Func___IntPtr_intPtr^ dbg_get_memory_config, Func_int_UInt64___IntPtr_int^ memory_read, Func_int_UInt64___IntPtr_int^ memory_write)
{
	set_dbgmem_source(
		static_cast<::range_t * (*)(int*)>(::System::Runtime::InteropServices::Marshal::GetFunctionPointerForDelegate(dbg_get_memory_config).ToPointer()),
		static_cast<int (*)(ea_t, void*, int)>(::System::Runtime::InteropServices::Marshal::GetFunctionPointerForDelegate(memory_read).ToPointer()),
		static_cast<int (*)(ea_t, const void*, int)>(::System::Runtime::InteropServices::Marshal::GetFunctionPointerForDelegate(memory_write).ToPointer()));
}

static void ida_invalidate_dbgmem_config()
{
	invalidate_dbgmem_config();
}

static void ida_invalidate_dbgmem_contents(ea_t ea, asize_t size)
{
	invalidate_dbgmem_contents(ea, size);
}

static bool ida_is_debugger_on()
{
	return is_debugger_on();
}

static bool ida_is_debugger_memory(ea_t ea)
{
	return is_debugger_memory(ea);
}

static ea_t ida_get_tev_ea(int n)
{
	ea_t ea; 
	callui(ui_dbg_get_tev_ea, n, &ea); 
	return ea;
}

static int ida_get_tev_type(int n)
{
	return callui(ui_dbg_get_tev_type, n).i;
}

static int ida_get_tev_tid(int n)
{
	return callui(ui_dbg_get_tev_tid, n).i;
}

static void ida_bring_debugger_to_front()
{
	callui(ui_dbg_bring_to_front);
}

static void ida_get_manual_regions(IntPtr ranges)
{
	callui(ui_dbg_get_manual_regions, ranges);
}

static void ida_set_manual_regions(IntPtr ranges)
{
	callui(ui_dbg_set_manual_regions, ranges);
}

static void ida_edit_manual_regions()
{
	callui(ui_dbg_edit_manual_regions);
}

static void ida_enable_manual_regions(bool enable)
{
	callui(ui_dbg_enable_manual_regions, enable);
}

static int ida_handle_debug_event(IntPtr ev, int rqflags)
{
	return callui(ui_dbg_handle_debug_event, ev, rqflags).i;
}

static bool ida_add_virt_module(IntPtr mod)
{
	return callui(ui_dbg_add_vmod, mod).cnd;
}

static bool ida_del_virt_module(ea_t base)
{
	return callui(ui_dbg_del_vmod, base).cnd;
}

static int ida_internal_get_sreg_base(IntPtr answer, thid_t tid, int sreg_value)
{
	return callui(ui_dbg_internal_get_sreg_base, answer, tid, sreg_value).i;
}

static int ida_internal_ioctl(int fn, IntPtr buf, size_t size, IntPtr poutbuf, IntPtr poutsize)
{
	return callui(ui_dbg_internal_ioctl, fn, buf, size, poutbuf, poutsize).i;
}

static int ida_get_reg_vals(thid_t tid, int clsmask, IntPtr values)
{
	return callui(ui_dbg_read_registers, tid, clsmask, values).i;
}

static int ida_set_reg_val(thid_t tid, int regidx, IntPtr value)
{
	return callui(ui_dbg_write_register, tid, regidx, value).i;
}

static int ida_get_dbg_memory_info(IntPtr ranges)
{
	return callui(ui_dbg_get_memory_info, ranges).i;
}

static bool ida_set_bpt_group(IntPtr bpt, IntPtr grp_name)
{
    return callui(ui_dbg_set_bpt_group, *(bpt_t*)(bpt.ToPointer()), (const char*)(grp_name.ToPointer())).cnd;
}

static bool ida_set_bptloc_group(IntPtr bptloc, IntPtr grp_name)
{
    return callui(ui_dbg_set_bptloc_group, *(const bpt_location_t*)(bptloc.ToPointer()), (const char*)(grp_name.ToPointer())).cnd;
}

static bool ida_get_bpt_group(IntPtr grp_name, IntPtr bptloc)
{
    return callui(ui_dbg_get_bpt_group, (const char*)(grp_name.ToPointer()), *(const bpt_location_t*)(bptloc.ToPointer())).cnd;
}

static size_t ida_list_bptgrps(IntPtr bptgrps)
{
	return callui(ui_dbg_list_bptgrps, bptgrps).ssize;
}

static bool ida_rename_bptgrp(IntPtr old_name, IntPtr new_name)
{
	return callui(ui_dbg_rename_bptgrp, old_name, new_name).cnd;
}

static bool ida_del_bptgrp(IntPtr name)
{
	return callui(ui_dbg_del_bptgrp, name).cnd;
}

static ssize_t ida_get_grp_bpts(IntPtr bpts, IntPtr grp_name)
{
	return callui(ui_dbg_get_grp_bpts, bpts, grp_name).ssize;
}

static int ida_enable_bptgrp(IntPtr bptgrp_name, bool enable)
{
	return callui(ui_dbg_enable_bptgrp, bptgrp_name, enable).i;
}

static bool ida_get_local_vars(IntPtr prov, ea_t ea, IntPtr out)
{
	return callui(ui_dbg_get_local_vars, prov, ea, out).cnd;
}

static bool ida_srcdbg_request_step_into()
{
	return callui(ui_dbg_srcdbg_request_step_into).cnd;
}

static bool ida_srcdbg_request_step_over()
{
	return callui(ui_dbg_srcdbg_request_step_over).cnd;
}

static bool ida_srcdbg_request_step_until_ret()
{
	return callui(ui_dbg_srcdbg_request_step_until_ret).cnd;
}

static int ida_internal_cleanup_appcall(thid_t tid)
{
	return callui(ui_dbg_internal_cleanup_appcall, tid).i;
}

static int ida_hide_all_bpts()
{
	return callui(ui_dbg_hide_all_bpts).i;
}

static ssize_t ida_read_dbg_memory(ea_t ea, IntPtr buffer, size_t size)
{
	return callui(ui_dbg_read_memory, ea, buffer, size).ssize;
}

static bool ida_get_module_info(ea_t ea, IntPtr modinfo)
{
	return callui(ui_dbg_get_module_info, ea, (modinfo_t*)(modinfo.ToPointer())).cnd;
}

static drc_t ida_dbg_bin_search(IntPtr out, ea_t start_ea, ea_t end_ea, IntPtr data, int srch_flags, IntPtr errbuf)
{
    return drc_t(callui(ui_dbg_bin_search, out, start_ea, end_ea, *(const compiled_binpat_vec_t*)(data.ToPointer()), srch_flags, (qstring*)(errbuf.ToPointer())).i);
}

static bool ida_dbg_can_query(IntPtr _dbg)
{
	return _dbg != IntPtr::Zero && (((debugger_t *)(_dbg.ToPointer()))->may_disturb() || (get_process_state() < DSTATE_NOTASK));
}

static bool ida_dbg_can_query()
{
	return dbg_can_query(dbg);
}

static bool ida_load_debugger(IntPtr dbgname, bool use_remote)
{
	return callui(ui_dbg_load_debugger, dbgname, use_remote).cnd;
}

static bool ida_collect_stack_trace(thid_t tid, IntPtr trace)
{
	return callui(ui_dbg_collect_stack_trace, tid, trace).cnd;
}

static bool ida_get_global_var(IntPtr prov, ea_t ea, IntPtr name, IntPtr out)
{
	return callui(ui_dbg_get_global_var, prov, ea, name, out).cnd;
}

static bool ida_get_local_var(IntPtr prov, ea_t ea, IntPtr name, IntPtr out)
{
	return callui(ui_dbg_get_local_var, prov, ea, name, out).cnd;
}

static IntPtr ida_get_srcinfo_provider(IntPtr name)
{
	return IntPtr((srcinfo_provider_t *)callui(ui_dbg_get_srcinfo_provider, name).vptr);
}

static bool ida_get_current_source_file(IntPtr out)
{
	return callui(ui_dbg_get_current_source_file, out).cnd;
}

static int ida_get_current_source_line()
{
	return callui(ui_dbg_get_current_source_line).i;
}

static void ida_add_path_mapping(IntPtr src, IntPtr dst)
{
	callui(ui_dbg_add_path_mapping, src, dst);
}

static bool ida_srcdbg_step_into()
{
	return callui(ui_dbg_srcdbg_step_into).cnd;
}

static bool ida_srcdbg_step_over()
{
	return callui(ui_dbg_srcdbg_step_over).cnd;
}

static bool ida_srcdbg_step_until_ret()
{
	return callui(ui_dbg_srcdbg_step_until_ret).cnd;
}

static ssize_t ida_write_dbg_memory(ea_t ea, IntPtr buffer, size_t size)
{
	return callui(ui_dbg_write_memory, ea, buffer, size).ssize;
}

static void ida_set_debugger_event_cond(const char* evcond)
{
	callui(ui_dbg_set_event_cond, evcond);
}
static IntPtr ida_get_debugger_event_cond()
{
	return IntPtr(callui(ui_dbg_get_event_cond).cptr);
}

static void ida_lock_dbgmem_config()
{
	lock_dbgmem_config();
}

static void ida_unlock_dbgmem_config()
{
	unlock_dbgmem_config();
}

