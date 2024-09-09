#pragma once

// complete. but ok?

static bool ida_has_cf_chg(uint32 feature, uint opnum)
{
	static const int bits[] =
	{
	  CF_CHG1, CF_CHG2, CF_CHG3, CF_CHG4,
	  CF_CHG5, CF_CHG6, CF_CHG7, CF_CHG8,
	};

	CASSERT(qnumber(bits) == UA_MAXOP);
	return opnum < UA_MAXOP && (feature & bits[opnum]) != 0;
}

static bool ida_has_cf_use(uint32 feature, uint opnum)
{
	static const int bits[] =
	{
	  CF_USE1, CF_USE2, CF_USE3, CF_USE4,
	  CF_USE5, CF_USE6, CF_USE7, CF_USE8,
	};

	CASSERT(qnumber(bits) == UA_MAXOP);
	return opnum < UA_MAXOP && (feature & bits[opnum]) != 0;
}

static bool ida_has_insn_feature(uint16 icode, uint32 bit)
{
	return has_insn_feature(icode, bit);
}

static bool ida_is_call_insn(IntPtr insn)
{
	return is_call_insn(*(const insn_t*)(insn.ToPointer()));
}

static bool ida_is_ret_insn(IntPtr insn, bool strict)
{
	return is_ret_insn(*(const insn_t*)(insn.ToPointer()), strict);
}

static bool ida_is_indirect_jump_insn(IntPtr insn)
{
	return is_indirect_jump_insn(*(const insn_t*)(insn.ToPointer()));
}

static bool ida_is_basic_block_end(IntPtr insn, bool call_insn_stops_block)
{
	return is_basic_block_end(*(const insn_t*)(insn.ToPointer()), call_insn_stops_block);
}

static bool ida_hook_event_listener(hook_type_t hook_type, IntPtr cb, IntPtr owner, int hkcb_flags)
{
	return hook_event_listener(hook_type, (event_listener_t*)(cb.ToPointer()), (const void*)(owner.ToPointer()), hkcb_flags);
}

static bool ida_unhook_event_listener(hook_type_t hook_type, IntPtr cb)
{
	return unhook_event_listener(hook_type, (event_listener_t*)(cb.ToPointer()));
}

static void ida_remove_event_listener(IntPtr cb)
{
	remove_event_listener((event_listener_t*)(cb.ToPointer()));
}

static IntPtr ida_get_ph()
{
	return IntPtr((void*)get_ph());
}

static IntPtr ida_get_ash()
{
	return IntPtr((void*)get_ash());
}

static System::Func<::System::IntPtr, int>^ ida_get_hexdsp()
{
	return safe_cast<System::Func<::System::IntPtr, int>^>(::System::Runtime::InteropServices::Marshal::GetDelegateForFunctionPointer(::System::IntPtr(get_hexdsp()), System::Func<::System::IntPtr, int>::typeid));;
}

static int ida_str2reg(IntPtr p)
{
	return str2reg((const char*)(p.ToPointer()));
}

static int ida_is_align_insn(ea_t ea)
{
	return is_align_insn(ea);
}

static ssize_t ida_get_reg_name(IntPtr buf, int reg, size_t width, int reghi)
{
	qstring qstr;
	auto len = get_reg_name(&qstr, reg, width, reghi);
	if (buf == IntPtr::Zero)
	{
		return len;
	}

	::ConvertQstringToIntPtr(qstr, buf, len);
	return len;
}

static bool ida_parse_reg_name(IntPtr ri, IntPtr regname)
{
	return parse_reg_name((reg_info_t*)(ri.ToPointer()), (const char*)(regname.ToPointer()));
}

static bool ida_set_processor_type(IntPtr procname, setproc_level_t level)
{
	return set_processor_type((const char*)(procname.ToPointer()), level);
}

static IntPtr ida_get_idp_name(IntPtr buf, size_t bufsize)
{
	return IntPtr((void*)get_idp_name((char*)(buf.ToPointer()), bufsize));
}

static bool ida_set_target_assembler(int asmnum)
{
	return set_target_assembler(asmnum);
}

static void ida_gen_idb_event(idb_event::event_code_t code) // ???
{
	invoke_callbacks(HT_IDB, code, nullptr);
}

static IntPtr ida_set_module_data(IntPtr data_id, IntPtr data_ptr)
{
	return IntPtr((void*)set_module_data((int*)(data_id.ToPointer()), (void*)(data_ptr.ToPointer())));
}

static IntPtr ida_clr_module_data(int data_id)
{
	return IntPtr((void*)clr_module_data(data_id));
}

static IntPtr ida_get_module_data(int data_id)
{
	return IntPtr((void*)get_module_data(data_id));
}

