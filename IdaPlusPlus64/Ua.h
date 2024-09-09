#pragma once

[::System::Runtime::InteropServices::UnmanagedFunctionPointer(::System::Runtime::InteropServices::CallingConvention::Cdecl)]
delegate bool Func_bool___IntPtr_bool(insn_t& insn, bool may_go_forward);

static bool ida_insn_create_op_data(IntPtr insn, ea_t ea, int opoff, unsigned char dtype)
{
	return insn_create_op_data(*(const ::insn_t*)(insn.ToPointer()), ea, opoff, dtype);
}

static void ida_insn_add_cref(IntPtr insn, ea_t to, int opoff, cref_t type)
{
	return insn_add_cref(*(const ::insn_t*)(insn.ToPointer()), to, opoff, type);
}

static void ida_insn_add_dref(IntPtr insn, ea_t to, int opoff, dref_t type)
{
	return insn_add_dref(*(const ::insn_t*)(insn.ToPointer()), to, opoff, type);
}

static unsigned long long ida_insn_add_off_drefs(IntPtr insn, IntPtr x, dref_t type, int outf)
{
	return insn_add_off_drefs(*(const ::insn_t*)(insn.ToPointer()),* (const ::op_t*)(x.ToPointer()), type, outf);
}

static bool ida_insn_create_stkvar(IntPtr insn, IntPtr x, long long v, int flags)
{
	return insn_create_stkvar(*(const ::insn_t*)(insn.ToPointer()), *(const ::op_t*)(x.ToPointer()), v, flags);
}

static unsigned long long ida_get_immvals(IntPtr out, unsigned long long ea, int n, unsigned int F, IntPtr cache)
{
	return get_immvals((::uval_t*)(out.ToPointer()), ea, n, F, (::insn_t*)(cache.ToPointer()));
}

static unsigned long long ida_get_printable_immvals(IntPtr out, ea_t ea, int n, flags_t F, IntPtr cache)
{
	F &= ~0x100; // no FF_IVL...
	F |= 0xFF;   // ...but a value of 0xFF
	return get_immvals((::uval_t*)(out.ToPointer()), ea, n, F, (::insn_t*)(cache.ToPointer()));
}

static int ida_get_lookback()
{
	return get_lookback();
}

static unsigned long long ida_calc_dataseg(IntPtr insn, int n, int rgnum)
{
	return calc_dataseg(*(const ::insn_t*)(insn.ToPointer()), n, rgnum);
}

static unsigned long long ida_map_data_ea(IntPtr insn, unsigned long long addr, int opnum)
{
	return to_ea(calc_dataseg(*(const ::insn_t*)(insn.ToPointer()), opnum), addr);
}

static unsigned long long ida_map_data_ea(IntPtr insn, IntPtr op) 
{
	return map_data_ea(*(const ::insn_t*)(insn.ToPointer()), (*(const ::op_t*)(op.ToPointer())).addr, (*(const ::op_t*)(op.ToPointer())).n);
}

static unsigned long long ida_map_code_ea(IntPtr insn, ea_t addr, int opnum)
{
	return map_code_ea(*(const ::insn_t*)(insn.ToPointer()), addr, opnum);
}

static unsigned long long ida_map_code_ea(IntPtr insn, IntPtr op)
{
	return map_code_ea(*(const ::insn_t*)(insn.ToPointer()), (*(const ::op_t*)(op.ToPointer())).addr, (*(const ::op_t*)(op.ToPointer())).n);
}

static unsigned long long ida_map_ea(IntPtr insn, IntPtr op, bool iscode)
{
  return iscode ? ida_map_code_ea(insn, op) : ida_map_data_ea(insn, op);
}

static unsigned long long ida_map_ea(IntPtr insn, ea_t addr, int opnum, bool iscode)
{
	return iscode ? ida_map_code_ea(insn, addr, opnum) : ida_map_data_ea(insn, addr, opnum);
}

static IntPtr ida_create_outctx(ea_t ea, unsigned int F, int suspop)
{
	return IntPtr((void*)create_outctx(ea, F, suspop));
}

static bool ida_print_insn_mnem(IntPtr out, ea_t ea)
{
	return print_insn_mnem((::qstring*)(out.ToPointer()), ea);
}

static bool ida_format_charlit(IntPtr out, IntPtr ptr, size_t size, unsigned int flags, int encidx)
{
	return format_charlit((::qstring*)(out.ToPointer()), (const unsigned char**)(ptr.ToPointer()), size, flags, encidx);
}

static bool ida_print_fpval(IntPtr buf, size_t bufsize, IntPtr v, int size)
{
	return print_fpval((char*)(buf.ToPointer()), bufsize, (const void*)(v.ToPointer()), size);
}

static flags_t ida_get_dtype_flag(op_dtype_t dtype)
{
	return get_dtype_flag(dtype);
}

static size_t ida_get_dtype_size(op_dtype_t dtype)
{
	return get_dtype_size(dtype);
}

static op_dtype_t ida_get_dtype_by_size(asize_t size)
{
	return get_dtype_by_size(size);
}

static bool ida_is_floating_dtype(op_dtype_t dtype)
{
	return dtype == dt_float
		|| dtype == dt_double
		|| dtype == dt_tbyte
		|| dtype == dt_ldbl
		|| dtype == dt_half;
}

static int ida_create_insn(ea_t ea, IntPtr out)
{
	return create_insn(ea, (insn_t *)out.ToPointer());
}

static int ida_decode_insn(IntPtr out, ea_t ea)
{
	return decode_insn((::insn_t*)(out.ToPointer()), ea);
}

static bool ida_can_decode(ea_t ea)
{
	insn_t insn; 
	return decode_insn(&insn, ea) > 0;
}

static bool ida_print_operand(IntPtr out, ea_t ea, int n, int getn_flags, IntPtr newtype)
{
	return print_operand((::qstring*)(out.ToPointer()), ea, n, getn_flags, (::printop_t*)(newtype.ToPointer()));
}

static ea_t ida_decode_prev_insn(IntPtr out, ea_t ea)
{
	return decode_prev_insn((::insn_t*)(out.ToPointer()), ea);
}

static ea_t ida_decode_preceding_insn(IntPtr out, ea_t ea, IntPtr p_farref)
{
	return decode_preceding_insn((::insn_t*)(out.ToPointer()), ea, (bool*)(p_farref.ToPointer()));
}

static bool ida_construct_macro2(IntPtr _this, IntPtr insn, bool enable)
{
	return construct_macro2((::macro_constructor_t*)(_this.ToPointer()), (::insn_t*)(insn.ToPointer()), enable);
}

static int ida_get_spoiled_reg(IntPtr insn, IntPtr regs, size_t n)
{
	return get_spoiled_reg(*(const ::insn_t*)(insn.ToPointer()), (const unsigned int*)(regs.ToPointer()), n);
}

#ifdef OBSOLETE_FUNCS
static bool ida_print_charlit(IntPtr buf, IntPtr ptr, int size)
{
	return print_charlit((char*)(buf.ToPointer()), (const void*)(ptr.ToPointer()), size);
}

static bool ida_construct_macro(IntPtr insn, bool enable, Func_bool___IntPtr_bool^ build_macro)
{
	return construct_macro(*(::insn_t*)(insn.ToPointer()), enable, static_cast<bool (__stdcall*)(::insn_t&, bool)>(::System::Runtime::InteropServices::Marshal::GetFunctionPointerForDelegate(build_macro).ToPointer()));
}
#endif
