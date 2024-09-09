#pragma once

[::System::Runtime::InteropServices::UnmanagedFunctionPointer(::System::Runtime::InteropServices::CallingConvention::Cdecl)]
delegate void Action___IntPtr_UInt64_int_int_string8(::System::String^ buf, unsigned long long ea, int lnnum, int indent, ::System::String^ line);


static bool ida_requires_color_esc(char c)
{
	return c >= COLOR_ON && c <= COLOR_INV;
}

//static void ida_tag_addr(IntPtr buf, ea_t ea, bool ins)
//{
//	qstring qstr;
//
//	return tag_addr((qstring*)(buf.ToPointer()), ea, ins);
//}

static IntPtr ida_tag_advance(IntPtr line, int cnt)
{
	return IntPtr((void*)tag_advance((const char*)(line.ToPointer()), cnt));
}

static IntPtr ida_tag_skipcodes(IntPtr line)
{
	return IntPtr((void*)tag_skipcodes((const char*)(line.ToPointer())));
}

static IntPtr ida_tag_skipcode(IntPtr line)
{
	return IntPtr((void*)tag_skipcode((const char*)(line.ToPointer())));
}

static ssize_t ida_tag_strlen(IntPtr line)
{
	return tag_strlen((const char*)(line.ToPointer()));
}

//static long long ida_tag_remove(IntPtr buf, IntPtr str, int init_level)
//{
//	return tag_remove((qstring*)(buf.ToPointer()), (const char*)(str.ToPointer()), init_level);
//}

//static long long ida_tag_remove(IntPtr buf, IntPtr str, int init_level) // inline
//{
//}

//static long long ida_tag_remove(IntPtr buf, int init_level)
//{
//}

static color_t ida_calc_prefix_color(ea_t ea)
{
	return calc_prefix_color(ea);
}

static bgcolor_t ida_calc_bg_color(ea_t ea)
{
	return calc_bg_color(ea);
}

static bool ida_add_sourcefile(ea_t ea1, ea_t ea2, IntPtr filename)
{
	return add_sourcefile(ea1, ea2, (const char*)(filename.ToPointer()));
}

static IntPtr ida_get_sourcefile(ea_t ea, IntPtr bounds)
{
	return IntPtr((void*)get_sourcefile(ea, (range_t*)(bounds.ToPointer())));
}

static bool ida_del_sourcefile(ea_t ea)
{
	return del_sourcefile(ea);
}

static bool ida_install_user_defined_prefix(size_t prefix_len, IntPtr udp, IntPtr owner)
{
	return install_user_defined_prefix(prefix_len, (user_defined_prefix_t*)(udp.ToPointer()), (const void*)(owner.ToPointer()));
}

static bool ida_vadd_extra_line(ea_t ea, int vel_flags, IntPtr format)
{
	return vadd_extra_line(ea, vel_flags, (const char*)(format.ToPointer()), nullptr);
}

static bool ida_add_extra_line(ea_t ea, bool isPrev, IntPtr format)
{
	int vel_flags = (isPrev ? 0 : VEL_POST);
	return add_extra_line(ea, vel_flags, (char*)(format.ToPointer()));
}

static bool ida_add_extra_cmt(unsigned long long ea, bool isprev, IntPtr format)
{
	int vel_flags = (isprev ? 0 : VEL_POST) | VEL_CMT;
	return vadd_extra_line(ea, vel_flags, (char*)(format.ToPointer()), nullptr);
}

static bool ida_add_pgm_cmt(IntPtr format)
{
	return vadd_extra_line(inf_get_min_ea(), VEL_CMT, (char*)(format.ToPointer()), nullptr);
}

//static int ida_generate_disassembly(IntPtr out, IntPtr lnnum, unsigned long long ea, int maxsize, bool as_stack)
//{
//	return generate_disassembly((qvector<_qstring<char>>*)(out.ToPointer()), (int*)(lnnum.ToPointer()), ea, maxsize, as_stack);
//}

//static bool ida_generate_disasm_line(IntPtr buf, unsigned long long ea, int flags)
//{
//	return generate_disasm_line((_qstring<char>*)(buf.ToPointer()), ea, flags);
//}

static int ida_get_last_pfxlen()
{
	return get_last_pfxlen();
}

static IntPtr ida_closing_comment()
{
	return IntPtr((void*)closing_comment());
}

static int ida_get_first_free_extra_cmtidx(ea_t ea, int start)
{
	return get_first_free_extra_cmtidx(ea, start);
}

static void ida_update_extra_cmt(ea_t ea, int what, IntPtr str)
{
	return update_extra_cmt(ea, what, (const char*)(str.ToPointer()));
}

static void ida_del_extra_cmt(ea_t ea, int what)
{
	return del_extra_cmt(ea, what);
}

//static long long ida_get_extra_cmt(IntPtr buf, ea_t ea, int what)
//{
//	return get_extra_cmt((qstring*)(buf.ToPointer()), ea, what);
//}

static void ida_delete_extra_cmts(ea_t ea, int what)
{
	return delete_extra_cmts(ea, what);
}

static ea_t ida_align_down_to_stack(ea_t newea)
{
	return align_down_to_stack(newea);
}

static ea_t ida_align_up_to_stack(ea_t ea1, ea_t ea2)
{
	return align_up_to_stack(ea1, ea2);
}

static IntPtr ida_create_encoding_helper(int encidx, encoder_t::notify_recerr_t nr)
{
	return IntPtr((void*)create_encoding_helper(encidx, nr));
}

#ifdef OBSOLETE_FUNCS
static void ida_set_user_defined_prefix(unsigned long long width, Action___IntPtr_UInt64_int_int_string8^ get_user_defined_prefix)
{
	set_user_defined_prefix(width, static_cast<void (*)(qstring*, ea_t, int, int, const char*)>(::System::Runtime::InteropServices::Marshal::GetFunctionPointerForDelegate(get_user_defined_prefix).ToPointer()));
}
#endif

