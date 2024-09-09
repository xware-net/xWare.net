#pragma once

// complete

static bool ida_is_fixup_custom(fixup_type_t type)
{
	return (type & FIXUP_CUSTOM) != 0;
}

static bool ida_get_fixup(IntPtr fd, ea_t source)
{
	return get_fixup((fixup_data_t*)(fd.ToPointer()), source);
}

static bool ida_exists_fixup(ea_t source)
{
	return get_fixup(nullptr, source);
}

static void ida_set_fixup(unsigned long long source, IntPtr fd)
{
	return set_fixup(source, *(const fixup_data_t*)(fd.ToPointer()));
}

static void ida_del_fixup(ea_t source)
{
	return del_fixup(source);
}

static ea_t ida_get_first_fixup_ea()
{
	return get_first_fixup_ea();
}

static ea_t ida_get_next_fixup_ea(ea_t ea)
{
	return get_next_fixup_ea(ea);
}

static ea_t ida_get_prev_fixup_ea(ea_t ea)
{
	return get_prev_fixup_ea(ea);
}

static IntPtr ida_get_fixup_handler(fixup_type_t type)
{
	return IntPtr((void*)get_fixup_handler(type));
}

static bool ida_apply_fixup(ea_t item_ea, ea_t fixup_ea, int n, bool is_macro)
{
	return apply_fixup(item_ea, fixup_ea, n, is_macro);
}

static uval_t ida_get_fixup_value(ea_t ea, fixup_type_t type)
{
	return get_fixup_value(ea, type);
}

static bool ida_patch_fixup_value(ea_t ea, IntPtr fd)
{
	return patch_fixup_value(ea, *(const fixup_data_t*)(fd.ToPointer()));
}

static IntPtr ida_get_fixup_desc(IntPtr buf, ea_t source, IntPtr fd)
{
	qstring qstr;
	auto ret = get_fixup_desc(&qstr, source, *(const fixup_data_t*)(fd.ToPointer()));
	if (buf == IntPtr::Zero)
	{
		return IntPtr((void*)ret);
	}

	::ConvertQstringToIntPtr(qstr, buf, qstr.size());
	return IntPtr((void*)ret);
}

static int ida_calc_fixup_size(fixup_type_t type)
{
	return calc_fixup_size(type);
}

static unsigned short ida_register_custom_fixup(IntPtr cfh)
{
	return register_custom_fixup((const fixup_handler_t*)(cfh.ToPointer()));
}

static bool ida_unregister_custom_fixup(fixup_type_t type)
{
	return unregister_custom_fixup(type);
}

static unsigned short ida_find_custom_fixup(IntPtr name)
{
	return find_custom_fixup((const char*)(name.ToPointer()));
}

static bool ida_get_fixups(IntPtr out, ea_t ea, asize_t size)
{
	return get_fixups((fixups_t*)(out.ToPointer()), ea, size);
}

static bool ida_contains_fixups(ea_t ea, asize_t size)
{
	return get_fixups(nullptr, ea, size);
}

static void ida_gen_fix_fixups(ea_t from, ea_t to, asize_t size)
{
	return gen_fix_fixups(from, to, size);
}

static bool ida_handle_fixups_in_macro(IntPtr ri, ea_t ea, fixup_type_t other, unsigned int macro_reft_and_flags)
{
	return handle_fixups_in_macro((refinfo_t*)(ri.ToPointer()), ea, other, macro_reft_and_flags);
}
