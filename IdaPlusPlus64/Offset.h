#pragma once

// complete

static reftype_t ida_get_default_reftype(ea_t ea)
{
	return get_default_reftype(ea);
}

static bool ida_op_offset_ex(ea_t ea, int n, IntPtr ri)
{
	return op_offset_ex(ea, n, (const refinfo_t*)(ri.ToPointer()));
}

static bool ida_op_offset(ea_t ea, int n, uint32 type_and_flags, ea_t target, ea_t base, adiff_t tdelta)
{
	return op_offset(ea, n, type_and_flags, target, base, tdelta);
}

static bool ida_op_plain_offset(ea_t ea, int n, ea_t base)
{
	reftype_t reftype = get_default_reftype(ea);
	return op_offset(ea, n, reftype, BADADDR, base) != 0;
}

static unsigned long long ida_get_offbase(ea_t ea, int n)
{
	refinfo_t ri;
	if (!get_refinfo(&ri, ea, n))
		return BADADDR;
	return ri.base;
}

static int ida_get_offset_expression(IntPtr buf, ea_t ea, int n, ea_t from, adiff_t offset, int getn_flags)
{
	qstring buffer;
	int ret = get_offset_expression(&buffer, ea, n, from, offset, getn_flags);
	if (buf == IntPtr::Zero)
	{
		// if buf is IntPtrZero just return the required buffer size
		return buffer.size() - 1;
	}

	::ConvertQstringToIntPtr(buffer, buf, buffer.size() - 1);
	return ret;
}

static int ida_get_offset_expr(IntPtr buf, ea_t ea, int n, IntPtr ri, ea_t from, adiff_t offset, int getn_flags)
{
	qstring buffer;
	int ret = get_offset_expr(&buffer, ea, n, *(const refinfo_t*)(ri.ToPointer()), from, offset, getn_flags);
	if (buf == IntPtr::Zero)
	{
		// if buf is IntPtrZero just return the required buffer size
		return buffer.size() - 1;
	}

	::ConvertQstringToIntPtr(buffer, buf, buffer.size() - 1);
	return ret;
}

static ea_t ida_can_be_off32(ea_t ea)
{
	return can_be_off32(ea);
}

static ea_t ida_calc_offset_base(ea_t ea, int n)
{
	return calc_offset_base(ea, n);
}

static ea_t ida_calc_probable_base_by_value(ea_t ea, uval_t off)
{
	return calc_probable_base_by_value(ea, off);
}

static bool ida_calc_reference_data(IntPtr target, IntPtr base, ea_t from, IntPtr ri, long long opval)
{
	return calc_reference_data((ea_t*)(target.ToPointer()), (ea_t*)(base.ToPointer()), from, *(const refinfo_t*)(ri.ToPointer()), opval);
}

static ea_t ida_add_refinfo_dref(IntPtr insn, ea_t from, IntPtr ri, adiff_t opval, dref_t type, int opoff)
{
	return add_refinfo_dref(*(const insn_t*)(insn.ToPointer()), from, *(const refinfo_t*)(ri.ToPointer()), opval, type, opoff);
}

static ea_t ida_calc_target(ea_t from, adiff_t opval, IntPtr ri)
{
	ea_t target;
	if (!calc_reference_data(&target, nullptr, from, *(const refinfo_t*)(ri.ToPointer()), opval))
		return BADADDR;
	return target;
}

static ea_t ida_calc_target(ea_t from, ea_t ea, int n, adiff_t opval)
{
	refinfo_t ri;
	return get_refinfo(&ri, ea, n) ? calc_target(from, opval, ri) : BADADDR;
}

static ea_t ida_calc_basevalue(ea_t target, ea_t base)
{
	return base - get_segm_base(getseg(target));
}

