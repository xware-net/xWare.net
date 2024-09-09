#pragma once

// complete

void ida_serialize_dynamic_register_set(IntPtr buf, IntPtr idaregs)
{
    serialize_dynamic_register_set((bytevec_t*)(buf.ToPointer()), *(dynamic_register_set_t*)(idaregs.ToPointer()));
}

void ida_deserialize_dynamic_register_set(IntPtr buf, IntPtr idaregs)
{
    deserialize_dynamic_register_set((dynamic_register_set_t*)(buf.ToPointer()), *(memory_deserializer_t*)(idaregs.ToPointer()));
}

void ida_serialize_insn(IntPtr buf, IntPtr idaregs)
{
    serialize_insn((bytevec_t*)(buf.ToPointer()), *(const insn_t*)(idaregs.ToPointer()));
}

void ida_deserialize_insn(IntPtr buf, IntPtr idaregs)
{
    deserialize_insn((insn_t*)(buf.ToPointer()), *(memory_deserializer_t*)(idaregs.ToPointer()));
}

static void ida_append_regval(IntPtr s, IntPtr value)
{
    bytevec_t& ss=*(bytevec_t*)(s.ToPointer());
    regval_t& vvalue=*(regval_t*)(value.ToPointer());

    ss.pack_dd(vvalue.rvtype + 2);
    if (vvalue.rvtype == RVT_INT) {
        ss.pack_dq(vvalue.ival + 1);
    } else if (vvalue.rvtype == RVT_FLOAT) {
        ss.append(&vvalue.fval, sizeof (vvalue.fval));
    } else if (vvalue.rvtype != RVT_UNAVAILABLE) {
        const bytevec_t &b = vvalue.bytes();
        ss.pack_dd(b.size());
        ss.append(b.begin(), b.size());
    }
}

template <class T>
static void ida_extract_regval(IntPtr out, IntPtr v)
{
    regval_t*oout = (regval_t*)(out.ToPointer());
    T& vv = (T&)(v.ToPointer());

    oout->clear();
    oout->rvtype = extract_dd(vv) - 2;
    if (oout->rvtype == RVT_INT) {
        oout->ival = extract_dq(vv) - 1;
    } else if (oout->rvtype == RVT_FLOAT) {
        extract_obj(vv, &oout->fval, sizeof (oout->fval));
    } else if (oout->rvtype != RVT_UNAVAILABLE) {
        bytevec_t &b = oout->_set_bytes();
        int size = extract_dd(vv);
        b.resize(size);
        extract_obj(vv, b.begin(), size);
    }
}

template <class T>
static void ida_extract_regvals(IntPtr values, int n, IntPtr v, IntPtr regmap)
{
    for (int i = 0; i < n && !(T&)(v.ToPointer()).eof(); i++)
        if ((const uchar*)(regmap.ToPointer()) == nullptr || test_bit((const uchar*)(regmap.ToPointer()), i))
            extract_regval(&(regval_t * )(values.ToPointer())[i], (T&)(v.ToPointer()));
}

template <class T>
static void ida_unpack_regvals(IntPtr values, int n, IntPtr regmap, IntPtr mmdsr)
{
    extract_regvals((regval_t*)(values.ToPointer()), n, (T&)(regmap.ToPointer()), (const uchar *)(mmdsr.ToPointer()));
}

static error_t ida_dbg_appcall(IntPtr retval, ea_t func_ea, thid_t tid, IntPtr ptif, IntPtr argv, size_t argnum)
{
	return dbg_appcall((idc_value_t*)(retval.ToPointer()), func_ea, tid, (const tinfo_t*)(ptif.ToPointer()), (idc_value_t*)(argv.ToPointer()), argnum);
}

static error_t ida_cleanup_appcall(thid_t tid)
{
	return cleanup_appcall(tid);
}

