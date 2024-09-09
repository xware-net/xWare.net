#pragma once

// complete

static unsigned long long ida_mmdsr_unpack_ea(IntPtr mmdsrPtr, ea_t base)
{
	auto mmdsr = *(memory_deserializer_t*)mmdsrPtr.ToPointer();
	if (is_cvt64()) {
		ea_t ea = ea32_t(mmdsr.unpack_dd() + base);
		return ea == ea32_t(-1ULL) ? ea_t(-1) : ea;
	}
	return mmdsr.unpack_ea() + base;
}

static unsigned long long ida_mmdsr_unpack_ea_neg(IntPtr mmdsrPtr, ea_t base)
{
	auto mmdsr = *(memory_deserializer_t*)mmdsrPtr.ToPointer();
	if (is_cvt64()) {
		ea_t ea = ea32_t(base - mmdsr.unpack_dd());
		return ea == ea32_t(-1ULL) ? ea_t(-1) : ea;
	}
	return base - mmdsr.unpack_ea();
}

static unsigned long long ida_mmdsr_unpack_node2ea(IntPtr mmdsrPtr)
{
	auto mmdsr = *(memory_deserializer_t*)mmdsrPtr.ToPointer();
	nodeidx_t ndx = mmdsr_unpack_ea(mmdsr);
	return node2ea(ndx);
}

static long long ida_mmdsr_unpack_sval(IntPtr mmdsrPtr, sval_t base)
{
	auto mmdsr = *(memory_deserializer_t*)mmdsrPtr.ToPointer();
	if (is_cvt64())
		return (int32)(mmdsr.unpack_dd() + base);
	return mmdsr.unpack_ea() + base;
}

static void ida_mmdsr_unpack_eavec(IntPtr vecPtr, IntPtr mmdsrPtr, ea_t ea)
{
	auto mmdsr = *(memory_deserializer_t*)mmdsrPtr.ToPointer();
	auto vec = (qvector<ea_t>*)vecPtr.ToPointer();
	if (is_cvt64())
	{
		ea_t old = ea;
		int n = mmdsr.unpack_dw();
		vec->resize_noinit(n);
		for (int i = 0; i < n; ++i) 
		{
			old = mmdsr_unpack_ea(mmdsr, old);
			vec->at(i) = old;
		}
		return;
	}
	return mmdsr.unpack_eavec(vec, ea);
}

static unsigned long long ida_mmdsr_read_ea(IntPtr mmdsrPtr)
{
	auto mmdsr = *(memory_deserializer_t*)mmdsrPtr.ToPointer();
	if (is_cvt64())
	{
		ea32_t ea32 = ea32_t(-1ULL);
		mmdsr.read(&ea32, sizeof(ea32));
		return ea32;
	}
	ea_t ea = ea_t(-1);
	mmdsr.read(&ea, sizeof(ea));
	return ea;
}

static int ida_cvt64_blob(netnode node, nodeidx_t start, uchar tag)
{
	bytevec_t buf;
	if (node.getblob(&buf, start, tag) > 0)
	{
		node.setblob(buf.begin(), buf.size(), start, tag);
		return 1;
	}
	return 0;
}

/*
static int ida_cvt64_node_supval_for_event(va_list va, IntPtr node_info, size_t node_info_qty)
{
	// does not exists in freeware version 8.3, 8.4
	return cvt64_node_supval_for_event(va, (const cvt64_node_tag_t*)(node_info.ToPointer()), node_info_qty);
}
*/
