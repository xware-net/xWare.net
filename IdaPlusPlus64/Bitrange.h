#pragma once

// complete

static bool ida_bitrange_t_extract_using_bitrange(IntPtr bm, IntPtr dst, size_t dst_size, IntPtr src, size_t src_size, bool is_mf)
{
	return bitrange_t_extract_using_bitrange((const bitrange_t*)(bm.ToPointer()), (void*)(dst.ToPointer()), dst_size, (const void*)(src.ToPointer()), src_size, is_mf);
}

static bool ida_bitrange_t_inject_using_bitrange(IntPtr bm, IntPtr dst, size_t dst_size, IntPtr src, size_t src_size, bool is_mf)
{
	return bitrange_t_inject_using_bitrange((const bitrange_t*)(bm.ToPointer()), (void*)(dst.ToPointer()), dst_size, (const void*)(src.ToPointer()), src_size, is_mf);
}

