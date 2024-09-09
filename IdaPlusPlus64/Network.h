#pragma once

// complete

static bool ida_parse_timestamp(IntPtr out, IntPtr in, uint32 flags)
{
	return parse_timestamp((utc_timestamp_t*)(out.ToPointer()), (const char*)(in.ToPointer()), flags);
}

static bool ida_format_timestamp(IntPtr out, size_t out_size, utc_timestamp_t ts, uint32 flags)
{
	return format_timestamp((char*)(out.ToPointer()), out_size, ts, flags);
}

static lofi_timestamp_t ida_to_lofi_timestamp(qtime64_t ts) 
{
	const uint64 s = get_secs(ts);
	const uint64 us = get_usecs(ts);
	return s * 10 + us / (100 * 1000);
}

static qtime64_t ida_from_lofi_timestamp(lofi_timestamp_t lts)
{
	return make_qtime64(lts / 10, (lts % 10) * (100 * 1000));
}

