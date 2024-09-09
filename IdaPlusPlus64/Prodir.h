#pragma once

// complete

static int ida_qfindfirst(IntPtr pattern, IntPtr blk, int attr)
{
	return qfindfirst((const char*)(pattern.ToPointer()), (::qffblk64_t*)(blk.ToPointer()), attr);
}

static int ida_qfindnext(IntPtr blk)
{
	return qfindnext((::qffblk64_t*)(blk.ToPointer()));
}

static void ida_qfindclose(IntPtr blk)
{
	return qfindclose((::qffblk64_t*)(blk.ToPointer()));
}

