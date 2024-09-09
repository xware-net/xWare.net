#pragma once

// complete

static void ida_MD5Init(IntPtr context)
{
	return MD5Init((::MD5Context*)(context.ToPointer()));
}

static void ida_MD5Update(IntPtr context, IntPtr buf, size_t len)
{
	return MD5Update((::MD5Context*)(context.ToPointer()), (const void*)(buf.ToPointer()), len);
}

static void ida_MD5Final(cli::array<unsigned char>^ digest, IntPtr context)
{
	pin_ptr<unsigned char> digestPtr = &digest[0];
	return MD5Final((unsigned char*)(digestPtr), (::MD5Context*)(context.ToPointer()));
}

static void ida_MD5Transform(cli::array<unsigned int>^ buf, cli::array<unsigned int>^ in)
{
	pin_ptr<unsigned int> bufPtr = &buf[0];
	pin_ptr<unsigned int> inPtr = &in[0];
	return MD5Transform((unsigned int*)(bufPtr), (const unsigned int*)(inPtr));
}

