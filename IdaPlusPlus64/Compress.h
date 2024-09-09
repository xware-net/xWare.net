#pragma once

// complete

[::System::Runtime::InteropServices::UnmanagedFunctionPointer(::System::Runtime::InteropServices::CallingConvention::Cdecl)]
delegate long long Func_long___IntPtr___IntPtr_UInt64(::System::IntPtr ud, ::System::IntPtr buf, unsigned long long size);

[::System::Runtime::InteropServices::UnmanagedFunctionPointer(::System::Runtime::InteropServices::CallingConvention::Cdecl)]
delegate int Func_int___IntPtr_long_int_UInt64_UInt64_uint_string8(::System::IntPtr ud, long long offset, int method, unsigned long long csize, unsigned long long ucsize, unsigned int attributes, ::System::String^ filename);

static int ida_zip_deflate(
	IntPtr ud, 
	Func_long___IntPtr___IntPtr_UInt64^ file_reader, 
	Func_long___IntPtr___IntPtr_UInt64^ file_writer)
{
	return zip_deflate(
		(void* )(ud.ToPointer()), 
		static_cast<ssize_t(__stdcall*)(void*, void*, size_t)>(::System::Runtime::InteropServices::Marshal::GetFunctionPointerForDelegate(file_reader).ToPointer()), 
		static_cast<ssize_t(__stdcall*)(void*, const void*, size_t)>(::System::Runtime::InteropServices::Marshal::GetFunctionPointerForDelegate(file_writer).ToPointer())
	);
}

static int ida_zip_inflate(
	IntPtr ud, 
	Func_long___IntPtr___IntPtr_UInt64^ file_reader, 
	Func_long___IntPtr___IntPtr_UInt64^ file_writer)
{
	return zip_inflate(
		(void*)(ud.ToPointer()), 
		static_cast<ssize_t(__stdcall*)(void*, void*, size_t)>(::System::Runtime::InteropServices::Marshal::GetFunctionPointerForDelegate(file_reader).ToPointer()), 
		static_cast<ssize_t(__stdcall*)(void*, const void*, size_t)>(::System::Runtime::InteropServices::Marshal::GetFunctionPointerForDelegate(file_writer).ToPointer())
	);
}

static int ida_process_zipfile(
	IntPtr zipfile, 
	Func_int___IntPtr_long_int_UInt64_UInt64_uint_string8^ callback, 
	IntPtr ud)
{
	return process_zipfile(
		(const char*)(zipfile.ToPointer()),
		static_cast<int (__stdcall*)(void*, int64, int, uint64, uint64, uint32, const char*)>(::System::Runtime::InteropServices::Marshal::GetFunctionPointerForDelegate(callback).ToPointer()), 
		(void*)(ud.ToPointer())
	);
}

static int ida_process_zip_linput(
	IntPtr li, 
	Func_int___IntPtr_long_int_UInt64_UInt64_uint_string8^ callback,
	IntPtr ud)
{
	return process_zip_linput(
		(::linput_t*)(li.ToPointer()),
		static_cast<int(__stdcall*)(void*, int64, int, uint64, uint64, uint32, const char*)>(::System::Runtime::InteropServices::Marshal::GetFunctionPointerForDelegate(callback).ToPointer()),
		(void*)(ud.ToPointer())
	);
}

static int ida_process_zipfile_entry(
	IntPtr zipfile, 
	IntPtr entry, 
	Func_int___IntPtr_long_int_UInt64_UInt64_uint_string8^ callback,
	IntPtr ud,
	bool case_sensitive)
{
	return process_zipfile_entry(
		(const char*)(zipfile.ToPointer()),
		(const char*)(entry.ToPointer()),
		static_cast<int (__stdcall*)(void*, int64, int, uint64, uint64, uint32, const char*)>(::System::Runtime::InteropServices::Marshal::GetFunctionPointerForDelegate(callback).ToPointer()),
		(void*)(ud.ToPointer()), 
		case_sensitive);
}

static IntPtr ida_create_zip_linput(IntPtr in, ssize_t insize, linput_close_code_t loc)
{
	return (IntPtr)(
		create_zip_linput(
			(::linput_t*)(in.ToPointer()),
			insize, 
			loc
		));
}

