#pragma once

[::System::Runtime::InteropServices::UnmanagedFunctionPointer(::System::Runtime::InteropServices::CallingConvention::Cdecl)]
delegate ::System::String^ Func___IntPtr___IntPtr_string8(::System::String^ buf, ::System::String^ line);

[::System::Runtime::InteropServices::UnmanagedFunctionPointer(::System::Runtime::InteropServices::CallingConvention::Cdecl)]
delegate int Func_int_string8___IntPtr(::System::String^ file, ::System::IntPtr ud);


static IntPtr ida_idadir(IntPtr subdir)
{
	return IntPtr((void*)idadir((const char*)(subdir.ToPointer())));
}

static IntPtr ida_getsysfile(IntPtr buf, size_t bufsize, IntPtr filename, IntPtr subdir)
{
	return IntPtr((void*)getsysfile((char*)(buf.ToPointer()), bufsize, (const char*)(filename.ToPointer()), (const char*)(subdir.ToPointer())));
}

static IntPtr ida_get_user_idadir()
{
	return IntPtr((void*)get_user_idadir());
}

static int ida_get_ida_subdirs(List<IntPtr>^ dirs, IntPtr subdir, int flags)
{
	qvector<qstring> out;
	auto ret = get_ida_subdirs(&out, (const char*)(subdir.ToPointer()), flags);
	auto list = ::ConvertQVectorToMyListOfIntPtr<qstring>(out);
	for (int i = 0; i < out.size(); ++i)
	{
		dirs->Add(IntPtr((void*)list[i]));
	}
	return ret;
}

static bool ida_get_special_folder(IntPtr buf, size_t bufsize, int csidl)
{
	return get_special_folder((char*)(buf.ToPointer()), bufsize, csidl);
}

// enumerate_files2
static int ida_enumerate_files2(IntPtr answer, size_t answer_size, IntPtr path, IntPtr fname, IntPtr fv)
{
	return enumerate_files2((char*)(answer.ToPointer()), answer_size, (const char*)(path.ToPointer()), (const char*)(fname.ToPointer()), *(file_enumerator_t*)(fv.ToPointer()));
}

static IntPtr ida_fopenWT(IntPtr file)
{
	return IntPtr((void*)fopenWT((const char*)(file.ToPointer())));
}

static IntPtr ida_fopenWB(IntPtr file)
{
	return IntPtr((void*)fopenWB((const char*)(file.ToPointer())));
}

static IntPtr ida_fopenRT(IntPtr file)
{
	return IntPtr((void*)fopenRT((const char*)(file.ToPointer())));
}

static IntPtr ida_fopenRB(IntPtr file)
{
	return IntPtr((void*)fopenRB((const char*)(file.ToPointer())));
}

static IntPtr ida_fopenM(IntPtr file)
{
	return IntPtr((void*)fopenM((const char*)(file.ToPointer())));
}

static IntPtr ida_fopenA(IntPtr file)
{
	return IntPtr((void*)fopenA((const char*)(file.ToPointer())));
}

static IntPtr ida_openR(IntPtr file)
{
	return IntPtr((void*)openR((const char*)(file.ToPointer())));
}

static IntPtr ida_openRT(IntPtr file)
{
	return IntPtr((void*)openRT((const char*)(file.ToPointer())));
}

static IntPtr ida_openM(IntPtr file)
{
	return IntPtr((void*)openM((const char*)(file.ToPointer())));
}

static void ida_echsize(IntPtr fp, uint64 size)
{
	echsize((FILE*)(fp.ToPointer()), size);
}

static uint64 ida_get_free_disk_space(IntPtr path)
{
	return get_free_disk_space((const char*)(path.ToPointer()));
}

//static ssize_t ida_read_ioports(IntPtr ports, IntPtr device, IntPtr file, IntPtr callback)
//{
//	return read_ioports((ioports_t*)(ports.ToPointer()), (qstring*)(device.ToPointer()), (const char*)(file.ToPointer()), ((const char**)(const ioports_t*, const char*)*)(callback.ToPointer()));
//}
//
//static ssize_t ida_read_ioports2(IntPtr ports, IntPtr device, IntPtr file, IntPtr callback)
//{
//	return read_ioports2((ioports_t*)(ports.ToPointer()), (qstring*)(device.ToPointer()), (const char*)(file.ToPointer()), (ioports_fallback_t*)(callback.ToPointer()));
//}
//
//static bool ida_choose_ioport_device(IntPtr _device, IntPtr file, Func___IntPtr___IntPtr_string8^ parse_params)
//{
//	return choose_ioport_device((qstring*)(_device.ToPointer()), (const char*)(file.ToPointer()), static_cast<const char* (*)(qstring*, const char*)>(::System::Runtime::InteropServices::Marshal::GetFunctionPointerForDelegate(parse_params).ToPointer()));
//}
//
//static bool ida_choose_ioport_device2(IntPtr _device, IntPtr file, IntPtr parse_params)
//{
//	return choose_ioport_device2((qstring*)(_device.ToPointer()), (const char*)(file.ToPointer()), (choose_ioport_parser_t*)(parse_params.ToPointer()));
//}

static IntPtr ida_find_ioport(IntPtr ports, ea_t address)
{
	return IntPtr((void*)find_ioport(*(ioports_t*)(ports.ToPointer()), address));
}

static IntPtr ida_find_ioport_bit(IntPtr ports, ea_t address, size_t bit)
{
	return IntPtr((void*)find_ioport_bit(*(ioports_t*)(ports.ToPointer()), address, bit));
}

static int ida_call_system(IntPtr command)
{
	return call_system((const char*)(command.ToPointer()));
}

static void ida_lread(IntPtr li, IntPtr buf, size_t size)
{
	lread((linput_t*)(li.ToPointer()), (void*)(buf.ToPointer()), size);
}

static ssize_t ida_qlread(IntPtr li, IntPtr buf, size_t size)
{
	return qlread((linput_t*)(li.ToPointer()), (void*)(buf.ToPointer()), size);
}

static IntPtr ida_qlgets(IntPtr s, size_t len, IntPtr li)
{
	return IntPtr((void*)qlgets((char*)(s.ToPointer()), len, (linput_t*)(li.ToPointer())));
}

static int ida_qlgetc(IntPtr li)
{
	return qlgetc((linput_t*)(li.ToPointer()));
}

static int ida_lreadbytes(IntPtr li, IntPtr buf, size_t size, bool mf)
{
	return lreadbytes((linput_t*)(li.ToPointer()), (void*)(buf.ToPointer()), size, mf);
}

static int ida_lread2bytes(IntPtr li, IntPtr res, bool mf)
{
	return lreadbytes((linput_t*)(li.ToPointer()), (short*)(res.ToPointer()), 2, mf);
}

static int ida_lread2bytesU(IntPtr li, IntPtr res, bool mf)
{
	return lreadbytes((linput_t*)(li.ToPointer()), (ushort*)(res.ToPointer()), 2, mf);
}

static int ida_lread4bytes(IntPtr li, IntPtr res, bool mf)
{
	return lreadbytes((linput_t*)(li.ToPointer()), (int*)(res.ToPointer()), 4, mf);
}

static int ida_lread4bytesU(IntPtr li, IntPtr res, bool mf)
{
	return lreadbytes((linput_t*)(li.ToPointer()), (uint*)(res.ToPointer()), 4, mf);
}

static int ida_lread8bytes(IntPtr li, IntPtr res, bool mf)
{
	return lreadbytes((linput_t*)(li.ToPointer()), (longlong*)(res.ToPointer()), 8, mf);
}

static int ida_lread8bytesU(IntPtr li, IntPtr res, bool mf)
{
	return lreadbytes((linput_t*)(li.ToPointer()), (ulonglong*)(res.ToPointer()), 8, mf);
}

static IntPtr ida_qlgetz(IntPtr li, int64 fpos, IntPtr buf, size_t bufsize)
{
	return IntPtr((void*)qlgetz((linput_t*)(li.ToPointer()), fpos, (char*)(buf.ToPointer()), bufsize));
}

static int64 ida_qlsize(IntPtr li)
{
	return qlsize((linput_t*)(li.ToPointer()));
}

static int64 ida_qlseek(IntPtr li, int64 pos, int whence)
{
	return qlseek((linput_t*)(li.ToPointer()), pos, whence);
}

static int64 ida_qltell(IntPtr li)
{
	return qlseek((linput_t*)(li.ToPointer()), 0, 1);
}

static IntPtr ida_open_linput(IntPtr file, bool remote)
{
	return IntPtr((void*)open_linput((const char*)(file.ToPointer()), remote));
}

static void ida_close_linput(IntPtr li)
{
	close_linput((linput_t*)(li.ToPointer()));
}

static IntPtr ida_qlfile(IntPtr li)
{
	return IntPtr((void*)qlfile((linput_t*)(li.ToPointer())));
}

static IntPtr ida_make_linput(IntPtr fp)
{
	return IntPtr((void*)make_linput((FILE*)(fp.ToPointer())));
}

static void ida_unmake_linput(IntPtr li)
{
	unmake_linput((linput_t*)(li.ToPointer()));
}

static IntPtr ida_create_generic_linput(IntPtr gl)
{
	return IntPtr((void*)create_generic_linput((generic_linput_t*)(gl.ToPointer())));
}

static IntPtr ida_create_bytearray_linput(IntPtr start, size_t size)
{
	return IntPtr((void*)create_bytearray_linput((const uchar*)(start.ToPointer()), size));
}

static IntPtr ida_create_memory_linput(ea_t start, asize_t size)
{
	return IntPtr((void*)create_memory_linput(start, size));
}

static linput_type_t ida_get_linput_type(IntPtr li)
{
	return li != IntPtr::Zero ? *(linput_type_t*)(li.ToPointer()) : LINPUT_NONE;
}

#ifdef OBSOLETE_FUNCS
static IntPtr ida_ecreate(IntPtr file)
{
	return IntPtr((void*)ecreate((const char*)(file.ToPointer())));
}

static void ida_eclose(IntPtr fp)
{
	eclose((FILE*)(fp.ToPointer()));
}

static void ida_eread(IntPtr fp, IntPtr buf, size_t size)
{
	eread((FILE*)(fp.ToPointer()), (void*)(buf.ToPointer()), size);
}

static void ida_ewrite(IntPtr fp, IntPtr buf, size_t size)
{
	ewrite((FILE*)(fp.ToPointer()), (const void*)(buf.ToPointer()), size);
}

static void ida_eseek(IntPtr fp, int64 pos)
{
	eseek((FILE*)(fp.ToPointer()), pos);
}

static int ida_enumerate_files(IntPtr answer, size_t answer_size, IntPtr path, IntPtr fname, Func_int_string8___IntPtr^ func, IntPtr ud)
{
	return enumerate_files((char*)(answer.ToPointer()), answer_size, (const char*)(path.ToPointer()), (const char*)(fname.ToPointer()), static_cast<int (*)(const char*, void*)>(::System::Runtime::InteropServices::Marshal::GetFunctionPointerForDelegate(func).ToPointer()), (void*)(ud.ToPointer()));
}
#endif
