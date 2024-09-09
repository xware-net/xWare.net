#pragma once

static int ida_init_database(int argc, IntPtr argv, IntPtr newfile)
{
	return init_database(argc, (const char* const*)(argv.ToPointer()), (int*)(newfile.ToPointer()));
}

static void ida_term_database()
{
	return term_database();
}

static void ida_verror(IntPtr format, char* va)
{
	return verror((const char*)(format.ToPointer()), va);
}

static void ida_vshow_hex(IntPtr dataptr, unsigned long long len, IntPtr format, char* va)
{
	return vshow_hex((const void*)(dataptr.ToPointer()), len, (const char*)(format.ToPointer()), va);
}

static void ida_vshow_hex_file(IntPtr li, long long pos, unsigned long long count, IntPtr format, char* va)
{
	return vshow_hex_file((::linput_t*)(li.ToPointer()), pos, count, (const char*)(format.ToPointer()), va);
}

//static long long ida_get_kernel_version(IntPtr buf, unsigned long long bufsize) // inline
//{
//	...
//}

static int ida_l_compare(IntPtr t1, IntPtr t2)
{
	return l_compare((const ::place_t*)(t1.ToPointer()), (const ::place_t*)(t2.ToPointer()));
}

static int ida_l_compare2(IntPtr t1, IntPtr t2, IntPtr ud)
{
	return l_compare2((const ::place_t*)(t1.ToPointer()), (const ::place_t*)(t2.ToPointer()), (void*)(ud.ToPointer()));
}

static void ida_simpleline_place_t__print(IntPtr p_0, IntPtr p_1, IntPtr p_2)
{
	return simpleline_place_t__print((const ::simpleline_place_t*)(p_0.ToPointer()), (::_qstring<char>*)(p_1.ToPointer()), (void*)(p_2.ToPointer()));
}

static unsigned long long ida_simpleline_place_t__touval(IntPtr p_0, IntPtr p_1)
{
	return simpleline_place_t__touval((const ::simpleline_place_t*)(p_0.ToPointer()), (void*)(p_1.ToPointer()));
}

static IntPtr ida_simpleline_place_t__clone(IntPtr p_0)
{
	return IntPtr((void*)simpleline_place_t__clone((const ::simpleline_place_t*)(p_0.ToPointer())));
}

static void ida_simpleline_place_t__copyfrom(IntPtr p_0, IntPtr p_1)
{
	return simpleline_place_t__copyfrom((::simpleline_place_t*)(p_0.ToPointer()), (const ::place_t*)(p_1.ToPointer()));
}

static IntPtr ida_simpleline_place_t__makeplace(IntPtr p_0, IntPtr p_1, unsigned long long p_2, int p_3)
{
	return IntPtr((void*)simpleline_place_t__makeplace((const ::simpleline_place_t*)(p_0.ToPointer()), (void*)(p_1.ToPointer()), p_2, p_3));
}

static int ida_simpleline_place_t__compare(IntPtr p_0, IntPtr p_1)
{
	return simpleline_place_t__compare((const ::simpleline_place_t*)(p_0.ToPointer()), (const ::place_t*)(p_1.ToPointer()));
}

static int ida_simpleline_place_t__compare2(IntPtr p_0, IntPtr p_1, IntPtr p_2)
{
	return simpleline_place_t__compare2((const ::simpleline_place_t*)(p_0.ToPointer()), (const ::place_t*)(p_1.ToPointer()), (void*)(p_2.ToPointer()));
}

static void ida_simpleline_place_t__adjust(IntPtr p_0, IntPtr p_1)
{
	return simpleline_place_t__adjust((::simpleline_place_t*)(p_0.ToPointer()), (void*)(p_1.ToPointer()));
}

static bool ida_simpleline_place_t__prev(IntPtr p_0, IntPtr p_1)
{
	return simpleline_place_t__prev((::simpleline_place_t*)(p_0.ToPointer()), (void*)(p_1.ToPointer()));
}

static bool ida_simpleline_place_t__next(IntPtr p_0, IntPtr p_1)
{
	return simpleline_place_t__next((::simpleline_place_t*)(p_0.ToPointer()), (void*)(p_1.ToPointer()));
}

static bool ida_simpleline_place_t__beginning(IntPtr p_0, IntPtr p_1)
{
	return simpleline_place_t__beginning((const ::simpleline_place_t*)(p_0.ToPointer()), (void*)(p_1.ToPointer()));
}

static bool ida_simpleline_place_t__ending(IntPtr p_0, IntPtr p_1)
{
	return simpleline_place_t__ending((const ::simpleline_place_t*)(p_0.ToPointer()), (void*)(p_1.ToPointer()));
}

static int ida_simpleline_place_t__generate(IntPtr p_0, IntPtr p_1, IntPtr p_2, IntPtr p_3, IntPtr p_4, IntPtr p_5, int p_6)
{
	return simpleline_place_t__generate((const ::simpleline_place_t*)(p_0.ToPointer()), (::qvector<::_qstring<char>>*)(p_1.ToPointer()), (int*)(p_2.ToPointer()), (unsigned char*)(p_3.ToPointer()), (unsigned int*)(p_4.ToPointer()), (void*)(p_5.ToPointer()), p_6);
}

static void ida_simpleline_place_t__serialize(IntPtr p_0, IntPtr out)
{
	return simpleline_place_t__serialize((const ::simpleline_place_t*)(p_0.ToPointer()), (::bytevec_t*)(out.ToPointer()));
}

static bool ida_simpleline_place_t__deserialize(IntPtr p_0, IntPtr p_1, IntPtr p_2)
{
	return simpleline_place_t__deserialize((::simpleline_place_t*)(p_0.ToPointer()), (const unsigned char**)(p_1.ToPointer()), (const unsigned char*)(p_2.ToPointer()));
}

static int ida_simpleline_place_t__id(IntPtr p_0)
{
	return simpleline_place_t__id((const ::simpleline_place_t*)(p_0.ToPointer()));
}

static IntPtr ida_simpleline_place_t__name(IntPtr p_0)
{
	return IntPtr((void*)simpleline_place_t__name((const ::simpleline_place_t*)(p_0.ToPointer())));
}

static unsigned long long ida_simpleline_place_t__toea(IntPtr p_0)
{
	return simpleline_place_t__toea((const ::simpleline_place_t*)(p_0.ToPointer()));
}

static IntPtr ida_simpleline_place_t__enter(IntPtr p_0, IntPtr p_1)
{
	return IntPtr((void*)simpleline_place_t__enter((const ::simpleline_place_t*)(p_0.ToPointer()), (unsigned int*)(p_1.ToPointer())));
}

static void ida_simpleline_place_t__leave(IntPtr p_0, unsigned int p_1)
{
	return simpleline_place_t__leave((const ::simpleline_place_t*)(p_0.ToPointer()), p_1);
}

//static bool ida_simpleline_place_t__rebase(IntPtr p_0, IntPtr p_1)
//{
//	return simpleline_place_t__rebase((::simpleline_place_t*)(p_0.ToPointer()), (const ::segm_move_infos_t&)(p_1.ToPointer()));
//}

static void ida_idaplace_t__print(IntPtr p_0, IntPtr p_1, IntPtr p_2)
{
	return idaplace_t__print((const ::idaplace_t*)(p_0.ToPointer()), (::_qstring<char>*)(p_1.ToPointer()), (void*)(p_2.ToPointer()));
}

static unsigned long long ida_idaplace_t__touval(IntPtr p_0, IntPtr p_1)
{
	return idaplace_t__touval((const ::idaplace_t*)(p_0.ToPointer()), (void*)(p_1.ToPointer()));
}

static IntPtr ida_idaplace_t__clone(IntPtr p_0)
{
	return IntPtr((void*)idaplace_t__clone((const ::idaplace_t*)(p_0.ToPointer())));
}

static void ida_idaplace_t__copyfrom(IntPtr p_0, IntPtr p_1)
{
	return idaplace_t__copyfrom((::idaplace_t*)(p_0.ToPointer()), (const ::place_t*)(p_1.ToPointer()));
}

static IntPtr ida_idaplace_t__makeplace(IntPtr p_0, IntPtr p_1, unsigned long long p_2, int p_3)
{
	return IntPtr((void*)idaplace_t__makeplace((const ::idaplace_t*)(p_0.ToPointer()), (void*)(p_1.ToPointer()), p_2, p_3));
}

static int ida_idaplace_t__compare(IntPtr p_0, IntPtr p_1)
{
	return idaplace_t__compare((const ::idaplace_t*)(p_0.ToPointer()), (const ::place_t*)(p_1.ToPointer()));
}

static int ida_idaplace_t__compare2(IntPtr p_0, IntPtr p_1, IntPtr p_2)
{
	return idaplace_t__compare2((const ::idaplace_t*)(p_0.ToPointer()), (const ::place_t*)(p_1.ToPointer()), (void*)(p_2.ToPointer()));
}

static void ida_idaplace_t__adjust(IntPtr p_0, IntPtr p_1)
{
	return idaplace_t__adjust((::idaplace_t*)(p_0.ToPointer()), (void*)(p_1.ToPointer()));
}

static bool ida_idaplace_t__prev(IntPtr p_0, IntPtr p_1)
{
	return idaplace_t__prev((::idaplace_t*)(p_0.ToPointer()), (void*)(p_1.ToPointer()));
}

static bool ida_idaplace_t__next(IntPtr p_0, IntPtr p_1)
{
	return idaplace_t__next((::idaplace_t*)(p_0.ToPointer()), (void*)(p_1.ToPointer()));
}

static bool ida_idaplace_t__beginning(IntPtr p_0, IntPtr p_1)
{
	return idaplace_t__beginning((const ::idaplace_t*)(p_0.ToPointer()), (void*)(p_1.ToPointer()));
}

static bool ida_idaplace_t__ending(IntPtr p_0, IntPtr p_1)
{
	return idaplace_t__ending((const ::idaplace_t*)(p_0.ToPointer()), (void*)(p_1.ToPointer()));
}

static int ida_idaplace_t__generate(IntPtr p_0, IntPtr p_1, IntPtr p_2, IntPtr p_3, IntPtr p_4, IntPtr p_5, int p_6)
{
	return idaplace_t__generate((const ::idaplace_t*)(p_0.ToPointer()), (::qvector<::_qstring<char>>*)(p_1.ToPointer()), (int*)(p_2.ToPointer()), (unsigned char*)(p_3.ToPointer()), (unsigned int*)(p_4.ToPointer()), (void*)(p_5.ToPointer()), p_6);
}

static void ida_idaplace_t__serialize(IntPtr p_0, IntPtr out)
{
	return idaplace_t__serialize((const ::idaplace_t*)(p_0.ToPointer()), (::bytevec_t*)(out.ToPointer()));
}

static bool ida_idaplace_t__deserialize(IntPtr p_0, IntPtr p_1, IntPtr p_2)
{
	return idaplace_t__deserialize((::idaplace_t*)(p_0.ToPointer()), (const unsigned char**)(p_1.ToPointer()), (const unsigned char*)(p_2.ToPointer()));
}

static int ida_idaplace_t__id(IntPtr p_0)
{
	return idaplace_t__id((const ::idaplace_t*)(p_0.ToPointer()));
}

static IntPtr ida_idaplace_t__name(IntPtr p_0)
{
	return IntPtr((void*)idaplace_t__name((const ::idaplace_t*)(p_0.ToPointer())));
}

static unsigned long long ida_idaplace_t__toea(IntPtr p_0)
{
	return idaplace_t__toea((const ::idaplace_t*)(p_0.ToPointer()));
}

static IntPtr ida_idaplace_t__enter(IntPtr p_0, IntPtr p_1)
{
	return IntPtr((void*)idaplace_t__enter((const ::idaplace_t*)(p_0.ToPointer()), (unsigned int*)(p_1.ToPointer())));
}

static void ida_idaplace_t__leave(IntPtr p_0, unsigned int p_1)
{
	return idaplace_t__leave((const ::idaplace_t*)(p_0.ToPointer()), p_1);
}

//static bool ida_idaplace_t__rebase(IntPtr p_0, IntPtr p_1)
//{
//	return idaplace_t__rebase((::idaplace_t*)(p_0.ToPointer()), (const ::segm_move_infos_t&)(p_1.ToPointer()));
//}

static void ida_enumplace_t__print(IntPtr p_0, IntPtr p_1, IntPtr p_2)
{
	return enumplace_t__print((const ::enumplace_t*)(p_0.ToPointer()), (::_qstring<char>*)(p_1.ToPointer()), (void*)(p_2.ToPointer()));
}

static unsigned long long ida_enumplace_t__touval(IntPtr p_0, IntPtr p_1)
{
	return enumplace_t__touval((const ::enumplace_t*)(p_0.ToPointer()), (void*)(p_1.ToPointer()));
}

static IntPtr ida_enumplace_t__clone(IntPtr p_0)
{
	return IntPtr((void*)enumplace_t__clone((const ::enumplace_t*)(p_0.ToPointer())));
}

static void ida_enumplace_t__copyfrom(IntPtr p_0, IntPtr p_1)
{
	return enumplace_t__copyfrom((::enumplace_t*)(p_0.ToPointer()), (const ::place_t*)(p_1.ToPointer()));
}

static IntPtr ida_enumplace_t__makeplace(IntPtr p_0, IntPtr p_1, unsigned long long p_2, int p_3)
{
	return IntPtr((void*)enumplace_t__makeplace((const ::enumplace_t*)(p_0.ToPointer()), (void*)(p_1.ToPointer()), p_2, p_3));
}

static int ida_enumplace_t__compare(IntPtr p_0, IntPtr p_1)
{
	return enumplace_t__compare((const ::enumplace_t*)(p_0.ToPointer()), (const ::place_t*)(p_1.ToPointer()));
}

static int ida_enumplace_t__compare2(IntPtr p_0, IntPtr p_1, IntPtr p_2)
{
	return enumplace_t__compare2((const ::enumplace_t*)(p_0.ToPointer()), (const ::place_t*)(p_1.ToPointer()), (void*)(p_2.ToPointer()));
}

static void ida_enumplace_t__adjust(IntPtr p_0, IntPtr p_1)
{
	return enumplace_t__adjust((::enumplace_t*)(p_0.ToPointer()), (void*)(p_1.ToPointer()));
}

static bool ida_enumplace_t__prev(IntPtr p_0, IntPtr p_1)
{
	return enumplace_t__prev((::enumplace_t*)(p_0.ToPointer()), (void*)(p_1.ToPointer()));
}

static bool ida_enumplace_t__next(IntPtr p_0, IntPtr p_1)
{
	return enumplace_t__next((::enumplace_t*)(p_0.ToPointer()), (void*)(p_1.ToPointer()));
}

static bool ida_enumplace_t__beginning(IntPtr p_0, IntPtr p_1)
{
	return enumplace_t__beginning((const ::enumplace_t*)(p_0.ToPointer()), (void*)(p_1.ToPointer()));
}

static bool ida_enumplace_t__ending(IntPtr p_0, IntPtr p_1)
{
	return enumplace_t__ending((const ::enumplace_t*)(p_0.ToPointer()), (void*)(p_1.ToPointer()));
}

static int ida_enumplace_t__generate(IntPtr p_0, IntPtr p_1, IntPtr p_2, IntPtr p_3, IntPtr p_4, IntPtr p_5, int p_6)
{
	return enumplace_t__generate((const ::enumplace_t*)(p_0.ToPointer()), (::qvector<::_qstring<char>>*)(p_1.ToPointer()), (int*)(p_2.ToPointer()), (unsigned char*)(p_3.ToPointer()), (unsigned int*)(p_4.ToPointer()), (void*)(p_5.ToPointer()), p_6);
}

static void ida_enumplace_t__serialize(IntPtr p_0, IntPtr out)
{
	return enumplace_t__serialize((const ::enumplace_t*)(p_0.ToPointer()), (::bytevec_t*)(out.ToPointer()));
}

static bool ida_enumplace_t__deserialize(IntPtr p_0, IntPtr p_1, IntPtr p_2)
{
	return enumplace_t__deserialize((::enumplace_t*)(p_0.ToPointer()), (const unsigned char**)(p_1.ToPointer()), (const unsigned char*)(p_2.ToPointer()));
}

static int ida_enumplace_t__id(IntPtr p_0)
{
	return enumplace_t__id((const ::enumplace_t*)(p_0.ToPointer()));
}

static IntPtr ida_enumplace_t__name(IntPtr p_0)
{
	return IntPtr((void*)enumplace_t__name((const ::enumplace_t*)(p_0.ToPointer())));
}

static unsigned long long ida_enumplace_t__toea(IntPtr p_0)
{
	return enumplace_t__toea((const ::enumplace_t*)(p_0.ToPointer()));
}

static IntPtr ida_enumplace_t__enter(IntPtr p_0, IntPtr p_1)
{
	return IntPtr((void*)enumplace_t__enter((const ::enumplace_t*)(p_0.ToPointer()), (unsigned int*)(p_1.ToPointer())));
}

static void ida_enumplace_t__leave(IntPtr p_0, unsigned int p_1)
{
	return enumplace_t__leave((const ::enumplace_t*)(p_0.ToPointer()), p_1);
}

//static bool ida_enumplace_t__rebase(IntPtr p_0, IntPtr p_1)
//{
//	return enumplace_t__rebase((::enumplace_t*)(p_0.ToPointer()), (const ::segm_move_infos_t&)(p_1.ToPointer()));
//}

static void ida_structplace_t__print(IntPtr p_0, IntPtr p_1, IntPtr p_2)
{
	return structplace_t__print((const ::structplace_t*)(p_0.ToPointer()), (::_qstring<char>*)(p_1.ToPointer()), (void*)(p_2.ToPointer()));
}

static unsigned long long ida_structplace_t__touval(IntPtr p_0, IntPtr p_1)
{
	return structplace_t__touval((const ::structplace_t*)(p_0.ToPointer()), (void*)(p_1.ToPointer()));
}

static IntPtr ida_structplace_t__clone(IntPtr p_0)
{
	return IntPtr((void*)structplace_t__clone((const ::structplace_t*)(p_0.ToPointer())));
}

static void ida_structplace_t__copyfrom(IntPtr p_0, IntPtr p_1)
{
	return structplace_t__copyfrom((::structplace_t*)(p_0.ToPointer()), (const ::place_t*)(p_1.ToPointer()));
}

static IntPtr ida_structplace_t__makeplace(IntPtr p_0, IntPtr p_1, unsigned long long p_2, int p_3)
{
	return IntPtr((void*)structplace_t__makeplace((const ::structplace_t*)(p_0.ToPointer()), (void*)(p_1.ToPointer()), p_2, p_3));
}

static int ida_structplace_t__compare(IntPtr p_0, IntPtr p_1)
{
	return structplace_t__compare((const ::structplace_t*)(p_0.ToPointer()), (const ::place_t*)(p_1.ToPointer()));
}

static int ida_structplace_t__compare2(IntPtr p_0, IntPtr p_1, IntPtr p_2)
{
	return structplace_t__compare2((const ::structplace_t*)(p_0.ToPointer()), (const ::place_t*)(p_1.ToPointer()), (void*)(p_2.ToPointer()));
}

static void ida_structplace_t__adjust(IntPtr p_0, IntPtr p_1)
{
	return structplace_t__adjust((::structplace_t*)(p_0.ToPointer()), (void*)(p_1.ToPointer()));
}

static bool ida_structplace_t__prev(IntPtr p_0, IntPtr p_1)
{
	return structplace_t__prev((::structplace_t*)(p_0.ToPointer()), (void*)(p_1.ToPointer()));
}

static bool ida_structplace_t__next(IntPtr p_0, IntPtr p_1)
{
	return structplace_t__next((::structplace_t*)(p_0.ToPointer()), (void*)(p_1.ToPointer()));
}

static bool ida_structplace_t__beginning(IntPtr p_0, IntPtr p_1)
{
	return structplace_t__beginning((const ::structplace_t*)(p_0.ToPointer()), (void*)(p_1.ToPointer()));
}

static bool ida_structplace_t__ending(IntPtr p_0, IntPtr p_1)
{
	return structplace_t__ending((const ::structplace_t*)(p_0.ToPointer()), (void*)(p_1.ToPointer()));
}

static int ida_structplace_t__generate(IntPtr p_0, IntPtr p_1, IntPtr p_2, IntPtr p_3, IntPtr p_4, IntPtr p_5, int p_6)
{
	return structplace_t__generate((const ::structplace_t*)(p_0.ToPointer()), (::qvector<::_qstring<char>>*)(p_1.ToPointer()), (int*)(p_2.ToPointer()), (unsigned char*)(p_3.ToPointer()), (unsigned int*)(p_4.ToPointer()), (void*)(p_5.ToPointer()), p_6);
}

static void ida_structplace_t__serialize(IntPtr p_0, IntPtr out)
{
	return structplace_t__serialize((const ::structplace_t*)(p_0.ToPointer()), (::bytevec_t*)(out.ToPointer()));
}

static bool ida_structplace_t__deserialize(IntPtr p_0, IntPtr p_1, IntPtr p_2)
{
	return structplace_t__deserialize((::structplace_t*)(p_0.ToPointer()), (const unsigned char**)(p_1.ToPointer()), (const unsigned char*)(p_2.ToPointer()));
}

static int ida_structplace_t__id(IntPtr p_0)
{
	return structplace_t__id((const ::structplace_t*)(p_0.ToPointer()));
}

static IntPtr ida_structplace_t__name(IntPtr p_0)
{
	return IntPtr((void*)structplace_t__name((const ::structplace_t*)(p_0.ToPointer())));
}

static unsigned long long ida_structplace_t__toea(IntPtr p_0)
{
	return structplace_t__toea((const ::structplace_t*)(p_0.ToPointer()));
}

static IntPtr ida_structplace_t__enter(IntPtr p_0, IntPtr p_1)
{
	return IntPtr((void*)structplace_t__enter((const ::structplace_t*)(p_0.ToPointer()), (unsigned int*)(p_1.ToPointer())));
}

static void ida_structplace_t__leave(IntPtr p_0, unsigned int p_1)
{
	return structplace_t__leave((const ::structplace_t*)(p_0.ToPointer()), p_1);
}

//static bool ida_structplace_t__rebase(IntPtr p_0, IntPtr p_1)
//{
//	return structplace_t__rebase((::structplace_t*)(p_0.ToPointer()), (const ::segm_move_infos_t&)(p_1.ToPointer()));
//}

static void ida_hexplace_t__print(IntPtr p_0, IntPtr p_1, IntPtr p_2)
{
	return hexplace_t__print((const ::hexplace_t*)(p_0.ToPointer()), (::_qstring<char>*)(p_1.ToPointer()), (void*)(p_2.ToPointer()));
}

static unsigned long long ida_hexplace_t__touval(IntPtr p_0, IntPtr p_1)
{
	return hexplace_t__touval((const ::hexplace_t*)(p_0.ToPointer()), (void*)(p_1.ToPointer()));
}

static IntPtr ida_hexplace_t__clone(IntPtr p_0)
{
	return IntPtr((void*)hexplace_t__clone((const ::hexplace_t*)(p_0.ToPointer())));
}

static void ida_hexplace_t__copyfrom(IntPtr p_0, IntPtr p_1)
{
	return hexplace_t__copyfrom((::hexplace_t*)(p_0.ToPointer()), (const ::place_t*)(p_1.ToPointer()));
}

static IntPtr ida_hexplace_t__makeplace(IntPtr p_0, IntPtr p_1, unsigned long long p_2, int p_3)
{
	return IntPtr((void*)hexplace_t__makeplace((const ::hexplace_t*)(p_0.ToPointer()), (void*)(p_1.ToPointer()), p_2, p_3));
}

static int ida_hexplace_t__compare(IntPtr p_0, IntPtr p_1)
{
	return hexplace_t__compare((const ::hexplace_t*)(p_0.ToPointer()), (const ::place_t*)(p_1.ToPointer()));
}

static int ida_hexplace_t__compare2(IntPtr p_0, IntPtr p_1, IntPtr p_2)
{
	return hexplace_t__compare2((const ::hexplace_t*)(p_0.ToPointer()), (const ::place_t*)(p_1.ToPointer()), (void*)(p_2.ToPointer()));
}

static void ida_hexplace_t__adjust(IntPtr p_0, IntPtr p_1)
{
	return hexplace_t__adjust((::hexplace_t*)(p_0.ToPointer()), (void*)(p_1.ToPointer()));
}

static bool ida_hexplace_t__prev(IntPtr p_0, IntPtr p_1)
{
	return hexplace_t__prev((::hexplace_t*)(p_0.ToPointer()), (void*)(p_1.ToPointer()));
}

static bool ida_hexplace_t__next(IntPtr p_0, IntPtr p_1)
{
	return hexplace_t__next((::hexplace_t*)(p_0.ToPointer()), (void*)(p_1.ToPointer()));
}

static bool ida_hexplace_t__beginning(IntPtr p_0, IntPtr p_1)
{
	return hexplace_t__beginning((const ::hexplace_t*)(p_0.ToPointer()), (void*)(p_1.ToPointer()));
}

static bool ida_hexplace_t__ending(IntPtr p_0, IntPtr p_1)
{
	return hexplace_t__ending((const ::hexplace_t*)(p_0.ToPointer()), (void*)(p_1.ToPointer()));
}

static int ida_hexplace_t__generate(IntPtr p_0, IntPtr p_1, IntPtr p_2, IntPtr p_3, IntPtr p_4, IntPtr p_5, int p_6)
{
	return hexplace_t__generate((const ::hexplace_t*)(p_0.ToPointer()), (::qvector<::_qstring<char>>*)(p_1.ToPointer()), (int*)(p_2.ToPointer()), (unsigned char*)(p_3.ToPointer()), (unsigned int*)(p_4.ToPointer()), (void*)(p_5.ToPointer()), p_6);
}

static void ida_hexplace_t__serialize(IntPtr p_0, IntPtr out)
{
	return hexplace_t__serialize((const ::hexplace_t*)(p_0.ToPointer()), (::bytevec_t*)(out.ToPointer()));
}

static bool ida_hexplace_t__deserialize(IntPtr p_0, IntPtr p_1, IntPtr p_2)
{
	return hexplace_t__deserialize((::hexplace_t*)(p_0.ToPointer()), (const unsigned char**)(p_1.ToPointer()), (const unsigned char*)(p_2.ToPointer()));
}

static int ida_hexplace_t__id(IntPtr p_0)
{
	return hexplace_t__id((const ::hexplace_t*)(p_0.ToPointer()));
}

static IntPtr ida_hexplace_t__name(IntPtr p_0)
{
	return IntPtr((void*)hexplace_t__name((const ::hexplace_t*)(p_0.ToPointer())));
}

static unsigned long long ida_hexplace_t__toea(IntPtr p_0)
{
	return hexplace_t__toea((const ::hexplace_t*)(p_0.ToPointer()));
}

static IntPtr ida_hexplace_t__enter(IntPtr p_0, IntPtr p_1)
{
	return IntPtr((void*)hexplace_t__enter((const ::hexplace_t*)(p_0.ToPointer()), (unsigned int*)(p_1.ToPointer())));
}

static void ida_hexplace_t__leave(IntPtr p_0, unsigned int p_1)
{
	return hexplace_t__leave((const ::hexplace_t*)(p_0.ToPointer()), p_1);
}

//static bool ida_hexplace_t__rebase(IntPtr p_0, IntPtr p_1)
//{
//	return hexplace_t__rebase((::hexplace_t*)(p_0.ToPointer()), (const ::segm_move_infos_t&)(p_1.ToPointer()));
//}

//static void ida_hexplace_t__out_one_item(IntPtr _this, IntPtr ctx, IntPtr hg, int itemno, IntPtr color, unsigned char patch_or_edit)
//{
//	return hexplace_t__out_one_item((const ::hexplace_t*)(_this.ToPointer()), (::outctx_base_t)(ctx.ToPointer()), (const ::hexplace_gen_t*)(hg.ToPointer()), itemno, (unsigned char*)(color.ToPointer()), patch_or_edit);
//}

static unsigned long long ida_hexplace_t__ea2str(IntPtr buf, unsigned long long bufsize, IntPtr hg, unsigned long long ea)
{
	return hexplace_t__ea2str((char*)(buf.ToPointer()), bufsize, (const ::hexplace_gen_t*)(hg.ToPointer()), ea);
}

static int ida_internal_register_place_class(IntPtr tmplate, int flags, IntPtr owner, int sdk_version)
{
	return internal_register_place_class((const ::place_t*)(tmplate.ToPointer()), flags, (const ::plugin_t*)(owner.ToPointer()), sdk_version);
}

//static int ida_register_place_class(IntPtr tmplate, int flags, IntPtr owner) // inline
//{
//	...
//}
//
static IntPtr ida_get_place_class(IntPtr out_flags, IntPtr out_sdk_version, int id)
{
	return IntPtr((void*)get_place_class((int*)(out_flags.ToPointer()), (int*)(out_sdk_version.ToPointer()), id));
}

//static IntPtr ida_get_place_class_template(int id) // inline
//{
//	...
//}
//
//static bool ida_is_place_class_ea_capable(int id) // inline
//{
//	...
//}

static int ida_get_place_class_id(IntPtr name)
{
	return get_place_class_id((const char*)(name.ToPointer()));
}

//static void ida_register_loc_converter2(IntPtr p1, IntPtr p2, IntPtr cvt)
//{
//	return register_loc_converter2((const char*)(p1.ToPointer()), (const char*)(p2.ToPointer()), (::lecvt_code_t(*)(::lochist_entry_t*, const ::lochist_entry_t&, ::TWidget*, unsigned int))(cvt.ToPointer()));
//}
//
//static System::Func<lecvt_code_t, lochist_entry_t^ dst, lochist_entry_t^ src, TWidget^ view, unsigned int flags>^ ida_lookup_loc_converter2(IntPtr p1, IntPtr p2)
//{
//	return lookup_loc_converter2((const char*)(p1.ToPointer()), (const char*)(p2.ToPointer()));
//}

static void ida_linearray_t_ctr(IntPtr p_0, IntPtr ud)
{
	return linearray_t_ctr((::linearray_t*)(p_0.ToPointer()), (void*)(ud.ToPointer()));
}

static void ida_linearray_t_dtr(IntPtr p_0)
{
	return linearray_t_dtr((::linearray_t*)(p_0.ToPointer()));
}

static int ida_linearray_t_set_place(IntPtr p_0, IntPtr new_at)
{
	return linearray_t_set_place((::linearray_t*)(p_0.ToPointer()), (const ::place_t*)(new_at.ToPointer()));
}

static bool ida_linearray_t_beginning(IntPtr p_0)
{
	return linearray_t_beginning((const ::linearray_t*)(p_0.ToPointer()));
}

static bool ida_linearray_t_ending(IntPtr p_0)
{
	return linearray_t_ending((const ::linearray_t*)(p_0.ToPointer()));
}

static IntPtr ida_linearray_t_down(IntPtr p_0)
{
	return IntPtr((void*)linearray_t_down((::linearray_t*)(p_0.ToPointer())));
}

static IntPtr ida_linearray_t_up(IntPtr p_0)
{
	return IntPtr((void*)linearray_t_up((::linearray_t*)(p_0.ToPointer())));
}

static uint64 ida_get_dirty_infos()
{
	return get_dirty_infos();
}

static void ida_request_refresh(uint64 mask, bool cnd)
{
	return request_refresh(mask, cnd);
}

//static void ida_clear_refresh_request(unsigned long long mask) // inline
//{
//	...
//}

static bool ida_is_refresh_requested(uint64 mask)
{
	return is_refresh_requested(mask);
}

static long long ida_qcleanline(IntPtr buf, char cmt_char, unsigned int flags)
{
	return qcleanline((::_qstring<char>*)(buf.ToPointer()), cmt_char, flags);
}

static IntPtr ida_strarray(IntPtr array, unsigned long long array_size, int code)
{
	return IntPtr((void*)strarray((const ::strarray_t*)(array.ToPointer()), array_size, code));
}

static unsigned long long ida_ea2str(IntPtr buf, unsigned long long bufsize, unsigned long long ea)
{
	return ea2str((char*)(buf.ToPointer()), bufsize, ea);
}

//static bool ida_ea2str(IntPtr out, unsigned long long ea) // inline
//{
//	...
//}

static bool ida_str2ea(IntPtr ea_ptr, IntPtr str, unsigned long long screen_ea)
{
	return str2ea((unsigned long long*)(ea_ptr.ToPointer()), (const char*)(str.ToPointer()), screen_ea);
}

static bool ida_str2ea_ex(IntPtr ea_ptr, IntPtr str, unsigned long long screen_ea, int flags)
{
	return str2ea_ex((unsigned long long*)(ea_ptr.ToPointer()), (const char*)(str.ToPointer()), screen_ea, flags);
}

static bool ida_atoea(IntPtr pea, IntPtr str)
{
	return atoea((unsigned long long*)(pea.ToPointer()), (const char*)(str.ToPointer()));
}

static unsigned long long ida_stoa(IntPtr buf, unsigned long long from, unsigned long long seg)
{
	return stoa((::_qstring<char>*)(buf.ToPointer()), from, seg);
}

static int ida_atos(IntPtr seg, IntPtr str)
{
	return atos((unsigned long long*)(seg.ToPointer()), (const char*)(str.ToPointer()));
}

static unsigned long long ida_b2a_width(int nbytes, int radix)
{
	return b2a_width(nbytes, radix);
}

static unsigned long long ida_b2a32(IntPtr buf, unsigned long long bufsize, unsigned int x, int nbytes, int radix)
{
	return b2a32((char*)(buf.ToPointer()), bufsize, x, nbytes, radix);
}

static unsigned long long ida_b2a64(IntPtr buf, unsigned long long bufsize, unsigned long long x, int nbytes, int radix)
{
	return b2a64((char*)(buf.ToPointer()), bufsize, x, nbytes, radix);
}

static unsigned long long ida_btoa_width(int nbytes, unsigned int flag, int n)
{
	return btoa_width(nbytes, flag, n);
}

static unsigned long long ida_btoa32(IntPtr buf, unsigned long long bufsize, unsigned int x, int radix)
{
	return btoa32((char*)(buf.ToPointer()), bufsize, x, radix);
}

static unsigned long long ida_btoa64(IntPtr buf, unsigned long long bufsize, unsigned long long x, int radix)
{
	return btoa64((char*)(buf.ToPointer()), bufsize, x, radix);
}

//static unsigned long long ida_btoa128(IntPtr buf, unsigned long long bufsize, uint128^ x, int radix)
//{
//	return btoa128((char*)(buf.ToPointer()), bufsize, x, radix);
//}

static unsigned long long ida_numop2str(IntPtr buf, unsigned long long bufsize, unsigned long long ea, int n, unsigned long long x, int nbytes, int radix)
{
	return numop2str((char*)(buf.ToPointer()), bufsize, ea, n, x, nbytes, radix);
}

static bool ida_atob32(IntPtr x, IntPtr str)
{
	return atob32((unsigned int*)(x.ToPointer()), (const char*)(str.ToPointer()));
}

static bool ida_atob64(IntPtr x, IntPtr str)
{
	return atob64((unsigned long long*)(x.ToPointer()), (const char*)(str.ToPointer()));
}

static void ida_append_disp(IntPtr buf, long long disp, bool tag)
{
	return append_disp((::_qstring<char>*)(buf.ToPointer()), disp, tag);
}

static int ida_r50_to_asc(IntPtr p, IntPtr r, int k)
{
	return r50_to_asc((char*)(p.ToPointer()), (const unsigned short*)(r.ToPointer()), k);
}

// where is asc_to_r50 defined ????
//static int ida_asc_to_r50(IntPtr r, IntPtr p, int k)
//{
//	return asc_to_r50((unsigned short*)(r.ToPointer()), (const char*)(p.ToPointer()), k);
//}

static unsigned int ida_calc_crc32(unsigned int crc, IntPtr buf, unsigned long long len)
{
	return calc_crc32(crc, (const void*)(buf.ToPointer()), len);
}

static unsigned int ida_calc_file_crc32(IntPtr fp)
{
	return calc_file_crc32((::linput_t*)(fp.ToPointer()));
}

static int ida_regex_match(IntPtr str, IntPtr pattern, bool sense_case)
{
	return regex_match((const char*)(str.ToPointer()), (const char*)(pattern.ToPointer()), sense_case);
}

//static void ida_place_t__serialize(IntPtr _this, IntPtr out) // inline
//{
//	...
//}
//
//static bool ida_place_t__deserialize(IntPtr _this, IntPtr pptr, IntPtr end) // inline
//{
//	...
//}
//
//static void ida_get_user_strlist_options(IntPtr out) // inline
//{
//	...
//}
//
//static bool ida_del_idc_hotkey(IntPtr hotkey) // inline
//{
//	...
//}

static void ida_ida_checkmem(IntPtr file, int line)
{
	return ida_checkmem((const char*)(file.ToPointer()), line);
}

static void ida_ui_info(IntPtr inf)
{
	info((char*)(inf.ToPointer()));
}

static void ida_ui_warning(IntPtr warn)
{
	warning((char*)(warn.ToPointer()));
}

static int ida_ui_msg(IntPtr message)
{
	return msg((char*)(message.ToPointer()));
}

static int ida_ui_ask_yn(int default, IntPtr message)
{
	return ask_yn(default, (char*)(message.ToPointer()));
}

static int ida_ui_ask_buttons(IntPtr yes, IntPtr no, IntPtr cancel, int default, IntPtr message)
{
	return ask_buttons((char*)(yes.ToPointer()), (char*)(no.ToPointer()), (char*)(cancel.ToPointer()), default, (char*)(message.ToPointer()));
}

static void ida_refresh_idaview_anyway()
{
	refresh_idaview_anyway();
}

//static callui_t ida_ui_callui(int what, ...array<Object^>^ args)
//{
//	return callui((ui_notification_t)what, args);
//}