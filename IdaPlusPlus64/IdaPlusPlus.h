#pragma once

#include "idasdk.h"
#include <hexrays.hpp>

#include "WaitBox\WaitBoxEx.h"
#include "SegSelect\SegSelectEx.h"
#include "MainDialog\MainDialogEx.h"
#include "OggPlayer\IdaOgg.h"
#include "RTTIChooser\rtti_chooser.h"

#include <msclr\marshal.h>
#include <msclr\marshal_windows.h>
#include <msclr\marshal_cppstd.h>
#include <cliext\utility>
#include <cliext\vector>
#include <type_traits>

using namespace System;
using namespace System::Collections::Generic;
using namespace System::Runtime::InteropServices;
using namespace msclr::interop;

struct enum_member_visitor : enum_member_visitor_t
{
	IntPtr callback;

	enum_member_visitor(IntPtr v)
	{
		callback = v;
	}

	int visit_enum_member(const_t cid, uval_t value)
	{
		auto fptr = (int(__stdcall*)(const_t cid, uval_t value))(callback.ToPointer());
		return (*fptr)(cid, value);
	}
};

static void ConvertQstringToIntPtr(qstring src, IntPtr dest, ssize_t size)
{
	if (size > 0)
	{
		String^ str = gcnew String(src.c_str(), 0, size);
		auto ptrtostr = Marshal::StringToHGlobalAnsi(str);
		std::memcpy(static_cast<void*>(dest), static_cast<const void*>(ptrtostr), size);
		Marshal::FreeHGlobal(ptrtostr);
	}
	else
	{
		String^ str = gcnew String(String::Empty);
		auto ptrtostr = Marshal::StringToHGlobalAnsi(str);
		std::memcpy(static_cast<void*>(dest), static_cast<const void*>(ptrtostr), size);
		Marshal::FreeHGlobal(ptrtostr);
	}
}

static void ConvertQwstringToIntPtr(qwstring src, IntPtr dest, ssize_t size)
{
	if (size > 0)
	{
		String^ str = gcnew String(src.c_str(), 0, size);
		auto ptrtostr = Marshal::StringToHGlobalUni(str);
		std::memcpy(static_cast<void*>(dest), static_cast<const void*>(ptrtostr), size);
		Marshal::FreeHGlobal(ptrtostr);
	}
	else
	{
		String^ str = gcnew String(String::Empty);
		auto ptrtostr = Marshal::StringToHGlobalUni(str);
		std::memcpy(static_cast<void*>(dest), static_cast<const void*>(ptrtostr), size);
		Marshal::FreeHGlobal(ptrtostr);
	}
}

static String^ ConvertQstringToString(qstring src)
{
	// must skip ending \x00
	return gcnew String(src.c_str(), 0, src.size() - 1);
}

static String^ ConvertQstringToString(qstring* src)
{
	// must skip ending \x00
	return gcnew String(src->c_str(), 0, src->size() - 1);
}

template <typename T>
ref class MyList : List<T>
{
public:
	MyList<T>()
	{
	}

	MyList<T>(const MyList<T>% rhs)
	{
	}   // copy constructor
};

template <typename T>
static MyList<IntPtr>^ ConvertQVectorToMyListOfIntPtr(qvector<T> src)
{
	// create List
	auto list = gcnew MyList<IntPtr>();
	// populate array
	if (typeid(T) == typeid(qstring))
	{
		for (int i = 0; i < src.size(); ++i)
		{
			IntPtr ptr = Marshal::AllocCoTaskMem(src[i].size() + 1);
			::ConvertQstringToIntPtr(src[i], ptr, src[i].size());
			list->Add(ptr);
		}
	}
	//else if (typeid(T) == typeid(qwstring))
	//{
	//	for (int i = 0; i < src.size(); ++i)
	//	{
	//		IntPtr ptr = Marshal::AllocCoTaskMem(src[i].size() + 1);
	//		::ConvertQwstringToIntPtr(dynamic_cast<qwstring>(src[i]), ptr, src[i].size());
	//		list->Add(ptr);
	//	}
	//}
	else
	{
		for (int i = 0; i < src.size(); ++i)
		{
			list->Add(IntPtr((void*)(&src[i])));
		}
	}
	return list;
}

ignore_micro_t im;

namespace IdaPlusPlus
{
	public ref class IdaInterop
	{
	public:

#include "Auto.h"
#include "Bitrange.h"
#include "Bytes.h"
#include "Compress.h"
#include "Config.h"
#include "Cvt64.h"
#include "Dbg.h"
#include "Demangle.h"
#include "Diskio.h"
#include "Entry.h"
#include "Enum.h"
#include "Err.h"
#include "Exehdr.h"
#include "Fixup.h"
#include "Fpro.h"
#include "Frame.h"
#include "Funcs.h"
#include "Gdl.h"
#include "Graph.h"
#include "Help.h"
#include "Hexrays.h"
#include "Idacfg.h"
#include "Idd.h"
#include "Idp.h"
#include "Inf.h"
#include "Jumptable.h"
#include "Kernwin.h"
#include "Lex.h"
#include "Lines.h"
#include "Loader.h"
#include "Md5.h"
#include "Moves.h"
#include "Nalt.h"
#include "Name.h"
#include "Netnode.h"
#include "Network.h"
#include "Offset.h"
#include "Parsejson.h"
#include "Pro.h"
#include "Problems.h"
#include "Prodir.h"
#include "Pronet.h"
#include "Range.h"
#include "Regex.h"
#include "Registry.h"
#include "Search.h"
#include "Segment.h"
#include "Segregs.h"
#include "Srclang.h"
#include "Strlist.h"
#include "Struct.h"
#include "Tryblks.h"
#include "Typeinf.h"
#include "Ua.h"
#include "Xref.h"
#include "Hexrays.h"

		// ClassInformer QT stuff
#include "WaitBox.h"
#include "SegSelect.h"
#include "MainDialog.h"
#include "OggPlayer.h"
#include "RTTIChooser.h"
	};
}
