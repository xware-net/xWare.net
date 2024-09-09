#pragma once

static List<IntPtr>^ SegSelect_select(uint flags, IntPtr title, IntPtr styleSheet, IntPtr icon)
{
	SegSelectEx_select(flags, (const char*)(title.ToPointer()), (const char*)(styleSheet.ToPointer()), (const char*)(icon.ToPointer()));
	auto size = SegSelectEx_getSelectedSegmentsCount();
	List<IntPtr>^ list = gcnew List<IntPtr>();
	for (int i = 0; i < size; i++)
	{
		IntPtr ptr = IntPtr(SegSelectEx_getNthSelectedSegment(i));
		list->Add(ptr);
	}

	return list;
}

// Free segments vector returned by select()
static void SegSelect_free()
{
	SegSelectEx_free();
}

// Convenience wrapper of Qt function "QApplication::processEvents();" to tick IDA's main window
static void SegSelect_processIdaEvents()
{
	SegSelectEx_processIdaEvents();
}