#pragma once

static List<IntPtr>^ MainDialog_getSelectedSegments()
{
	auto size = SegSelectEx_getSelectedSegmentsCount();
	List<IntPtr>^ list = gcnew List<IntPtr>();
	for (int i = 0; i < size; i++)
	{
		IntPtr ptr = IntPtr(SegSelectEx_getNthSelectedSegment(i));
		list->Add(ptr);
	}

	return list;
}

static bool DoMainDialog(bool& optionPlaceStructs, bool& optionProcessStatic,  bool& optionAudioOnDone)
{
	return doMainDialog(optionPlaceStructs, optionProcessStatic, optionAudioOnDone);
}
