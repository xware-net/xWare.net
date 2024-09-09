#pragma once

static rtti_chooser *rttiChooser1 = nullptr;

static void RTTIChooser_New()
{
	auto rttiChooser = new rtti_chooser();
	rttiChooser->choose();
	rttiChooser->customizeChooserWindow();
}

static void RTTIChooser_AddTableEntry(ea_t vft, ushort methodCount, ushort flags, IntPtr entry)
{
	if (rttiChooser1 == nullptr)
	{
		rttiChooser1 = new rtti_chooser();
	}

	rttiChooser1->addTableEntry(vft, methodCount, flags, (const char*)(entry.ToPointer()));
}

