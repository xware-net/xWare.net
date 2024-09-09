#pragma once

static void WaitBox_show(IntPtr titleText, IntPtr labelText, IntPtr styleSheet, IntPtr icon)
{
	WaitBoxEx_show((const char*)(titleText.ToPointer()), (const char*)(labelText.ToPointer()), (const char*)(styleSheet.ToPointer()), (const char*)(icon.ToPointer()));
}

static void WaitBox_showDefault()
{
	WaitBoxEx_showDefault();
}

// Stop the wait box
static void WaitBox_hide()
{
	WaitBoxEx_hide();
}

// Check if user canceled and optionally the update progress too w/built-in timed update limiter.
// Progress range: 0 to 100, or -1 to switch to indeterminate mode.
static bool WaitBox_updateAndCancelCheck(int progress)
{
	return WaitBoxEx_updateAndCancelCheck(progress);
}


// Returns TRUE if ready for internal update
static bool WaitBox_isUpdateTime()
{
	return WaitBoxEx_isUpdateTime();
}

// Returns TRUE if wait box up
static bool WaitBox_isShowing()
{
	return WaitBoxEx_isShowing();
}

// Change the label text
static void WaitBox_setLabelText(IntPtr labelText)
{
	WaitBoxEx_setLabelText((const char*)(labelText.ToPointer()));
}

// Convenience wrapper of Qt function "QApplication::processEvents();" to tick IDA's Qt event queue
static void WaitBox_processIdaEvents()
{
	WaitBoxEx_processIdaEvents();
}
