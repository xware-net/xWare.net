#pragma once

// Show the modal wait box dialog
void WaitBoxEx_show(LPCSTR titleText = "Progress", LPCSTR labelText = "Please wait..", LPCSTR styleSheet = NULL, LPCSTR icon = NULL);

// Show the modal wait box dialog
void WaitBoxEx_showDefault();

// Stop the wait box
void WaitBoxEx_hide();

// Check if user canceled and optionally the update progress too w/built-in timed update limiter.
// Progress range: 0 to 100, or -1 to switch to indeterminate mode.
BOOL WaitBoxEx_updateAndCancelCheck(int progress);


// Returns TRUE if ready for internal update
BOOL WaitBoxEx_isUpdateTime();

// Returns TRUE if wait box up
BOOL WaitBoxEx_isShowing();

// Change the label text
void WaitBoxEx_setLabelText(LPCSTR labelText);

// Convenience wrapper of Qt function "QApplication::processEvents();" to tick IDA's Qt event queue
void WaitBoxEx_processIdaEvents();


