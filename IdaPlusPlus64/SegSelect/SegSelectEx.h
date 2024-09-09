
// SegSelect: IDA Pro Qt multi-segment select dialog
// By Sirmabus 2015
// Version 1.2
// Docs: http://www.macromonkey.com/ida-waitboxex/
// License: Qt 5.6.0 LGPL
#pragma once

#define WIN32_LEAN_AND_MEAN
//#define WINVER       0x0601 // _WIN32_WINNT_WIN7
//#define _WIN32_WINNT 0x0601
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <exception>

#define QT_NO_STATUSTIP
#define QT_NO_WHATSTHIS
#define QT_NO_ACCESSIBILITY
#include <QtCore/QTextStream>
#include <QtCore/QFile>
#include <QtWidgets/QApplication>
#include <QtWidgets/QDialog>
#include <QtWidgets/QTableWidget>

#define USE_DANGEROUS_FUNCTIONS
// Nix the many warning about int type conversions
#pragma warning(push)
#pragma warning(disable:4244)
#pragma warning(disable:4267)
#include <ida.hpp>
#include <idp.hpp>
#include <segment.hpp>
#include "SegmentDialog.h"
#pragma warning(pop)

// IDA SDK Qt libs @ (SDK)\lib\x86_win_qt
#pragma comment(lib, "Qt5Core.lib")
#pragma comment(lib, "Qt5Gui.lib")
#pragma comment(lib, "Qt5Widgets.lib")


	// Option flags
static const uint CODE_HINT = (1 << 0);    // Default check any code segment(s)
static const uint DATA_HINT = (1 << 1);    // Default check any ".data" segment(s)
static const uint RDATA_HINT = (1 << 2);    // "" ".rdata" segment(s)
static const uint XTRN_HINT = (1 << 3);    // "" ".idata" type segment(s)

typedef std::vector<segment_t*> SegSelectEx_segments;

//SegSelectEx_segments* SegSelectEx_getSelectedSegments();

segment_t* SegSelectEx_getNthSelectedSegment(int n);

int SegSelectEx_getSelectedSegmentsCount();

// Do segment selection dialog
// Results are returned as a 'segments' vector pointer or NULL if canceled or none selected.
// Call free() below to free up segments vector.
void SegSelectEx_select(UINT flags, LPCSTR title = "Choose SegmentsChoose Segments", LPCSTR styleSheet = NULL, LPCSTR icon = NULL);

// Free segments vector returned by select()
void SegSelectEx_free();

// Convenience wrapper of Qt function "QApplication::processEvents();" to tick IDA's main window
void SegSelectEx_processIdaEvents();


