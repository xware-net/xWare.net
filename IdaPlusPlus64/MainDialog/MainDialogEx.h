#pragma once

#define WIN32_LEAN_AND_MEAN
//#define WINVER		 0x0601 // _WIN32_WINNT_WIN7
//#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <tchar.h>
#include <math.h>
#include <crtdbg.h>
#include <intrin.h>

#pragma intrinsic(memset, memcpy, strcat, strcmp, strcpy, strlen, abs, fabs, labs, atan, atan2, tan, sqrt, sin, cos)

// IDA libs
#define USE_DANGEROUS_FUNCTIONS
#define USE_STANDARD_FILE_FUNCTIONS
// #define NO_OBSOLETE_FUNCS
#define __DEFINE_INF__
// Nix the many warning about int type conversions
#pragma warning(push)
#pragma warning(disable:4244)
#pragma warning(disable:4267)
#include <ida.hpp>
#include <auto.hpp>
#include <loader.hpp>
#include <search.hpp>
#include <typeinf.hpp>
#include <struct.hpp>
#include <nalt.hpp>
#include <demangle.hpp>
#pragma warning(pop)

// Qt libs
#include <QtCore/QTextStream>
#include <QtCore/QFile>
#include <QtWidgets/QApplication>
#include <QtWidgets/QProgressDialog>
#include <QtWidgets/QLabel>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QTableView>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QScrollBar>
#include <QtWidgets/QDialogButtonBox>
// IDA SDK Qt libs
#pragma comment(lib, "Qt5Core.lib")
#pragma comment(lib, "Qt5Gui.lib")
#pragma comment(lib, "Qt5Widgets.lib")

#include <QtWidgets\QDialog>
#include "..\SegSelect\SegSelectEx.h"

#include "ui_dialog.h"

class MainDialog : public QDialog, public Ui::MainCIDialog
{
    Q_OBJECT
public:
    MainDialog(bool& optionPlaceStructs, bool& optionProcessStatic, bool& optionAudioOnDone);

private:
	segment_t* MainDialog_getNthSelectedSegment(int n);
	int MainDialog_getSelectedSegmentsCount();

private slots:
	void segmentSelect();
};

// Do main dialog, return TRUE if canceled
BOOL doMainDialog(bool& optionPlaceStructs, bool& optionProcessStatic, bool& optionAudioOnDone);
