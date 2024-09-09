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
#include <kernwin.hpp>
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

// RTTI list chooser
const char LBTITLE[] = { "[Class Informer]" };
const UINT LBCOLUMNCOUNT = 5;
const int LBWIDTHS[LBCOLUMNCOUNT] = { (8 | CHCOL_HEX), (4 | CHCOL_DEC), 3, 19, 500 };
const char* const LBHEADER[LBCOLUMNCOUNT] =
{
    "Vftable",
    "Methods",
    "Flags",
    "Type",
    "Hierarchy"
};

// Size of string sans terminator
#define SIZESTR(x) (sizeof(x) - 1)

static int  chooserIcon = 0;

public class rtti_chooser : public chooser_multi_t
{
public:
    rtti_chooser()/* : chooser_multi_t(CH_QFTYP_DEFAULT, LBCOLUMNCOUNT, LBWIDTHS, LBHEADER, LBTITLE)*/;

    virtual const void* get_obj_id(size_t* len) const;

    virtual size_t get_count() const;

    virtual void get_row(qstrvec_t* cols_, int* icon_, chooser_item_attrs_t* attributes, size_t n) const;

    virtual cbres_t enter(sizevec_t* sel);

    virtual void closed();

    virtual void customizeChooserWindow();

    void addTableEntry(ea_t vft, WORD methodCount, WORD flags, const char *format, ...);

private:
    char addressFormat[16]{};
};
