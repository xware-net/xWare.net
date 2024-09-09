#pragma once

#include <windows.h>
#include "ida.hpp"

using namespace System;

LPCSTR MENU_PATH = "Edit/xWare.net Plugins/";

enum MENU_ACTION
{
	MA_CLASSINFORMER,
	MA_TEST,
	MA_COUNT
};

#define ENUM2STR(_value) #_value
