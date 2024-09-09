#pragma once

#pragma unmanaged
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <hexrays.hpp>

#pragma managed
bool runPlugin(char* name);
bool initPlugin();

