// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

#include <windows.h>
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <diskio.hpp>
#include <filesystem>

// Plugin information
#define PLUGIN_NAME "Ida Plugin Shim"
#define PLUGIN_HOTKEY ""
#define PLUGIN_VERSION "1.0"

namespace fs = std::filesystem;

// Struct to hold the real plugin
struct RealPlugin {
    HMODULE handle;
    plugin_t* plugin;
    plugmod_t* plugmod;
};

static RealPlugin g_real_plugin = { nullptr, nullptr, nullptr };

// Helper function to set DLL directory and load the real plugin
bool load_real_plugin() 
{
    try 
    {
        // Get the path to the shim plugin (it is in plugins dir)
        char shim_path[MAX_PATH];
        qstrncpy(shim_path, idadir("plugins"), MAX_PATH);
        fs::path plugin_dir = fs::path(shim_path);

        fs::path managed_plugin_dir = plugin_dir / "MixedModePlugin64";

        HANDLE dll_dir = AddDllDirectory(managed_plugin_dir.c_str());
        if (!dll_dir) 
        {
            msg("Failed to add DLL directory: %08X\n", GetLastError());
            return false;
        }

        if (!SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS | LOAD_LIBRARY_SEARCH_USER_DIRS))
        {
            msg("Failed to set default DLL directory: %08X\n", GetLastError());
            return false;
        }

        // Load the real plugin
        fs::path real_plugin_path = plugin_dir / "xWare.net64.dll";
        g_real_plugin.handle = LoadLibraryW(real_plugin_path.c_str());
        if (!g_real_plugin.handle) 
        {
            msg("Failed to load real plugin: %08X\n", GetLastError());
            return false;
        }

        // Get the PLUGIN export
        g_real_plugin.plugin = (plugin_t*)GetProcAddress(g_real_plugin.handle, "PLUGIN");
        if (!g_real_plugin.plugin) 
        {
            msg("Failed to get PLUGIN export\n");
            FreeLibrary(g_real_plugin.handle);
            g_real_plugin.handle = nullptr;
            return false;
        }

        return true;
    }
    catch (const std::exception& e) {
        msg("Exception while loading real plugin: %s\n", e.what());
        return false;
    }
}

// Plugin initialization
plugmod_t* idaapi init(void) 
{
    if (!load_real_plugin()) 
    {
        return nullptr;
    }

    // Initialize the real plugin
    if (g_real_plugin.plugin && g_real_plugin.plugin->init) 
    {
        g_real_plugin.plugmod = g_real_plugin.plugin->init();
    }

    return g_real_plugin.plugmod;
}

// Plugin termination
void idaapi term(void) 
{
    if (g_real_plugin.plugin && g_real_plugin.plugin->term) 
    {
        g_real_plugin.plugin->term();
    }

    if (g_real_plugin.handle) 
    {
        FreeLibrary(g_real_plugin.handle);
        g_real_plugin.handle = nullptr;
        g_real_plugin.plugin = nullptr;
    }
}

// Plugin execution
bool idaapi run(size_t arg) 
{
    if (g_real_plugin.plugin && g_real_plugin.plugin->run) 
    {
        return g_real_plugin.plugin->run(arg);
    }

    return false;
}

// Plugin registration
plugin_t PLUGIN = 
{
    IDP_INTERFACE_VERSION,
    PLUGIN_FIX,           // Plugin flags
    init,                 // Initialize
    term,                 // Terminate
    run,                  // Main function
    nullptr, 
    nullptr, 
    nullptr, 
    nullptr, 
};
