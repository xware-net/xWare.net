#include "pch.h"
#include "xWare.net64.h"
#include "Importer.hpp"

struct ClassInformerHandler : public action_handler_t
{
    int idaapi activate(action_activation_ctx_t* ctx) override
    {
        runPlugin("ClassInformer");
        return 1;
    }

    action_state_t idaapi update(action_update_ctx_t* ctx) override { return AST_ENABLE_FOR_WIDGET; }
};

struct TestHandler : public action_handler_t
{
    int idaapi activate(action_activation_ctx_t* ctx) override
    {
        try
        {
            runPlugin("Test");
        }
        catch (...)
        {
        };

        return 1;
    }

    action_state_t idaapi update(action_update_ctx_t* ctx) override { return AST_ENABLE_FOR_WIDGET; }
};


ClassInformerHandler classInformerHandler;
TestHandler testHandler;
const action_desc_t action[MA_COUNT] =
{
    ACTION_DESC_LITERAL(ENUM2STR(MENU_ACTION::MA_CLASSINFORMER),  "ClassInformer",  &classInformerHandler,  "", "ClassInformer plugin", -1),
    ACTION_DESC_LITERAL(ENUM2STR(MENU_ACTION::MA_TEST), "Test", &testHandler, "", "Test plugin", -1)
};

//--------------------------------------------------------------------------
struct plugin_ctx_t : public plugmod_t
{
    virtual bool idaapi run(size_t) override;
};

//--------------------------------------------------------------------------
bool idaapi plugin_ctx_t::run(size_t)
{
#ifdef __EA64__
    // here is defined 64bit
    // runPlugin("ClassInformer");
#else
    // here 64bit is not defined.
#endif
    return true;
}

//--------------------------------------------------------------------------
static plugmod_t* idaapi init()
{
    // Add action menu
    for (UINT32 i = 0; i < MENU_ACTION::MA_COUNT; i++)
    {
        register_action(action[i]);
        attach_action_to_menu(MENU_PATH, action[i].name, SETMENU_APP);
    }

    return new plugin_ctx_t;
    //return PLUGIN_KEEP;
}

//--------------------------------------------------------------------------
void idaapi term()
{
}

//--------------------------------------------------------------------------
bool idaapi run(size_t s)
{
    return (new plugin_ctx_t)->run(s);
}

//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_FIX,           // Load plugin when IDA starts and keep it in the memory until IDA stops.
  init,                 // initialize
  term,                 // terminate
  run,                  // run
  nullptr,              // long comment about the plugin
  nullptr,              // multiline help about the plugin
  nullptr/*"xWare.net64"*/,        // the preferred short name of the plugin
  nullptr,              // the preferred hotkey to run the plugin
};
