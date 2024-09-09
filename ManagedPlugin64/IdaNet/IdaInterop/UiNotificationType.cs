using System;

namespace IdaNet.IdaInterop
{
    // Events marked as '*' should be used as a parameter to callui()
    // See convenience functions below (like get_screen_ea())
    // Events marked as 'cb' are designed to be callbacks and should not
    // be used in callui(). The user may hook to HT_UI events to catch them
    public enum UiNotificationType : int
    {
        ui_null = 0,

        ui_range,             ///< cb: The disassembly range has been changed (\inf{min_ea} ... \inf{max_ea}).
                              ///< UI should redraw the scrollbars. See also: ::ui_lock_range_refresh
                              ///< \param none
                              ///< \return void

        ui_refresh_choosers,  ///< cb: The list (chooser) window contents have been changed (names, signatures, etc).
                              ///< UI should redraw them. Please consider request_refresh() instead
                              ///< \param none
                              ///< \return void

        ui_idcstart,          ///< cb: Start of IDC engine work.
                              ///< \param none
                              ///< \return void

        ui_idcstop,           ///< cb: Stop of IDC engine work.
                              ///< \param none
                              ///< \return void

        ui_suspend,           ///< cb: Suspend graphical interface.
                              ///< Only the text version.
                              ///< Interface should respond to it.
                              ///< \param none
                              ///< \return void

        ui_resume,            ///< cb: Resume the suspended graphical interface.
                              ///< Only the text version.
                              ///< Interface should respond to it
                              ///< \param none
                              ///< \return void

        ui_broadcast,         ///< cb: broadcast call
                              ///< \param magic (::int64) a magic number
                              ///< \param ... other parameters depend on the given magic
                              ///< modules may hook to this event and reply to the caller.
                              ///< for example, the decompiler uses it to communicate
                              ///< its entry point to other plugins

        ui_read_selection,    ///< ui: see read_selection()

        ui_read_range_selection,  ///< ui: see read_range_selection()

        ui_unmarksel,         ///< ui: see unmark_selection()

        ui_screenea,          ///< ui: see get_screen_ea()

        ui_saving,            ///< cb: The kernel is flushing its buffers to the disk.
                              ///< The user interface should save its state.
                              ///< Parameters: none
                              ///< Returns:    none

        ui_saved,             ///< cb: The kernel has saved the database.
                              ///< This callback just informs the interface.
                              ///< Note that at the time this notification is sent,
                              ///< the internal paths are not updated yet,
                              ///< and calling get_path(PATH_TYPE_IDB) will return
                              ///< the previous path.
                              ///< \param path (const char *) the database path
                              ///< \return void

        ui_refreshmarked,     ///< ui: see refresh_idaview()

        ui_refresh,           ///< ui: see refresh_idaview_anyway()

        ui_choose,            ///< ui: Allow the user to choose an object.
                              ///< Always use the helper inline functions for this code.
                              ///< See \ref ui_choose_funcs for a list of such functions.
                              ///< \param type  (::choose_type_t) type of chooser to display
                              ///< \param ... other parameters depend on the given type
                              ///< \return depends on the given type

        ui_close_chooser,     ///< ui: see close_chooser()

        ui_banner,            ///< ui: see banner()

        ui_setidle,           ///< ui: Set a function to call at idle times.
                              ///< \param func  (int (*)(void)) pointer to function that will be called
                              ///< \return void

        ui_database_closed,   ///< cb: The database has been closed.
                              ///< See also processor_t::closebase, it occurs earlier.
                              ///< See also ui_initing_database.
                              ///< This is not the same as IDA exiting. If you need
                              ///< to perform cleanup at the exiting time, use qatexit().
                              ///< \param none
                              ///< \return void

        ui_beep,              ///< ui: see beep()

        ui_is_msg_inited,     ///< ui: see is_msg_inited()

        ui_msg,               ///< ui: Show a message in the message window.
                              ///< \param format  (const char *) format of message body
                              ///< \param va      (va_list) format args
                              ///< \return number of bytes output

        ui_mbox,              ///< ui: Show a message box.
                              ///< \param kind    (::mbox_kind_t)
                              ///< \param format  (const char *) format of message body
                              ///< \param va      (va_list]) format args
                              ///< \return void

        ui_clr_cancelled,     ///< ui: see clr_cancelled()

        ui_set_cancelled,     ///< ui: see set_cancelled()

        ui_test_cancelled,    ///< ui: see user_cancelled()

        ui_ask_buttons,       ///< ui: see ask_yn() and ask_buttons()

        ui_ask_file,          ///< ui: see ask_file()

        ui_ask_form,          ///< ui: see \ref FORM_C

        ui_ask_text,          ///< ui: see ask_text()

        ui_ask_str,           ///< ui: see ask_str()

        ui_ask_addr,          ///< ui: see ask_addr()

        ui_ask_seg,           ///< ui: see ask_seg()

        ui_ask_long,          ///< ui: see ask_long()

        ui_add_idckey,        ///< ui: see add_idc_hotkey()

        ui_obsolete_del_idckey,
        ///< ui: see ui_del_idckey()

        ui_analyzer_options,  ///< ui: see analyzer_options()

        ui_load_file,         ///< ui: see ui_load_new_file()

        ui_run_dbg,           ///< ui: see ui_run_debugger()

        ui_get_cursor,        ///< ui: see get_cursor()

        ui_get_curline,       ///< ui: see get_curline()

        ui_copywarn,          ///< ui: see display_copyright_warning()

        ui_noabort,           ///< ui: Disable 'abort' menu item - the database was not compressed.
                              ///< \param none
                              ///< \return void

        ui_lock_range_refresh,///< ui: Lock the ui_range refreshes.
                              ///< The ranges will not be refreshed until the corresponding
                              ///< ::ui_unlock_range_refresh is issued.
                              ///< \param none
                              ///< \return void

        ui_unlock_range_refresh,///< ui: Unlock the ::ui_range refreshes.
                                ///< If the number of locks is back to zero, then refresh the ranges.
                                ///< \param none
                                ///< \return void

        ui_genfile_callback,  ///< cb: handle html generation.
                              ///< \param html_header_cb_t **
                              ///< \param html_footer_cb_t **
                              ///< \param html_line_cb_t **
                              ///< \return void

        ui_open_url,          ///< ui: see open_url()

        ui_hexdumpea,         ///< ui: Return the current address in a hex view.
                              ///< \param result       (::ea_t *)
                              ///< \param hexdump_num  (int)
                              ///< \return void

        ui_get_key_code,      ///< ui: see get_key_code()

        ui_setup_plugins_menu,///< ui: setup plugins submenu
                              ///< \param none
                              ///< \return void

        ui_get_kernel_version,///< ui: see get_kernel_version()

        ui_is_idaq,           ///< ui: see is_idaq()

        ui_refresh_navband,   ///< ui: see refresh_navband()

        ui_debugger_menu_change, ///< cb: debugger menu modification detected
                                 ///< \param enable (bool)
                                 ///<    true: debugger menu has been added, or a different debugger has been selected
                                 ///<    false: debugger menu will be removed (user switched to "No debugger")
                                 ///< \return void

        ui_get_curplace,      ///< ui: see get_custom_viewer_place(). See also ui_get_custom_viewer_location

        ui_obsolete_display_widget,
        ui_close_widget,       ///< ui: see close_widget()

        ui_activate_widget,   ///< ui: see activate_widget()

        ui_find_widget,       ///< ui: see find_widget()

        ui_get_current_widget,
        ///< ui: see get_current_widget()

        ui_widget_visible,    ///< TWidget is displayed on the screen.
                              ///< Use this event to populate the window with controls
                              ///< \param widget (TWidget *)
                              ///< \return void

        ui_widget_closing,    ///< TWidget is about to close.
                              ///< This event precedes ui_widget_invisible. Use this
                              ///< to perform some possible actions relevant to
                              ///< the lifecycle of this widget
                              ///< \param widget (TWidget *)
                              ///< \return void

        ui_widget_invisible,  ///< TWidget is being closed.
                              ///< Use this event to destroy the window controls
                              ///< \param widget (TWidget *)
                              ///< \return void

        ui_get_ea_hint,       ///< cb: ui wants to display a simple hint for an address.
                              ///< Use this event to generate a custom hint
                              ///< See also more generic ::ui_get_item_hint
                              ///< \param buf      (::qstring *)
                              ///< \param ea       (::ea_t)
                              ///< \return true if generated a hint

        ui_get_item_hint,     ///< cb: ui wants to display multiline hint for an item.
                              ///< See also more generic ::ui_get_custom_viewer_hint
                              ///< \param[out] hint             (::qstring *) the output string
                              ///< \param ea                    (ea_t) or item id like a structure or enum member
                              ///< \param max_lines             (int) maximal number of lines
                              ///< \param[out] important_lines  (int *) number of important lines. if zero, output is ignored
                              ///< \return true if generated a hint

        ui_refresh_custom_viewer,
        ///< ui: see refresh_custom_viewer()

        ui_destroy_custom_viewer,
        ///< ui: see destroy_custom_viewer()

        ui_jump_in_custom_viewer,
        ///< ui: see jumpto()

        ui_get_custom_viewer_curline,
        ///< ui: see get_custom_viewer_curline()

        ui_get_current_viewer,///< ui: see get_current_viewer()

        ui_is_idaview,        ///< ui: see is_idaview()

        ui_get_custom_viewer_hint,
        ///< cb: ui wants to display a hint for a viewer (idaview or custom).
        ///< Every subscriber is supposed to append the hint lines
        ///< to HINT and increment IMPORTANT_LINES accordingly.
        ///< Completely overwriting the existing lines in HINT
        ///< is possible but not recommended.
        ///< If the REG_HINTS_MARKER sequence is found in the
        ///< returned hints string, it will be replaced with the
        ///< contents of the "regular" hints.
        ///< If the SRCDBG_HINTS_MARKER sequence is found in the
        ///< returned hints string, it will be replaced with the
        ///< contents of the source-level debugger-generated hints.
        ///< The following keywords might appear at the beginning of the
        ///< returned hints:
        ///< HIGHLIGHT text\n
        ///<   where text will be highlighted
        ///< CAPTION caption\n
        ///<   caption for the hint widget
        ///< \param[out] hint             (::qstring *) the output string,
        ///<                              on input contains hints from the previous subscribes
        ///< \param viewer                (TWidget*) viewer
        ///< \param place                 (::place_t *) current position in the viewer
        ///< \param[out] important_lines  (int *) number of important lines,
        ///<                                     should be incremented,
        ///<                                     if zero, the result is ignored
        ///< \retval 0 continue collecting hints with other subscribers
        ///< \retval 1 stop collecting hints

        ui_set_custom_viewer_range,
        ///< ui: set_custom_viewer_range()

        ui_database_inited,   ///< cb: database initialization has completed.
                              ///< the kernel is about to run idc scripts
                              ///< \param is_new_database  (int)
                              ///< \param idc_script       (const char *) - may be nullptr
                              ///< \return void
                              ///< See also ui_initing_database.
                              ///< This event is called for both new and old databases.

        ui_ready_to_run,      ///< cb: all UI elements have been initialized.
                              ///< Automatic plugins may hook to this event to
                              ///< perform their tasks.
                              ///< \param none
                              ///< \return void

        ui_set_custom_viewer_handler,
        ///< ui: see set_custom_viewer_handler().
        ///< also see other examples in \ref ui_scvh_funcs

        ui_refresh_chooser,   ///< ui: see refresh_chooser()

        ui_open_builtin,      ///< ui: open a window of a built-in type. see \ref ui_open_builtin_funcs

        ui_preprocess_action, ///< cb: ida ui is about to handle a user action.
                              ///< \param name  (const char *) ui action name.
                              ///<                             these names can be looked up in ida[tg]ui.cfg
                              ///< \retval 0 ok
                              ///< \retval nonzero a plugin has handled the command

        ui_postprocess_action,///< cb: an ida ui action has been handled

        ui_set_custom_viewer_mode,
        ///< ui: switch between graph/text modes.
        ///< \param custom_viewer  (TWidget *)
        ///< \param graph_view     (bool)
        ///< \param silent         (bool)
        ///< \return bool success

        ui_gen_disasm_text,   ///< ui: see gen_disasm_text()

        ui_gen_idanode_text,  ///< cb: generate disassembly text for a node.
                              ///< Plugins may intercept this event and provide
                              ///< custom text for an IDA graph node
                              ///< They may use gen_disasm_text() for that.
                              ///< \param text  (text_t *)
                              ///< \param fc    (qflow_chart_t *)
                              ///< \param node  (int)
                              ///< \return bool text_has_been_generated

        ui_install_cli,       ///< ui: see:
                              ///< install_command_interpreter(),
                              ///< remove_command_interpreter()

        ui_execute_sync,      ///< ui: see execute_sync()

        ui_get_chooser_obj,   ///< ui: see get_chooser_obj()

        ui_enable_chooser_item_attrs,
        ///< ui: see enable_chooser_item_attrs()

        ui_get_chooser_item_attrs,
        ///< cb: get item-specific attributes for a chooser.
        ///< This callback is generated only after enable_chooser_attrs()
        ///< \param chooser  (const ::chooser_base_t *)
        ///< \param n        (::size_t)
        ///< \param attrs    (::chooser_item_attrs_t *)
        ///< \return void

        ui_set_dock_pos,      ///< ui: see set_dock_pos()

        ui_get_opnum,         ///< ui: see get_opnum()

        ui_install_custom_datatype_menu,
        ///< ui: install/remove custom data type menu item.
        ///< \param dtid     (int) data type id
        ///< \param install  (bool)
        ///< \return success

        ui_install_custom_optype_menu,
        ///< ui: install/remove custom operand type menu item.
        ///< \param fid      (int) format id
        ///< \param install  (bool)
        ///< \return success

        ui_get_range_marker,  ///< ui: Get pointer to function.
                              ///< see mark_range_for_refresh(ea_t, asize_t).
                              ///< This function will be called by the kernel when the
                              ///< database is changed
                              ///< \param none
                              ///< \return vptr: (idaapi*marker)(ea_t ea, asize_t) or nullptr

        ui_lookup_key_code,   ///< ui: see lookup_key_code()

        ui_load_custom_icon_file,
        ///< ui: see load_custom_icon(const char *)

        ui_load_custom_icon,  ///< ui: see load_custom_icon(const void *, unsigned int, const char *)

        ui_free_custom_icon,  ///< ui: see free_custom_icon()

        ui_process_action,    ///< ui: see process_ui_action()

        ui_create_code_viewer,///< ui: see create_code_viewer()

        ui_addons,            ///< ui: see \ref ui_addons_funcs

        ui_execute_ui_requests,
        ///< ui: see execute_ui_requests(ui_request_t, ...)

        ui_execute_ui_requests_list,
        ///< ui: see execute_ui_requests(ui_requests_t)

        ui_register_timer,    ///< ui: see register_timer()

        ui_unregister_timer,  ///< ui: see unregister_timer()

        ui_take_database_snapshot,
        ///< ui: see take_database_snapshot()

        ui_restore_database_snapshot,
        ///< ui: see restore_database_snapshot()

        ui_set_code_viewer_line_handlers,
        ///< ui: see set_code_viewer_line_handlers()

        ui_obsolete_refresh_custom_code_viewer,

        ui_create_source_viewer,
        ///< ui: Create new source viewer.
        ///< \param top_tl    (TWidget **) toplevel widget of created source viewer (can be nullptr)
        ///< \param parent    (TWidget *)
        ///< \param custview  (TWidget *)
        ///< \param path      (const char *)
        ///< \param lines     (strvec_t *)
        ///< \param lnnum     (int)
        ///< \param colnum    (int)
        ///< \param flags     (int) (\ref SVF_)
        ///< \return source_view_t *

        ui_get_tab_size,      ///< ui: see get_tab_size()

        ui_repaint_qwidget,   ///< ui: see repaint_custom_viewer()

        ui_custom_viewer_set_userdata,
        ///< ui: Change ::place_t user data for a custom view.
        ///< \param custom_viewer  (TWidget *)
        ///< \param user_data      (void *)
        ///< \return old user_data

        ui_jumpto,            ///< ui: see jumpto(ea_t, int, int)

        ui_cancel_exec_request,
        ///< ui: see cancel_exec_request()

        ui_open_form,         ///< ui: see vopen_form()

        ui_unrecognized_config_directive,
        ///< ui: Possibly handle an extra config directive,
        ///<   passed through '-d' or '-D'.
        ///< \param directive  (const char *) The config directive
        ///< \return char * - one of \ref IDPOPT_RET
        ///< See also register_cfgopts, which is better

        ui_get_output_cursor, ///< ui: see get_output_cursor()

        ui_get_output_curline,///< ui: see get_output_curline()

        ui_get_output_selected_text,
        ///< ui: see get_output_selected_text()

        ui_get_renderer_type, ///< ui: see get_view_renderer_type()

        ui_set_renderer_type, ///< ui: see set_view_renderer_type()

        ui_get_viewer_user_data,
        ///< ui: see get_viewer_user_data()

        ui_get_viewer_place_type,
        ///< ui: see get_viewer_place_type()

        ui_ea_viewer_history_push_and_jump,
        ///< ui: see ea_viewer_history_push_and_jump()

        ui_ea_viewer_history_info,
        ///< ui: see get_ea_viewer_history_info()

        ui_register_action,
        ///< ui: see register_action()

        ui_unregister_action,
        ///< ui: see unregister_action()

        ui_attach_action_to_menu,
        ///< ui: see attach_action_to_menu()

        ui_detach_action_from_menu,
        ///< ui: see detach_action_from_menu()

        ui_attach_action_to_popup,
        ///< ui: see attach_action_to_popup()

        ui_detach_action_from_popup,
        ///< ui: see detach_action_from_popup()

        ui_attach_dynamic_action_to_popup,
        ///< ui: see create attach_dynamic_action_to_popup()

        ui_attach_action_to_toolbar,
        ///< ui: see attach_action_to_toolbar()

        ui_detach_action_from_toolbar,
        ///< ui: see detach_action_from_toolbar()

        ui_updating_actions,  ///< cb: IDA is about to update all actions. If your plugin
                              ///< needs to perform expensive operations more than once
                              ///< (e.g., once per action it registers), you should do them
                              ///< only once, right away.
                              ///< \param ctx  (::action_update_ctx_t *)
                              ///< \return void

        ui_updated_actions,   ///< cb: IDA is done updating actions.
                              ///< \param none
                              ///< \return void

        ui_populating_widget_popup,
        ///< cb: IDA is populating the context menu for a widget.
        ///< This is your chance to attach_action_to_popup().
        ///<
        ///< Have a look at ui_finish_populating_widget_popup,
        ///< if you want to augment the
        ///< context menu with your own actions after the menu
        ///< has had a chance to be properly populated by the
        ///< owning component or plugin (which typically does it
        ///< on ui_populating_widget_popup.)
        ///<
        ///< \param widget        (TWidget *)
        ///< \param popup_handle  (TPopupMenu *)
        ///< \param ctx           (const action_activation_ctx_t *)
        ///< \return void
        ///<
        ///< ui: see ui_finish_populating_widget_popup

        ui_finish_populating_widget_popup,
        ///< cb: IDA is about to be done populating the
        ///< context menu for a widget.
        ///< This is your chance to attach_action_to_popup().
        ///<
        ///< \param widget        (TWidget *)
        ///< \param popup_handle  (TPopupMenu *)
        ///< \param ctx           (const action_activation_ctx_t *)
        ///< \return void
        ///<
        ///< ui: see ui_populating_widget_popup

        ui_update_action_attr,
        ///< ui: see \ref ui_uaa_funcs

        ui_get_action_attr,   ///< ui: see \ref ui_gaa_funcs

        ui_plugin_loaded,     ///< cb: The plugin was loaded in memory.
                              ///< \param plugin_info  (const ::plugin_info_t *)

        ui_plugin_unloading,  ///< cb: The plugin is about to be unloaded
                              ///< \param plugin_info  (const ::plugin_info_t *)

        ui_get_widget_type,  ///< ui: see get_widget_type()

        ui_current_widget_changed,
        ///< cb: The currently-active TWidget changed.
        ///< \param widget      (TWidget *)
        ///< \param prev_widget (TWidget *)
        ///< \return void

        ui_get_widget_title, ///< ui: see get_widget_title()

        ui_obsolete_get_user_strlist_options,
        ///< ui: see get_user_strlist_options()

        ui_create_custom_viewer,
        ///< ui: see create_viewer()

        ui_custom_viewer_jump,///< ui: set the current location, and have the viewer display it
                              ///< \param v     (TWidget *)
                              ///< \param loc   (const lochist_entry_t *)
                              ///< \param flags (uint32) or'ed combination of CVNF_* values
                              ///< \return success

        ui_set_custom_viewer_handlers,
        ///< ui: see set_custom_viewer_handlers()

        ui_get_registered_actions,
        ///< ui: see get_registered_actions()

        ui_create_toolbar,    ///< ui: see create_toolbar()
        ui_delete_toolbar,    ///< ui: see delete_toolbar()
        ui_create_menu,       ///< ui: see create_menu()
        ui_delete_menu,       ///< ui: see delete_menu()
        ui_obsolete_set_nav_colorizer,
        ui_get_chooser_data,  ///< ui: see get_chooser_data()
        ui_obsolete_get_highlight, ///< now ui_get_highlight_2
        ui_set_highlight,     ///< ui: see set_highlight()

        ui_set_mappings,      ///< ui: Show current memory mappings
                              ///<     and allow the user to change them.
        ui_create_empty_widget,
        ///< ui: see create_empty_widget()

        ui_msg_clear,         ///< ui: see msg_clear()
        ui_msg_save,          ///< ui: see msg_save()
        ui_msg_get_lines,     ///< ui: see msg_get_lines()

        ui_chooser_default_enter,
        ///< ui: jump to the address returned by get_ea() callback in the
        ///< case of the non-modal choosers
        ///< \param chooser  (const ::chooser_base_t *)
        ///< \param n/sel    (::size_t *)     for chooser_t
        ///<                 (::sizevec_t *)  for chooser_multi_t
        ///< \return int     chooser_t::cbres_t

        ui_screen_ea_changed,
        ///< cb: The "current address" changed
        ///< \param ea          (ea_t)
        ///< \param prev_ea     (ea_t)
        ///< \return void

        ui_get_active_modal_widget,
        ///< ui: see get_active_modal_widget()

        ui_navband_pixel,     ///< ui: see get_navband_pixel
        ui_navband_ea,        ///< ui: see get_navband_ea
        ui_get_window_id,     ///< ui: set get_window_id (GUI only)

        ui_create_desktop_widget,
        ///< cb: create a widget, to be placed in the widget tree (at desktop-creation time.)
        ///< \param title    (const char *)
        ///< \param cfg      (const jobj_t *)
        ///< \return TWidget * the created widget, or null

        ui_strchoose,         ///< ui: undocumented


        ui_set_nav_colorizer, ///< ui: see set_nav_colorizer()
        ui_display_widget,    ///< ui: see display_widget()

        ui_get_lines_rendering_info,
        ///< cb: get lines rendering information
        ///< \param out (lines_rendering_output_t *)
        ///< \param widget (const TWidget *)
        ///< \param info (const lines_rendering_input_t *)
        ///< \return void

        ui_sync_sources,
        ///< ui: [un]synchronize sources
        ///< \param what (const sync_source_t *)
        ///< \param with (const sync_source_t *)
        ///< \param sync (bool)
        ///< \return success

        ui_get_widget_config,   ///< cb: retrieve the widget configuration (it will be passed
                                ///< back at ui_create_desktop_widget-, and ui_set_widget_config-time)
                                ///< \param widget (const TWidget *)
                                ///< \param cfg (jobj_t *)
                                ///< \return void

        ui_set_widget_config,   ///< cb: set the widget configuration
                                ///< \param widget (const TWidget *)
                                ///< \param cfg (const jobj_t *)
                                ///< \return void

        ui_get_custom_viewer_location,
        ///< ui: see get_custom_viewer_location()
        ///< \param out (lochist_entry_t *)
        ///< \param custom_viewer (TWidget *)
        ///< \param mouse (bool)

        ui_initing_database,    ///< cb: database initialization has started.
                                ///< \return void
                                ///< See also ui_database_inited.
                                ///< This event is called for both new and old databases.

        ui_destroying_procmod,  ///< cb: The processor module is about to be destroyed
                                ///< \param procmod  (const ::procmod_t *)

        ui_destroying_plugmod,  ///< cb: The plugin object is about to be destroyed
                                ///< \param plugmod  (const ::plugmod_t *)
                                ///< \param entry  (const ::plugin_t *)

        ui_update_file_history, ///< ui: manipulate the file history
                                ///< \param add_path  (const char *)
                                ///< \param del_path  (const char *)

        ui_cancel_thread_exec_requests,
        ///< ui: see cancel_thread_exec_requests()

        ui_get_synced_group,
        ///< ui: see get_synced_group()

        ui_show_rename_dialog,  ///< ui: undocumented
                                ///< Rename address dialog -]
                                ///< \param        ea        (ea_t)
                                ///< \param        ndialog   (int) dialog number \ref RENADDR_DIALOGS
                                ///< \param[inout] hr_flags  (ushort *) additional flags
                                ///< \return success

        ui_desktop_applied,     ///< cb: a desktop has been applied
                                ///< \param name      (const char *) the desktop name
                                ///< \param from_idb  (bool) the desktop was stored in the IDB (false if it comes from the registry)
                                ///< \param type      (int) the desktop type (1-disassembly, 2-debugger, 3-merge)

        ui_choose_bookmark,
        ///< ui: modal chooser (legacy)
        ///< \param n     (uint32 *) input: default slot, output: chosen bookmark index
        ///< \param entry (const lochist_entry_t *) entry with place type
        ///< \param ud    (void *) user data

        ui_get_custom_viewer_place_xcoord,
        ///< ui: see get_custom_viewer_place_xcoord()

        ui_get_user_input_event,
        ///< ui: see get_user_input_event()

        ui_get_highlight_2,     ///< ui: see get_highlight()

        // -[
        ui_last,              ///< the last notification code

        ui_dbg_begin = 1000, ///< debugger callgates. should not be used directly, see dbg.hpp for details
        ui_dbg_run_requests = ui_dbg_begin,
        ui_dbg_get_running_request,
        ui_dbg_get_running_notification,
        ui_dbg_clear_requests_queue,
        ui_dbg_get_process_state,
        ui_dbg_start_process,
        ui_dbg_request_start_process,
        ui_dbg_suspend_process,
        ui_dbg_request_suspend_process,
        ui_dbg_continue_process,
        ui_dbg_request_continue_process,
        ui_dbg_exit_process,
        ui_dbg_request_exit_process,
        ui_dbg_get_thread_qty,
        ui_dbg_getn_thread,
        ui_dbg_select_thread,
        ui_dbg_request_select_thread,
        ui_dbg_step_into,
        ui_dbg_request_step_into,
        ui_dbg_step_over,
        ui_dbg_request_step_over,
        ui_dbg_run_to,
        ui_dbg_request_run_to,
        ui_dbg_step_until_ret,
        ui_dbg_request_step_until_ret,
        ui_dbg_get_bpt_qty,
        ui_dbg_add_oldbpt,
        ui_dbg_request_add_oldbpt,
        ui_dbg_del_oldbpt,
        ui_dbg_request_del_oldbpt,
        ui_dbg_enable_oldbpt,
        ui_dbg_request_enable_oldbpt,
        ui_dbg_set_trace_size,
        ui_dbg_clear_trace,
        ui_dbg_request_clear_trace,
        ui_dbg_is_step_trace_enabled,
        ui_dbg_enable_step_trace,
        ui_dbg_request_enable_step_trace,
        ui_dbg_get_step_trace_options,
        ui_dbg_set_step_trace_options,
        ui_dbg_request_set_step_trace_options,
        ui_dbg_is_insn_trace_enabled,
        ui_dbg_enable_insn_trace,
        ui_dbg_request_enable_insn_trace,
        ui_dbg_get_insn_trace_options,
        ui_dbg_set_insn_trace_options,
        ui_dbg_request_set_insn_trace_options,
        ui_dbg_is_func_trace_enabled,
        ui_dbg_enable_func_trace,
        ui_dbg_request_enable_func_trace,
        ui_dbg_get_func_trace_options,
        ui_dbg_set_func_trace_options,
        ui_dbg_request_set_func_trace_options,
        ui_dbg_get_tev_qty,
        ui_dbg_get_tev_info,
        ui_dbg_get_call_tev_callee,
        ui_dbg_get_ret_tev_return,
        ui_dbg_get_bpt_tev_ea,
        ui_dbg_get_reg_value_type,
        ui_dbg_get_processes,
        ui_dbg_attach_process,
        ui_dbg_request_attach_process,
        ui_dbg_detach_process,
        ui_dbg_request_detach_process,
        ui_dbg_get_first_module,
        ui_dbg_get_next_module,
        ui_dbg_bring_to_front,
        ui_dbg_get_current_thread,
        ui_dbg_wait_for_next_event,
        ui_dbg_get_debug_event,
        ui_dbg_set_debugger_options,
        ui_dbg_set_remote_debugger,
        ui_dbg_load_debugger,
        ui_dbg_retrieve_exceptions,
        ui_dbg_store_exceptions,
        ui_dbg_define_exception,
        ui_dbg_suspend_thread,
        ui_dbg_request_suspend_thread,
        ui_dbg_resume_thread,
        ui_dbg_request_resume_thread,
        ui_dbg_get_process_options,
        ui_dbg_check_bpt,
        ui_dbg_set_process_state,
        ui_dbg_get_manual_regions,
        ui_dbg_set_manual_regions,
        ui_dbg_enable_manual_regions,
        ui_dbg_set_process_options,
        ui_dbg_is_busy,
        ui_dbg_hide_all_bpts,
        ui_dbg_edit_manual_regions,
        ui_dbg_get_sp_val,
        ui_dbg_get_ip_val,
        ui_dbg_get_reg_val,
        ui_dbg_set_reg_val,
        ui_dbg_request_set_reg_val,
        ui_dbg_get_insn_tev_reg_val,
        ui_dbg_get_insn_tev_reg_result,
        ui_dbg_register_provider,
        ui_dbg_unregister_provider,
        ui_dbg_handle_debug_event,
        ui_dbg_add_vmod,
        ui_dbg_del_vmod,
        ui_dbg_compare_bpt_locs,
        ui_obsolete_dbg_save_bpts,
        ui_dbg_set_bptloc_string,
        ui_dbg_get_bptloc_string,
        ui_dbg_internal_appcall,
        ui_dbg_internal_cleanup_appcall,
        ui_dbg_internal_get_sreg_base,
        ui_dbg_internal_ioctl,
        ui_dbg_read_memory,
        ui_dbg_write_memory,
        ui_dbg_read_registers,
        ui_dbg_write_register,
        ui_dbg_get_memory_info,
        ui_dbg_get_event_cond,
        ui_dbg_set_event_cond,
        ui_dbg_enable_bpt,
        ui_dbg_request_enable_bpt,
        ui_dbg_del_bpt,
        ui_dbg_request_del_bpt,
        ui_dbg_map_source_path,
        ui_dbg_map_source_file_path,
        ui_dbg_modify_source_paths,
        ui_dbg_is_bblk_trace_enabled,
        ui_dbg_enable_bblk_trace,
        ui_dbg_request_enable_bblk_trace,
        ui_dbg_get_bblk_trace_options,
        ui_dbg_set_bblk_trace_options,
        ui_dbg_request_set_bblk_trace_options,
        // trace management
        ui_dbg_load_trace_file,
        ui_dbg_save_trace_file,
        ui_dbg_is_valid_trace_file,
        ui_dbg_set_trace_file_desc,
        ui_dbg_get_trace_file_desc,
        ui_dbg_choose_trace_file,
        ui_dbg_diff_trace_file,
        ui_dbg_graph_trace,
        ui_dbg_get_tev_memory_info,
        ui_dbg_get_tev_event,
        ui_dbg_get_insn_tev_reg_mem,
        // breakpoint management (new codes were introduced in v6.3)
        ui_dbg_getn_bpt,
        ui_dbg_get_bpt,
        ui_dbg_find_bpt,
        ui_dbg_add_bpt,
        ui_dbg_request_add_bpt,
        ui_dbg_update_bpt,
        ui_dbg_for_all_bpts,
        ui_dbg_get_tev_ea,
        ui_dbg_get_tev_type,
        ui_dbg_get_tev_tid,
        ui_dbg_get_trace_base_address,
        // calluis for creating traces from scratch (added in 6.4)
        ui_dbg_set_trace_base_address,
        ui_dbg_add_tev,
        ui_dbg_add_insn_tev,
        ui_dbg_add_call_tev,
        ui_dbg_add_ret_tev,
        ui_dbg_add_bpt_tev,
        ui_dbg_add_debug_event,
        ui_dbg_add_thread,
        ui_dbg_del_thread,
        ui_dbg_add_many_tevs,
        ui_dbg_set_bpt_group,
        ui_dbg_set_highlight_trace_options,
        ui_dbg_set_trace_platform,
        ui_dbg_get_trace_platform,
        // added in 6.6
        ui_dbg_internal_get_elang,
        ui_dbg_internal_set_elang,

        // added in 6.7
        ui_dbg_load_dbg_dbginfo,
        ui_dbg_set_resume_mode,
        ui_dbg_request_set_resume_mode,
        ui_dbg_set_bptloc_group,
        ui_dbg_list_bptgrps,
        ui_dbg_rename_bptgrp,
        ui_dbg_del_bptgrp,
        ui_dbg_get_grp_bpts,
        ui_dbg_get_bpt_group,
        ui_dbg_change_bptlocs,

        // added in 7.1
        ui_dbg_collect_stack_trace,
        ui_dbg_get_module_info,

        // source-level debugging
        ui_dbg_get_srcinfo_provider,
        ui_dbg_get_global_var,
        ui_dbg_get_local_var,
        ui_dbg_get_local_vars,
        ui_dbg_add_path_mapping,
        ui_dbg_get_current_source_file,
        ui_dbg_get_current_source_line,

        ui_dbg_srcdbg_step_into,
        ui_dbg_srcdbg_request_step_into,
        ui_dbg_srcdbg_step_over,
        ui_dbg_srcdbg_request_step_over,
        ui_dbg_srcdbg_step_until_ret,
        ui_dbg_srcdbg_request_step_until_ret,

        ui_dbg_getn_thread_name,
        ui_dbg_bin_search,

        ui_dbg_get_insn_tev_reg_val_i,
        ui_dbg_get_insn_tev_reg_result_i,
        ui_dbg_get_reg_val_i,
        ui_dbg_set_reg_val_i,

        ui_dbg_get_reg_info,

        ui_dbg_set_trace_dynamic_register_set,
        ui_dbg_get_trace_dynamic_register_set,

        // added in 7.7
        ui_dbg_enable_bptgrp,

        ui_dbg_end,

        // Debugging notifications
        debug_obsolete_assert_thread_waitready = ui_dbg_end
    }
}
