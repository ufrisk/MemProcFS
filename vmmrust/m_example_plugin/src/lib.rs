// lib.rs - MemProcFS Plugin Example
//
// The example will show up under /rust/example both at the root and per-process.
// The process views are dependent on the process PID and type.
// 
// The plugin will not show up in kernel-mode processes.
// The plugin will show the 024 directory for PIDs ending in those numbers.
// The plugin will show the 68 directory for PIDs ending in those numbers.
// The root folder have a readme.txt as a read-only file.
// The sub-folders will have a writeme.txt as a read/write file.
//
// (c) Ulf Frisk, 2023-2025
// Author: Ulf Frisk, pcileech@frizk.net
// https://github.com/ufrisk/MemProcFS
//

use memprocfs::*;
use anyhow::anyhow;

const PLUGIN_README : &str =
    "This is a MemProcFS example plugin for Rust.\n\
    --------------------------------------------\n\
    Please check the plugin source code for info\n\
    Or visit https://github.com/ufrisk/MemProcFS\n";

const PLUGIN_README_024_WRITABLE : &str =
    "This is a writable file in the MemProcFS Rust example plugin.\n\
    The file should _not_ show up in processes which pid doesn't  \n\
    end with the numbers 6 or 8.                                  \n";

const PLUGIN_README_68_WRITABLE : &str =
    "This is a writable file in the MemProcFS Rust example plugin.   \n\
    The file should show up in processes which pids ends with 6 or 8.\n";



// User-defined plugin context.
struct PluginContext {
    id : u32,
    file_024 : Vec<u8>,
    file_68 : Vec<u8>,
}



/// MemProcFS plugin main entry point:
/// 
/// The native VMM library will call this function when the plugin should be
/// initialized. The function should start by making a call to the plugin API
/// initializing the MemProcFS rust sub-system before doing anything else.
#[no_mangle]
pub extern "C" fn InitializeVmmPlugin(native_h : usize, native_reginfo : usize) {
    // First line of initialization function:
    // Retrieve system information and the plugin init context from native layer.
    // Note the generic type T which allows the init function to initialize a
    // plugin specific context which will be shared between callbacks.
    let (system_info, mut plugin_init_ctx) =
        match new_plugin_initialization::<PluginContext>(native_h, native_reginfo) {
            Ok(r) => r,
            Err(_) => return,
        };

    // The system_info may be used to check whether the plugin should run or not.
    // It's important that this function is fast! General API usage is possibele
    // to further check whether the plugin should be run or not, but is discouraged
    // due to added overhead. Ideally only the system_info should be used.
    // In this example do not allow plugin to run on Windows Vista and older.
    if system_info.version_build < 7600 {
        return;
    }

    // Initialize the plugin by setting the custom plugin context and also
    // callback functions. Callback functions may be called in multi-threaded
    // mode and the custom plugin context will be serialized behind a RwLock to
    // avoid race conditions.
    // This module is a root module which will show up under /rust/example in
    // the MemProcFS virtual file system.
    let ctx = PluginContext {
        id : 1337,
        file_024 : PLUGIN_README_024_WRITABLE.as_bytes().to_vec(),
        file_68 : PLUGIN_README_68_WRITABLE.as_bytes().to_vec(),
    };
    plugin_init_ctx.ctx = Some(ctx);
    plugin_init_ctx.is_root_module = true;
    plugin_init_ctx.is_process_module = true;
    plugin_init_ctx.path_name = String::from("/rust/example");

    // Populate the plugin_init_ctx with implemented functions.
    // list/read/write is commonly implemented (even if no requirement)
    // while notify/visible is more rare and used in special circumstances.
    plugin_init_ctx.fn_list = Some(plugin_list_cb);
    plugin_init_ctx.fn_read = Some(plugin_read_cb);
    plugin_init_ctx.fn_write = Some(plugin_write_cb);
    plugin_init_ctx.fn_notify = Some(plugin_notify_cb);
    plugin_init_ctx.fn_visible = Some(plugin_visible_cb);

    // Register the plugin with MemProcFS. This will consume the context which
    // should not be possible to use after this.
    let _r = plugin_init_ctx.register();

    // Sometimes one may wish to register additional plugins. This is possible.
    // Simply call new_plugin_initialization() to retrieve a new
    // plugin initialzation context and start anew.
    //
    // let (system_info, mut plugin_init_ctx) =
    //     match new_plugin_initialization::<u32>(native_h, native_reginfo) {
    //         Ok(r) => r,
    //         Err(_) => return,
    //     };
    // ...
    // let _r = plugin_init_ctx.register();
}



// Example: Plugin VFS list Callback:
//
// The list callback should populate the directory that is queried by path.
//
// It is important that the list callback is fast. Any longer running tasks
// should be spawn into a separate thread so that the file system doesn't
// freeze waiting for the list callback to complete processing.
fn plugin_list_cb(ctxp : &VmmPluginContext<PluginContext>, process : Option<VmmProcess>, path : &str, file_list : &VmmPluginFileList) -> ResultEx<()> {
    // The user-defined is stored behind a RwLock that may be locked for either read() or write().
    // All callbacks may happen in multi-threaded mode so locking is important!
    let mut ctx_user = ctxp.ctxlock.write().unwrap();
    let mut is_pid_024 = true;
    let mut is_pid_68 = true;
    if let Some(process) = process {
        is_pid_024 = ((process.pid % 10) == 0) || ((process.pid % 10) == 2) || ((process.pid % 10) == 4);
        is_pid_68 = ((process.pid % 10) == 6) || ((process.pid % 10) == 8);
    }
    // root folder:
    if path.len() == 0 {
        ctx_user.id += 1;
        let id_string = ctx_user.id.to_string();
        file_list.add_file("readme.txt", PLUGIN_README.len() as u64);
        file_list.add_file("numeric_list_counter.txt", id_string.len() as u64);
        if is_pid_024 {
            file_list.add_directory("024");
        }
        if is_pid_68 {
            file_list.add_directory("68");
        }
        return Ok(());
    }
    // 024 folder:
    if path.eq_ignore_ascii_case("024") {
        file_list.add_file("writeme_024.txt", ctx_user.file_024.len() as u64);
        return Ok(());
    }
    // 68 folder:
    if path.eq_ignore_ascii_case("68") {
        file_list.add_file("writeme_68.txt", ctx_user.file_68.len() as u64);
        return Ok(());
    }
    return Ok(());
}



// Example: Plugin VFS read Callback:
//
// The read callback should return the read data as a vectorized byte-array.
// If the read is past the file size an empty vector should be returned.
// If the file does not exist an error should be returned.
fn plugin_read_cb(ctxp : &VmmPluginContext<PluginContext>, _process : Option<VmmProcess>, file_name : &str, cb : u32, cb_offset : u64) -> ResultEx<Vec<u8>> {
    let ctx_user = ctxp.ctxlock.read().unwrap();
    let data_vec;
    let data;
    // check which file to read:
    if file_name.eq_ignore_ascii_case("readme.txt") {
        data_vec = Vec::from(PLUGIN_README);
        data = &data_vec;
    } else if file_name.eq_ignore_ascii_case("numeric_list_counter.txt") {
        data_vec = Vec::from(ctx_user.id.to_string());
        data = &data_vec;
    } else if file_name.eq_ignore_ascii_case("024/writeme_024.txt") {
        data = &ctx_user.file_024;
    } else if file_name.eq_ignore_ascii_case("68/writeme_68.txt") {
        data = &ctx_user.file_68;
    } else {
        return Err(anyhow!("[err]"));
    }
    // read from file:
    let file_offset_base = usize::try_from(cb_offset)?;
    let file_offset_top = std::cmp::min(data.len(), file_offset_base + usize::try_from(cb)?);
    if file_offset_base > data.len() {
        return Ok(Vec::new());
    }
    let r = (&data[file_offset_base..file_offset_top]).to_vec();
    return Ok(r);
}



// Example: Plugin VFS write Callback:
//
// The write callback should return success always even if no data is written.
// Errors may be returned when files are missing and in rare error propagation cases.
fn plugin_write_cb(ctxp : &VmmPluginContext<PluginContext>, _process : Option<VmmProcess>, file_name : &str, data : Vec<u8>, cb_offset : u64) -> ResultEx<()> {
    let mut ctx_user = ctxp.ctxlock.write().unwrap();
    let file_offset_base = usize::try_from(cb_offset)?;
    // check which file to write:
    if file_name.eq_ignore_ascii_case("024/writeme_024.txt") {
        let file_offset_top = std::cmp::min(ctx_user.file_024.len(), file_offset_base + data.len());
        let file_copy_len = file_offset_top - file_offset_base;
        if (file_offset_base > data.len()) || (file_copy_len == 0)  {
            return Ok(());
        }
        for i in 0..file_copy_len {
            ctx_user.file_024[file_offset_base + i] = data[i];
        }
    } else if file_name.eq_ignore_ascii_case("68/writeme_68.txt") {
        let file_offset_top = std::cmp::min(ctx_user.file_68.len(), file_offset_base + data.len());
        let file_copy_len = file_offset_top - file_offset_base;
        if (file_offset_base > data.len()) || (file_copy_len == 0)  {
            return Ok(());
        }
        for i in 0..file_copy_len {
            ctx_user.file_68[file_offset_base + i] = data[i];
        }
    } else {
        return Err(anyhow!("[err]"));
    }
    return Ok(());
}



// Example: Plugin VFS dynamic visibility Callback:
//
// This should almost never be used! It is only used in the cases when it's
// desirable to have dynamic plugin visiblity in select processes.
//
// In this example the plugin is shown in the root and in user-mode processes -
// but it should be hidden in kernel mode processes.
fn plugin_visible_cb(_ctxp : &VmmPluginContext<PluginContext>, process : Option<VmmProcess>) -> ResultEx<bool> {
    if process.is_some() {
        if let Ok(info) = process.unwrap().info() {
            return Ok(info.is_user_mode);
        }
    }
    return Ok(true);
}



// Example: Plugin Notification Callback:
//
// MemProcFS will send notification at some events to subscribers.
// These notifications are stored in constants: PLUGIN_NOTIFY_*
//
// Some times it's desirable to take an action on a notification,
// such as changing plugin visibility when forensic mode is complete,
// or throw away cached data at PLUGIN_NOTIFY_REFRESH_SLOW.
fn plugin_notify_cb(ctxp : &VmmPluginContext<PluginContext>, event_id : u32) -> ResultEx<()> {
    // Throw away changes to files if there is a slow (complete) refresh.
    // NB! this does only happen on dynamic memory (not on memory dump files).
    if event_id == PLUGIN_NOTIFY_REFRESH_SLOW {
        let mut ctx_user: std::sync::RwLockWriteGuard<'_, PluginContext> = ctxp.ctxlock.write().unwrap();
        ctx_user.file_024 = PLUGIN_README_024_WRITABLE.as_bytes().to_vec();
        ctx_user.file_68 = PLUGIN_README_68_WRITABLE.as_bytes().to_vec();
    }
    return Ok(());
}
