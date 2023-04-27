use super::{desc::Desc, errno::*, *};
#[cfg(not(debug_assertions))]
use crate::common::is_server;
use crate::{flutter, ui_interface::get_id};
use hbb_common::{
    allow_err, bail,
    dlopen::symbor::Library,
    lazy_static, log,
    message_proto::{Message, Misc, PluginResponse},
    ResultType,
};
use std::{
    collections::HashMap,
    ffi::{c_char, c_void},
    path::PathBuf,
    sync::{Arc, RwLock},
};

const METHOD_HANDLE_UI: &[u8; 10] = b"handle_ui\0";
const METHOD_HANDLE_PEER: &[u8; 12] = b"handle_peer\0";

lazy_static::lazy_static! {
    static ref PLUGIN_INFO: Arc<RwLock<HashMap<String, PluginInfo>>> = Default::default();
    pub static ref PLUGINS: Arc<RwLock<HashMap<String, Plugin>>> = Default::default();
    pub static ref LOCAL_PEER_ID: Arc<RwLock<String>> = Default::default();
}

struct PluginInfo {
    path: String,
    desc: Desc,
}

/// Initialize the plugins.
///
/// Return null ptr if success.
/// Return the error message if failed.  `i32-String` without dash, i32 is a signed little-endian number, the String is utf8 string.
/// The plugin allocate memory with `libc::malloc` and return the pointer.
pub type PluginFuncInit = fn() -> *const c_void;
/// Reset the plugin.
///
/// Return null ptr if success.
/// Return the error message if failed.  `i32-String` without dash, i32 is a signed little-endian number, the String is utf8 string.
/// The plugin allocate memory with `libc::malloc` and return the pointer.
pub type PluginFuncReset = fn() -> *const c_void;
/// Clear the plugin.
///
/// Return null ptr if success.
/// Return the error message if failed.  `i32-String` without dash, i32 is a signed little-endian number, the String is utf8 string.
/// The plugin allocate memory with `libc::malloc` and return the pointer.
pub type PluginFuncClear = fn() -> *const c_void;
/// Get the description of the plugin.
/// Return the description. The plugin allocate memory with `libc::malloc` and return the pointer.
pub type PluginFuncDesc = fn() -> *const c_char;
/// Callback to send message to peer or ui.
/// peer, target, id are utf8 strings(null terminated).
///
/// peer:    The peer id.
/// target:  "peer" or "ui".
/// id:      The id of this plugin.
/// content: The content.
/// len:     The length of the content.
type CallbackMsg = fn(
    peer: *const c_char,
    target: *const c_char,
    id: *const c_char,
    content: *const c_void,
    len: usize,
);
/// Callback to get the id of local peer id.
/// The returned string is utf8 string(null terminated).
/// Don't free the returned ptr.
type CallbackGetId = fn() -> *const c_char;
/// Callback to get the config.
/// peer, key are utf8 strings(null terminated).
///
/// peer: The peer id.
/// id:  The id of this plugin.
/// key:  The key of the config.
///
/// The returned string is utf8 string(null terminated) and must be freed by caller.
type CallbackGetConf =
    fn(peer: *const c_char, id: *const c_char, key: *const c_char) -> *const c_char;
/// The main function of the plugin.
/// method: The method. "handle_ui" or "handle_peer"
/// peer:  The peer id.
/// args: The arguments.
///
/// Return null ptr if success.
/// Return the error message if failed.  `i32-String` without dash, i32 is a signed little-endian number, the String is utf8 string.
/// The plugin allocate memory with `libc::malloc` and return the pointer.
pub type PluginFuncCall = fn(
    method: *const c_char,
    peer: *const c_char,
    args: *const c_void,
    len: usize,
) -> *const c_void;

#[repr(C)]
struct Callbacks {
    msg: CallbackMsg,
    get_id: CallbackGetId,
    get_conf: CallbackGetConf,
}
type PluginFuncSetCallbacks = fn(Callbacks);

macro_rules! make_plugin {
    ($($field:ident : $tp:ty),+) => {
        #[allow(dead_code)]
        pub struct Plugin {
            _lib: Library,
            id: Option<String>,
            path: String,
            $($field: $tp),+
        }

        impl Plugin {
            fn new(path: &str) -> ResultType<Self> {
                let lib = match Library::open(path) {
                    Ok(lib) => lib,
                    Err(e) => {
                        bail!("Failed to load library {}, {}", path, e);
                    }
                };

                $(let $field = match unsafe { lib.symbol::<$tp>(stringify!($field)) } {
                        Ok(m) => {
                            log::debug!("{} method found {}", path, stringify!($field));
                            *m
                        },
                        Err(e) => {
                            bail!("Failed to load {} func {}, {}", path, stringify!($field), e);
                        }
                    }
                ;)+

                Ok(Self {
                    _lib: lib,
                    id: None,
                    path: path.to_string(),
                    $( $field ),+
                })
            }

            fn desc(&self) -> ResultType<Desc> {
                let desc_ret = (self.desc)();
                let desc = Desc::from_cstr(desc_ret);
                free_c_ptr(desc_ret as _);
                desc
            }

            fn init(&self, path: &str) -> ResultType<()> {
                let init_ret = (self.init)();
                if !init_ret.is_null() {
                    let (code, msg) = get_code_msg_from_ret(init_ret);
                    free_c_ptr(init_ret as _);
                    bail!(
                        "Failed to init plugin {}, code: {}, msg: {}",
                        path,
                        code,
                        msg
                    );
                }
                Ok(())
            }

            fn clear(&self, id: &str) {
                let clear_ret = (self.clear)();
                if !clear_ret.is_null() {
                    let (code, msg) = get_code_msg_from_ret(clear_ret);
                    free_c_ptr(clear_ret as _);
                    log::error!(
                        "Failed to clear plugin {}, code: {}, msg: {}",
                        id,
                        code,
                        msg
                    );
                }
            }
        }

        impl Drop for Plugin {
            fn drop(&mut self) {
                let id = self.id.as_ref().unwrap_or(&self.path);
                self.clear(id);
            }
        }
    }
}

make_plugin!(
    init: PluginFuncInit,
    reset: PluginFuncReset,
    clear: PluginFuncClear,
    desc: PluginFuncDesc,
    call: PluginFuncCall,
    set_cbs: PluginFuncSetCallbacks
);

#[cfg(target_os = "windows")]
const DYLIB_SUFFIX: &str = ".dll";
#[cfg(target_os = "linux")]
const DYLIB_SUFFIX: &str = ".so";
#[cfg(target_os = "macos")]
const DYLIB_SUFFIX: &str = ".dylib";

pub fn load_plugins() -> ResultType<()> {
    let exe = std::env::current_exe()?.to_string_lossy().to_string();
    match PathBuf::from(&exe).parent() {
        Some(dir) => {
            for entry in std::fs::read_dir(dir)? {
                match entry {
                    Ok(entry) => {
                        let path = entry.path();
                        if path.is_file() {
                            let filename = entry.file_name();
                            let filename = filename.to_str().unwrap_or("");
                            if filename.starts_with("plugin_") && filename.ends_with(DYLIB_SUFFIX) {
                                if let Err(e) = load_plugin(Some(path.to_str().unwrap_or("")), None)
                                {
                                    log::error!("Failed to load plugin {}, {}", filename, e);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        log::error!("Failed to read dir entry, {}", e);
                    }
                }
            }
            Ok(())
        }
        None => {
            bail!("Failed to get parent dir of {}", exe);
        }
    }
}

pub fn unload_plugins() {
    log::info!("Plugins unloaded");
    PLUGINS.write().unwrap().clear();
    if change_manager() {
        super::config::ManagerConfig::remove_plugins(false);
    }
}

pub fn unload_plugin(id: &str) {
    log::info!("Plugin {} unloaded", id);
    PLUGINS.write().unwrap().remove(id);
    if change_manager() {
        allow_err!(super::config::ManagerConfig::remove_plugin(id, false));
    }
}

pub fn reload_plugin(id: &str) -> ResultType<()> {
    let path = match PLUGIN_INFO.read().unwrap().get(id) {
        Some(plugin) => plugin.path.clone(),
        None => bail!("Plugin {} not found", id),
    };
    unload_plugin(id);
    load_plugin(Some(&path), Some(id))
}

#[no_mangle]
fn cb_get_local_peer_id() -> *const c_char {
    let mut id = (*LOCAL_PEER_ID.read().unwrap()).clone();
    if id.is_empty() {
        let mut lock = LOCAL_PEER_ID.write().unwrap();
        id = (*lock).clone();
        if id.is_empty() {
            id = get_id();
            id.push('\0');
            *lock = id.clone();
        }
    }
    id.as_ptr() as _
}

fn load_plugin_path(path: &str) -> ResultType<()> {
    let plugin = Plugin::new(path)?;
    let desc = plugin.desc()?;

    // to-do validate plugin
    // to-do check the plugin id (make sure it does not use another plugin's id)

    plugin.init(path)?;

    if change_manager() {
        super::config::ManagerConfig::add_plugin(desc.id())?;
    }

    // set callbacks
    (plugin.set_cbs)(Callbacks {
        msg: callback_msg::cb_msg,
        get_id: cb_get_local_peer_id,
        get_conf: config::cb_get_conf,
    });

    // update ui
    // Ui may be not ready now, so we need to update again once ui is ready.
    update_ui_plugin_desc(&desc, None);
    reload_ui(&desc, None);

    // add plugins
    let id = desc.id().to_string();
    let plugin_info = PluginInfo {
        path: path.to_string(),
        desc,
    };
    PLUGIN_INFO.write().unwrap().insert(id.clone(), plugin_info);
    PLUGINS.write().unwrap().insert(id.clone(), plugin);

    log::info!("Plugin {} loaded", id);
    Ok(())
}

pub fn sync_ui(sync_to: String) {
    for plugin in PLUGIN_INFO.read().unwrap().values() {
        update_ui_plugin_desc(&plugin.desc, Some(&sync_to));
        reload_ui(&plugin.desc, Some(&sync_to));
    }
}

pub fn load_plugin(path: Option<&str>, id: Option<&str>) -> ResultType<()> {
    match (path, id) {
        (Some(path), _) => load_plugin_path(path),
        (None, Some(id)) => {
            let path = match PLUGIN_INFO.read().unwrap().get(id) {
                Some(plugin) => plugin.path.clone(),
                None => bail!("Plugin {} not found", id),
            };
            load_plugin_path(&path)
        }
        (None, None) => {
            bail!("path and id are both None");
        }
    }
}

fn handle_event(method: &[u8], id: &str, peer: &str, event: &[u8]) -> ResultType<()> {
    let mut peer: String = peer.to_owned();
    peer.push('\0');
    match PLUGINS.read().unwrap().get(id) {
        Some(plugin) => {
            let ret = (plugin.call)(
                method.as_ptr() as _,
                peer.as_ptr() as _,
                event.as_ptr() as _,
                event.len(),
            );
            if ret.is_null() {
                Ok(())
            } else {
                let (code, msg) = get_code_msg_from_ret(ret);
                free_c_ptr(ret as _);
                bail!(
                    "Failed to handle plugin event, id: {}, method: {}, code: {}, msg: {}",
                    id,
                    std::string::String::from_utf8(method.to_vec()).unwrap_or_default(),
                    code,
                    msg
                );
            }
        }
        None => bail!("Plugin {} not found", id),
    }
}

#[inline]
pub fn handle_ui_event(id: &str, peer: &str, event: &[u8]) -> ResultType<()> {
    handle_event(METHOD_HANDLE_UI, id, peer, event)
}

#[inline]
pub fn handle_server_event(id: &str, peer: &str, event: &[u8]) -> ResultType<()> {
    handle_event(METHOD_HANDLE_PEER, id, peer, event)
}

#[inline]
pub fn handle_client_event(id: &str, peer: &str, event: &[u8]) -> Option<Message> {
    let mut peer: String = peer.to_owned();
    peer.push('\0');
    match PLUGINS.read().unwrap().get(id) {
        Some(plugin) => {
            let ret = (plugin.call)(
                METHOD_HANDLE_PEER.as_ptr() as _,
                peer.as_ptr() as _,
                event.as_ptr() as _,
                event.len(),
            );
            if ret.is_null() {
                None
            } else {
                let (code, msg) = get_code_msg_from_ret(ret);
                free_c_ptr(ret as _);
                if code > ERR_RUSTDESK_HANDLE_BASE && code < ERR_PLUGIN_HANDLE_BASE {
                    let name = match PLUGIN_INFO.read().unwrap().get(id) {
                        Some(plugin) => plugin.desc.name(),
                        None => "???",
                    }
                    .to_owned();
                    match code {
                        ERR_CALL_NOT_SUPPORTED_METHOD => Some(make_plugin_response(
                            id,
                            &name,
                            "plugin method is not supported",
                        )),
                        ERR_CALL_INVALID_ARGS => Some(make_plugin_response(
                            id,
                            &name,
                            "plugin arguments is invalid",
                        )),
                        _ => Some(make_plugin_response(id, &name, &msg)),
                    }
                } else {
                    log::error!(
                        "Failed to handle client event, code: {}, msg: {}",
                        code,
                        msg
                    );
                    None
                }
            }
        }
        None => Some(make_plugin_response(id, "", "plugin not found")),
    }
}

fn make_plugin_response(id: &str, name: &str, msg: &str) -> Message {
    let mut misc = Misc::new();
    misc.set_plugin_response(PluginResponse {
        id: id.to_owned(),
        name: name.to_owned(),
        msg: msg.to_owned(),
        ..Default::default()
    });
    let mut msg_out = Message::new();
    msg_out.set_misc(misc);
    msg_out
}

#[inline]
fn change_manager() -> bool {
    #[cfg(debug_assertions)]
    let change_manager = true;
    #[cfg(not(debug_assertions))]
    let change_manager = is_server();
    change_manager
}

fn reload_ui(desc: &Desc, sync_to: Option<&str>) {
    for (location, ui) in desc.location().ui.iter() {
        if let Ok(ui) = serde_json::to_string(&ui) {
            let make_event = |ui: &str| {
                let mut m = HashMap::new();
                m.insert("name", MSG_TO_UI_TYPE_PLUGIN_RELOAD);
                m.insert("id", desc.id());
                m.insert("location", &location);
                // Do not depend on the "location" and plugin desc on the ui side.
                // Send the ui field to ensure the ui is valid.
                m.insert("ui", ui);
                serde_json::to_string(&m).unwrap_or("".to_owned())
            };
            match sync_to {
                Some(channel) => {
                    let _res = flutter::push_global_event(channel, make_event(&ui));
                }
                None => {
                    let v: Vec<&str> = location.split('|').collect();
                    // The first element is the "client" or "host".
                    // The second element is the "main", "remote", "cm", "file transfer", "port forward".
                    if v.len() >= 2 {
                        let available_channels = vec![
                            flutter::APP_TYPE_MAIN,
                            flutter::APP_TYPE_DESKTOP_REMOTE,
                            flutter::APP_TYPE_CM,
                            flutter::APP_TYPE_DESKTOP_FILE_TRANSFER,
                            flutter::APP_TYPE_DESKTOP_PORT_FORWARD,
                        ];
                        if available_channels.contains(&v[1]) {
                            let _res = flutter::push_global_event(v[1], make_event(&ui));
                        }
                    }
                }
            }
        }
    }
}

fn update_ui_plugin_desc(desc: &Desc, sync_to: Option<&str>) {
    // This function is rarely used. There's no need to care about serialization efficiency here.
    if let Ok(desc_str) = serde_json::to_string(desc) {
        let mut m = HashMap::new();
        m.insert("name", MSG_TO_UI_TYPE_PLUGIN_DESC);
        m.insert("desc", &desc_str);
        let event = serde_json::to_string(&m).unwrap_or("".to_owned());
        match sync_to {
            Some(channel) => {
                let _res = flutter::push_global_event(channel, event.clone());
            }
            None => {
                let _res = flutter::push_global_event(flutter::APP_TYPE_MAIN, event.clone());
                let _res =
                    flutter::push_global_event(flutter::APP_TYPE_DESKTOP_REMOTE, event.clone());
                let _res = flutter::push_global_event(flutter::APP_TYPE_CM, event.clone());
            }
        }
    }
}

pub(super) fn get_desc_conf(id: &str) -> Option<super::desc::Config> {
    PLUGIN_INFO
        .read()
        .unwrap()
        .get(id)
        .map(|info| info.desc.config().clone())
}
