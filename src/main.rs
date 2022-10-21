// Specify the Windows subsystem to eliminate console window.
// Requires Rust 1.18.
//..
#![windows_subsystem = "windows"]

use librustdesk::*;

#[cfg(any(target_os = "android", target_os = "ios"))]
fn main() {
    if !common::global_init() {
        return;
    }
    common::test_rendezvous_server();
    common::test_nat_type();
    #[cfg(target_os = "android")]
    crate::common::check_software_update();
    common::global_clean();
}


#[cfg(not(any(target_os = "android", target_os = "ios", feature = "cli")))]
fn main() {
    #[cfg(debug_assertions)]
    {
        //..m======0
        //..w======0
        {
            use std::io::Write;
    
            println!("======================0");
            std::io::stdout().flush().unwrap();
            
            //platform::macos::is_can_screen_recording(false);
        }
        #[cfg(windows)]
        {
            use std::io::Write;
    
            let mut path = std::env::current_exe().unwrap_or_default();
            path.pop();
    
            if let Ok(mut file) = std::fs::OpenOptions::new().write(true).create(true).append(true).open(&format!(
                "{}/rustdesk.log", path.to_str().unwrap_or_default())) {
                writeln!(&mut file, "======================0\n{}\n", std::process::id()).unwrap();
            }
        }
        #[cfg(windows)]
        unsafe {
            let name  = "kernel32.dll\0";
            let  dll  : isize =  winapi::um::libloaderapi::LoadLibraryA( name.as_ptr() as winapi::um::winnt::LPCSTR) as isize;
    
            let name = "OutputDebugStringA\0";
            let proc : winapi::shared::minwindef::FARPROC = winapi::um::libloaderapi::GetProcAddress(dll as winapi::shared::minwindef::HMODULE, name.as_ptr() as winapi::um::winnt::LPCSTR);
            let func : extern "stdcall" fn(winapi::um::winnt::LPCSTR) = std::mem::transmute(proc);
    
            let name  = "======================0\n\0";
            func(name.as_ptr() as winapi::um::winnt::LPCSTR);
            let name  = std::format!("{}\n\0", std::process::id());
            func(name.as_ptr() as winapi::um::winnt::LPCSTR);
            winapi::um::libloaderapi::FreeLibrary(dll as winapi::shared::minwindef::HMODULE);
        }
        #[cfg(windows)]
        unsafe {
            let event_log : winapi::um::winnt::HANDLE = winapi::um::winbase::RegisterEventSourceA(winapi::shared::ntdef::NULL as winapi::um::winnt::LPCSTR, "EchoServer\0".as_ptr() as winapi::um::winnt::LPCSTR);
            let mut bytes : Vec<u8> = std::format!("======================0\n").to_string().into_bytes();
            bytes.append(&mut std::format!("{} \n\0", std::process::id()).to_string().into_bytes());
            let mut message = bytes.as_ptr() as winapi::um::winnt::LPCSTR;
            winapi::um::winbase::ReportEventA(event_log, winapi::um::winnt::EVENTLOG_INFORMATION_TYPE, 0, 0xC0020100, winapi::shared::ntdef::NULL, 1, 0, &mut message, winapi::shared::ntdef::NULL);
            winapi::um::winbase::DeregisterEventSource(event_log);
        }    
    }

    if !common::global_init() {
        return;
    }

    if let Some(args) = crate::core_main::core_main().as_mut() {
        ui::start(args);
    }
    common::global_clean();
}

#[cfg(feature = "cli")]
fn main() {
    if !common::global_init() {
        return;
    }
    use hbb_common::log;
    use clap::App;
    let args = format!(
        "-p, --port-forward=[PORT-FORWARD-OPTIONS] 'Format: remote-id:local-port:remote-port[:remote-host]'
        -k, --key=[KEY] ''
       -s, --server... 'Start server'",
    );
    let matches = App::new("rustdesk")
        .version(crate::VERSION)
        .author("CarrieZ Studio<info@rustdesk.com>")
        .about("RustDesk command line tool")
        .args_from_usage(&args)
        .get_matches();
    use hbb_common::{env_logger::*, config::LocalConfig};
    init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "info"));
    if let Some(p) = matches.value_of("port-forward") {
        let options: Vec<String> = p.split(":").map(|x| x.to_owned()).collect();
        if options.len() < 3 {
            log::error!("Wrong port-forward options");
            return;
        }
        let mut port = 0;
        if let Ok(v) = options[1].parse::<i32>() {
            port = v;
        } else {
            log::error!("Wrong local-port");
            return;
        }
        let mut remote_port = 0;
        if let Ok(v) = options[2].parse::<i32>() {
            remote_port = v;
        } else {
            log::error!("Wrong remote-port");
            return;
        }
        let mut remote_host = "localhost".to_owned();
        if options.len() > 3 {
            remote_host = options[3].clone();
        }
        let key = matches.value_of("key").unwrap_or("").to_owned();
        let token = LocalConfig::get_option("access_token");
        cli::start_one_port_forward(options[0].clone(), port, remote_host, remote_port, key, token);
    }
    common::global_clean();
}