use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::thread;
use std::time::Duration;
use sysinfo::{Pid, System};

#[cfg(windows)]
use std::ptr;
#[cfg(windows)]
use winapi::um::synchapi::CreateMutexW;
#[cfg(windows)]
use winapi::um::errhandlingapi::GetLastError;
#[cfg(windows)]
use winapi::shared::winerror::ERROR_ALREADY_EXISTS;

#[derive(Debug, Deserialize, Serialize)]
struct Config {
    monitor_directory: String,
    target_exe: String,
    kill_exe: String,
    check_interval_ms: u64,
    #[serde(default)]
    auto_start: bool,
}

impl Config {
    fn load() -> Result<Self, Box<dyn std::error::Error>> {
        let config_str = fs::read_to_string("config.json")?;
        let config: Config = serde_json::from_str(&config_str)?;
        Ok(config)
    }
}

struct KillNeac {
    config: Config,
    system: System,
    target_pid: Option<Pid>,
    log_file: Option<std::fs::File>,
}

impl KillNeac {
    fn new(config: Config) -> Self {
        let log_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open("monitor.log")
            .ok();
        
        Self {
            config,
            system: System::new_all(),
            target_pid: None,
            log_file,
        }
    }

    fn log(&mut self, msg: String) {
        let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
        let log_msg = format!("[{}] {}\n", timestamp, msg);
        
        if let Some(ref mut file) = self.log_file {
            let _ = file.write_all(log_msg.as_bytes());
            let _ = file.flush();
        }
    }

    fn find_process_in_directory(&mut self, exe_name: &str) -> Option<Pid> {
        self.system
            .refresh_processes(sysinfo::ProcessesToUpdate::All, true);
        let monitor_path = Path::new(&self.config.monitor_directory);

        for (pid, process) in self.system.processes() {
            if let Some(exe_path) = process.exe() {
                if let Some(parent_dir) = exe_path.parent() {
                    if parent_dir == monitor_path {
                        if let Some(name) = exe_path.file_name() {
                            if name.to_string_lossy().eq_ignore_ascii_case(exe_name) {
                                return Some(*pid);
                            }
                        }
                    }
                }
            }
        }
        None
    }

    fn is_process_alive(&mut self, pid: Pid) -> bool {
        self.system
            .refresh_processes(sysinfo::ProcessesToUpdate::All, true);
        self.system.process(pid).is_some()
    }

    fn kill_process(&mut self, exe_name: &str) -> bool {
        if let Some(pid) = self.find_process_in_directory(exe_name) {
            self.log(format!("找到进程 {} (PID: {}), 正在强制关闭...", exe_name, pid));

            if let Some(process) = self.system.process(pid) {
                if process.kill() {
                    self.log(format!("成功发送终止信号到 {} (PID: {})", exe_name, pid));

                    for i in 1..=10 {
                        thread::sleep(Duration::from_millis(100));
                        if !self.is_process_alive(pid) {
                            self.log(format!("进程 {} 已确认终止", exe_name));
                            return true;
                        }
                        if i == 10 {
                            self.log(format!("警告: 进程 {} 可能仍在运行", exe_name));
                        }
                    }
                } else {
                    self.log(format!("无法终止进程 {} (PID: {})", exe_name, pid));
                }
            }
        } else {
            self.log(format!("未找到进程: {}", exe_name));
        }
        false
    }

    fn run(&mut self) {
        self.log("KillNeac 已启动".to_string());
        
        self.log(format!("监控目录: {}", self.config.monitor_directory));
        self.log(format!("目标进程: {}", self.config.target_exe));
        self.log(format!("待关闭进程: {}", self.config.kill_exe));
        self.log(format!(
            "开机自启: {}",
            if check_auto_start_status() { "已启用" } else { "未启用" }
        ));
        self.log(format!(
            "检查间隔: {}ms",
            self.config.check_interval_ms
        ));

        let check_interval = Duration::from_millis(self.config.check_interval_ms);

        loop {
            if self.target_pid.is_none() {
                let target_exe = self.config.target_exe.clone();
                if let Some(pid) = self.find_process_in_directory(&target_exe) {
                    self.target_pid = Some(pid);
                    self.log(format!(
                        "检测到目标进程 {} 正在运行 (PID: {})",
                        target_exe, pid
                    ));
                }
            }

            if let Some(pid) = self.target_pid {
                if !self.is_process_alive(pid) {
                    self.log(format!(
                        "目标进程 {} (PID: {}) 已关闭",
                        self.config.target_exe, pid
                    ));
                    self.target_pid = None;

                    let kill_exe = self.config.kill_exe.clone();
                    self.kill_process(&kill_exe);
                }
            }

            thread::sleep(check_interval);
        }
    }
}

#[cfg(windows)]
fn hide_console_window() {
    unsafe {
        let window = winapi::um::wincon::GetConsoleWindow();
        if !window.is_null() {
            winapi::um::winuser::ShowWindow(window, winapi::um::winuser::SW_HIDE);
        }
    }
}

#[cfg(windows)]
fn setup_auto_start(enable: bool) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Error;
    use winapi::shared::minwindef::HKEY;
    use winapi::um::winreg::{RegCloseKey, RegDeleteValueW, RegOpenKeyExW, RegSetValueExW};
    use winapi::um::winnt::{KEY_WRITE, REG_SZ};

    let app_name = "KillNeac";
    let key_path = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
    
    // 获取当前程序的完整路径
    let exe_path = std::env::current_exe()?;
    let exe_path_str = exe_path.to_string_lossy().to_string();

    unsafe {
        let mut hkey: HKEY = std::ptr::null_mut();
        let key_path_wide: Vec<u16> = key_path.encode_utf16().chain(Some(0)).collect();
        
        // 打开注册表项
        let result = RegOpenKeyExW(
            winapi::um::winreg::HKEY_CURRENT_USER,
            key_path_wide.as_ptr(),
            0,
            KEY_WRITE,
            &mut hkey,
        );

        if result != 0 {
            return Err(format!("无法打开注册表项: {}", Error::from_raw_os_error(result as i32)).into());
        }

        let app_name_wide: Vec<u16> = app_name.encode_utf16().chain(Some(0)).collect();

        if enable {
            // 添加开机自启
            let exe_path_wide: Vec<u16> = exe_path_str.encode_utf16().chain(Some(0)).collect();
            let result = RegSetValueExW(
                hkey,
                app_name_wide.as_ptr(),
                0,
                REG_SZ,
                exe_path_wide.as_ptr() as *const u8,
                (exe_path_wide.len() * 2) as u32,
            );

            RegCloseKey(hkey);

            if result != 0 {
                return Err(format!("无法设置注册表值: {}", Error::from_raw_os_error(result as i32)).into());
            }
        } else {
            // 移除开机自启
            let result = RegDeleteValueW(hkey, app_name_wide.as_ptr());
            RegCloseKey(hkey);

            if result != 0 && result != 2 {
                // 错误码 2 表示值不存在，这是可以接受的
                return Err(format!("无法删除注册表值: {}", Error::from_raw_os_error(result as i32)).into());
            }
        }
    }

    Ok(())
}

#[cfg(windows)]
fn check_auto_start_status() -> bool {
    use winapi::shared::minwindef::HKEY;
    use winapi::um::winreg::{RegCloseKey, RegOpenKeyExW, RegQueryValueExW};
    use winapi::um::winnt::{KEY_READ, REG_SZ};

    let app_name = "KillNeac";
    let key_path = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";

    unsafe {
        let mut hkey: HKEY = std::ptr::null_mut();
        let key_path_wide: Vec<u16> = key_path.encode_utf16().chain(Some(0)).collect();
        
        let result = RegOpenKeyExW(
            winapi::um::winreg::HKEY_CURRENT_USER,
            key_path_wide.as_ptr(),
            0,
            KEY_READ,
            &mut hkey,
        );

        if result != 0 {
            return false;
        }

        let app_name_wide: Vec<u16> = app_name.encode_utf16().chain(Some(0)).collect();
        let mut buffer: Vec<u16> = vec![0; 512];
        let mut buffer_size: u32 = (buffer.len() * 2) as u32;
        let mut value_type: u32 = 0;

        let result = RegQueryValueExW(
            hkey,
            app_name_wide.as_ptr(),
            ptr::null_mut(),
            &mut value_type,
            buffer.as_mut_ptr() as *mut u8,
            &mut buffer_size,
        );

        RegCloseKey(hkey);

        result == 0 && value_type == REG_SZ
    }
}

#[cfg(not(windows))]
fn check_auto_start_status() -> bool {
    false
}

#[cfg(windows)]
fn kill_previous_instance() {
    let mutex_name: Vec<u16> = "Global\\KillNeac_SingleInstance_Mutex"
        .encode_utf16()
        .chain(Some(0))
        .collect();

    unsafe {
        let mutex = CreateMutexW(ptr::null_mut(), 1, mutex_name.as_ptr());
        
        if mutex.is_null() {
            return;
        }

        let error = GetLastError();
        if error == ERROR_ALREADY_EXISTS {
            // 找到并杀死之前的实例
            let mut system = System::new_all();
            system.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
            
            let current_pid = sysinfo::get_current_pid().ok();
            let current_exe = std::env::current_exe().ok();
            
            if let Some(exe_path) = current_exe {
                for (pid, process) in system.processes() {
                    if Some(*pid) != current_pid {
                        if let Some(proc_exe) = process.exe() {
                            if proc_exe == exe_path {
                                let _ = process.kill();
                                thread::sleep(Duration::from_millis(500));
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(not(windows))]
fn kill_previous_instance() {}

#[cfg(not(windows))]
fn setup_auto_start(_enable: bool) -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}

fn main() {
    // 杀死之前的实例（如果存在）
    #[cfg(windows)]
    kill_previous_instance();

    let config = match Config::load() {
        Ok(config) => config,
        Err(e) => {
            eprintln!("加载配置文件失败: {}", e);
            eprintln!("请确保 config.json 文件存在且格式正确");
            std::process::exit(1);
        }
    };

    // 设置开机自启
    let _ = setup_auto_start(config.auto_start);

    #[cfg(windows)]
    hide_console_window();

    let mut monitor = KillNeac::new(config);
    monitor.run();
}
