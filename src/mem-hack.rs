use sysinfo::PidExt;
use sysinfo::ProcessExt;
use sysinfo::SystemExt;

use std::io;
use std::mem;
use std::ptr;

use std::ffi::CStr;
use winapi::ctypes::c_void;
use winapi::shared::minwindef::{DWORD, LPVOID, MAX_PATH};
use winapi::um::memoryapi::{ReadProcessMemory, VirtualQueryEx, WriteProcessMemory};
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::psapi::GetModuleBaseNameA;
use winapi::um::sysinfoapi::SYSTEM_INFO;
use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32,
};
use winapi::um::winnt::{HANDLE, PROCESS_ALL_ACCESS, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
use winapi::um::winnt::{MEMORY_BASIC_INFORMATION, PAGE_READWRITE};

fn scan_and_modify_memory(
    process_id: DWORD,
    search_value: &str,
    new_value: &str,
) -> io::Result<()> {
    let h_process: HANDLE = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, process_id) };
    if h_process.is_null() {
        return Err(io::Error::last_os_error());
    }

    unsafe {
        let mut si: SYSTEM_INFO = mem::zeroed();
        winapi::um::sysinfoapi::GetSystemInfo(&mut si);

        let mut lp_minimum_application_address: LPVOID = si.lpMinimumApplicationAddress;
        let lp_maximum_application_address: LPVOID = si.lpMaximumApplicationAddress;

        while lp_minimum_application_address < lp_maximum_application_address {
            let mut mbi: MEMORY_BASIC_INFORMATION = mem::zeroed();
            if VirtualQueryEx(
                h_process,
                lp_minimum_application_address as *const c_void,
                &mut mbi as *mut MEMORY_BASIC_INFORMATION,
                mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            ) == 0
            {
                return Err(io::Error::last_os_error());
            }

            if mbi.State == winapi::um::winnt::MEM_COMMIT && mbi.Protect == PAGE_READWRITE {
                let buffer_size: usize = mbi.RegionSize;
                let buffer = vec![0u8; buffer_size];
                let mut bytes_read: usize = 0;
                if ReadProcessMemory(
                    h_process,
                    mbi.BaseAddress as *const c_void,
                    buffer.as_ptr() as *mut c_void,
                    buffer_size,
                    &mut bytes_read,
                ) != 0
                {
                    for i in 0..bytes_read - search_value.len() {
                        let compare_buffer = &buffer[i..(i + search_value.len())];
                        if compare_buffer == search_value.as_bytes() {
                            if WriteProcessMemory(
                                h_process,
                                (mbi.BaseAddress as usize + i) as *mut c_void,
                                new_value.as_bytes().as_ptr() as *const c_void,
                                new_value.len(),
                                ptr::null_mut(),
                            ) != 0
                            {
                                println!("Memory modified.");
                                return Ok(());
                            } else {
                                return Err(io::Error::last_os_error());
                            }
                        }
                    }
                } else {
                    return Err(io::Error::last_os_error());
                }
            }

            lp_minimum_application_address =
                (lp_minimum_application_address as usize + mbi.RegionSize) as LPVOID;
        }
    }

    println!("Value not found.");
    Ok(())
}

fn auto_scan_and_modify_memory(
    exe_name: &str,
    search_value: &str,
    new_value: &str,
) -> io::Result<()> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(winapi::um::tlhelp32::TH32CS_SNAPPROCESS, 0) };
    if snapshot == winapi::um::handleapi::INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }

    let mut process_entry: PROCESSENTRY32 = unsafe { mem::zeroed() };
    process_entry.dwSize = mem::size_of::<PROCESSENTRY32>() as DWORD;

    if unsafe { Process32First(snapshot, &mut process_entry) } == 0 {
        return Err(io::Error::last_os_error());
    }

    let mut system = sysinfo::System::new();
    system.refresh_all();

    for p in system.processes_by_name(exe_name) {
        if exe_name == p.name() {
            let process_id = p.pid().as_u32();
            println!("Process ID: {}", process_id);
            scan_and_modify_memory(process_id, search_value, new_value)?;
        }
    }

    while unsafe { Process32Next(snapshot, &mut process_entry) } != 0 {
        let process_id = process_entry.th32ProcessID;
        let process_name = get_module_base_name(process_id)?;

        if process_name == exe_name {
            println!("Process ID: {}", process_id);
            scan_and_modify_memory(process_id, search_value, new_value)?;
        }
    }

    Ok(())
}

fn get_module_base_name(process_id: DWORD) -> io::Result<String> {
    let mut sz_process_name: [i8; MAX_PATH] = [0; MAX_PATH];
    let h_process: HANDLE =
        unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, process_id) };
    if h_process.is_null() {
        return Err(io::Error::last_os_error());
    }
 
    unsafe {
        if GetModuleBaseNameA(
            h_process,
            std::ptr::null_mut(),
            sz_process_name.as_mut_ptr(),
            MAX_PATH as u32,
        ) != 0
        {
            let cstr = CStr::from_ptr(sz_process_name.as_ptr());
            let process_name = cstr.to_string_lossy().into_owned();
            Ok(process_name)
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

fn main() {
    let exe_name = "dummy.exe";
    let search_value = "test2";
    let new_value = "test0";

    println!("search value: {:?}", search_value);
    println!("   new value: {:?}", new_value);

    let _ = auto_scan_and_modify_memory(exe_name, search_value, new_value);
}
