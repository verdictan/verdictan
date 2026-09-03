// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Owner-only DACL for secret files and directories on Windows.
//!
//! Unix hosts use mode bits. Windows has no equivalent in `std`, so this module
//! rebuilds the DACL with a single ACE for the current user.

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows_sys::Win32::Foundation::{
    CloseHandle, LocalFree, GENERIC_ALL, HANDLE, HLOCAL, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{
    GetNamedSecurityInfoW, SetEntriesInAclW, SetNamedSecurityInfoW, EXPLICIT_ACCESS_W, SET_ACCESS,
    TRUSTEE_IS_SID, TRUSTEE_IS_USER,
};
use windows_sys::Win32::Security::{
    CopySid, GetLengthSid, GetTokenInformation, TokenUser, ACL, DACL_SECURITY_INFORMATION,
    NO_INHERITANCE, PSID, SUB_CONTAINERS_AND_OBJECTS_INHERIT, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

const ACCESS_ALLOWED_ACE_TYPE: u8 = 0x00;

/// Replaces the DACL on `path` so only the current user has access.
///
/// Returns `true` when the DACL was applied. Returns `false` when any Win32
/// call fails.
#[allow(unsafe_code)]
pub(crate) fn restrict_path_to_owner(path: &Path) -> bool {
    let wide_path = path_to_wide(path);
    let is_directory = std::fs::metadata(path)
        .map(|metadata| metadata.is_dir())
        .unwrap_or(false);

    let user_sid = match current_user_sid() {
        Some(sid) => sid,
        None => return false,
    };

    let mut security_descriptor = std::ptr::null_mut();
    let mut dacl = std::ptr::null_mut() as *mut ACL;
    let mut owner = std::ptr::null_mut() as PSID;

    // SAFETY: `wide_path` stays alive for the call and ends with a null. Every
    // out-parameter is a live local. The parameters that this call does not
    // request are passed as null, which `GetNamedSecurityInfoW` documents as
    // "not requested".
    let query_status = unsafe {
        GetNamedSecurityInfoW(
            wide_path.as_ptr(),
            windows_sys::Win32::Security::Authorization::SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut security_descriptor,
        )
    };
    if query_status != 0 {
        return false;
    }

    let explicit_access = EXPLICIT_ACCESS_W {
        grfAccessPermissions: GENERIC_ALL,
        grfAccessMode: SET_ACCESS,
        grfInheritance: if is_directory {
            SUB_CONTAINERS_AND_OBJECTS_INHERIT
        } else {
            NO_INHERITANCE
        },
        Trustee: windows_sys::Win32::Security::Authorization::TRUSTEE_W {
            pMultipleTrustee: std::ptr::null_mut(),
            MultipleTrusteeOperation:
                windows_sys::Win32::Security::Authorization::NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_USER,
            ptstrName: user_sid.as_ptr() as *mut u16,
        },
    };

    let mut new_dacl = std::ptr::null_mut() as *mut ACL;
    // SAFETY: `explicit_access` and `new_dacl` are live locals. The trustee name
    // points into `user_sid`, which stays alive for the call. A null old ACL
    // asks for a new ACL that holds only this entry.
    let build_status =
        unsafe { SetEntriesInAclW(1, &explicit_access, std::ptr::null_mut(), &mut new_dacl) };
    if build_status != 0 || new_dacl.is_null() {
        free_security_descriptor(security_descriptor);
        return false;
    }

    // SAFETY: `wide_path` stays alive for the call, and `new_dacl` holds the ACL
    // that `SetEntriesInAclW` allocated above.
    let apply_status = unsafe {
        SetNamedSecurityInfoW(
            wide_path.as_ptr(),
            windows_sys::Win32::Security::Authorization::SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            new_dacl,
            std::ptr::null_mut(),
        )
    };

    // SAFETY: `SetEntriesInAclW` allocated `new_dacl` and documents `LocalFree`
    // as the matching release call. This path runs once for that allocation.
    unsafe {
        let _ = LocalFree(new_dacl as HLOCAL);
    }
    free_security_descriptor(security_descriptor);

    apply_status == 0
}

fn path_to_wide(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

#[allow(unsafe_code)]
fn free_security_descriptor(descriptor: *mut c_void) {
    if descriptor.is_null() {
        return;
    }
    // SAFETY: `GetNamedSecurityInfoW` allocated the descriptor and documents
    // `LocalFree` as the matching release call. The null check above keeps the
    // release to one live allocation.
    unsafe {
        let _ = LocalFree(descriptor as HLOCAL);
    }
}

#[allow(unsafe_code)]
fn current_user_sid() -> Option<Vec<u8>> {
    let mut token = INVALID_HANDLE_VALUE;
    // SAFETY: `token` is a live local, and the process handle stays valid for
    // the lifetime of the process.
    let open_status =
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token as *mut HANDLE) };
    if open_status == 0 || token == INVALID_HANDLE_VALUE {
        return None;
    }

    let sid = read_token_user_sid(token);
    // SAFETY: `OpenProcessToken` opened `token` above, and this path closes it
    // exactly once.
    unsafe {
        let _ = CloseHandle(token);
    }
    sid
}

#[allow(unsafe_code)]
fn read_token_user_sid(token: HANDLE) -> Option<Vec<u8>> {
    let mut required_size = 0;
    // SAFETY: `token` is open for the call. A null buffer with a zero length
    // asks `GetTokenInformation` for the required size only.
    let first_status = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            std::ptr::null_mut(),
            0,
            &mut required_size,
        )
    };
    if first_status == 0 && required_size == 0 {
        return None;
    }

    let mut buffer = vec![0u8; required_size as usize];
    // SAFETY: `buffer` holds the size that the probe above reported, and
    // `required_size` describes that same buffer.
    let second_status = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr() as *mut c_void,
            required_size,
            &mut required_size,
        )
    };
    if second_status == 0 {
        return None;
    }

    let token_user = buffer.as_ptr() as *const TOKEN_USER;
    // SAFETY: `GetTokenInformation` filled `buffer` with a `TOKEN_USER` for the
    // `TokenUser` class, and `buffer` stays alive for this read.
    let source_sid = unsafe { (*token_user).User.Sid };
    if source_sid.is_null() {
        return None;
    }

    // SAFETY: `source_sid` points into the live `buffer` allocation.
    let sid_length = unsafe { GetLengthSid(source_sid) };
    if sid_length == 0 {
        return None;
    }

    let mut sid_buffer = vec![0u8; sid_length as usize];
    // SAFETY: `sid_buffer` holds the length that `GetLengthSid` reported, and
    // `source_sid` stays alive in `buffer` for the copy.
    let copied = unsafe { CopySid(sid_length, sid_buffer.as_mut_ptr() as PSID, source_sid) };
    if copied == 0 {
        return None;
    }

    Some(sid_buffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use windows_sys::Win32::Security::{GetAce, ACE_HEADER};

    #[test]
    #[allow(unsafe_code)]
    fn restrict_path_to_owner_applies_to_a_secret_file() {
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("credentials.json");
        std::fs::write(&path, b"secret").expect("seed file");

        assert!(restrict_path_to_owner(&path));

        let mut security_descriptor = std::ptr::null_mut();
        let mut dacl = std::ptr::null_mut() as *mut ACL;
        let wide_path = path_to_wide(&path);
        let status = unsafe {
            GetNamedSecurityInfoW(
                wide_path.as_ptr(),
                windows_sys::Win32::Security::Authorization::SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut dacl,
                std::ptr::null_mut(),
                &mut security_descriptor,
            )
        };
        assert_eq!(status, 0, "GetNamedSecurityInfoW should succeed");
        assert!(!dacl.is_null(), "DACL should exist");

        let ace_count = unsafe { (*dacl).AceCount };
        assert_eq!(ace_count, 1, "owner-only DACL should contain one ACE");

        let mut ace: *mut c_void = std::ptr::null_mut();
        let ace_status = unsafe { GetAce(dacl, 0, &mut ace) };
        assert_ne!(ace_status, 0, "GetAce should return the single ACE");
        assert!(!ace.is_null(), "ACE pointer should exist");

        let ace_header = ace.cast::<ACE_HEADER>();
        assert_eq!(unsafe { (*ace_header).AceType }, ACCESS_ALLOWED_ACE_TYPE);

        free_security_descriptor(security_descriptor);
    }

    #[test]
    #[allow(unsafe_code)]
    fn restrict_path_to_owner_applies_to_a_secret_directory() {
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("nested");
        std::fs::create_dir(&path).expect("create dir");

        assert!(restrict_path_to_owner(&path));

        let mut security_descriptor = std::ptr::null_mut();
        let mut dacl = std::ptr::null_mut() as *mut ACL;
        let wide_path = path_to_wide(&path);
        let status = unsafe {
            GetNamedSecurityInfoW(
                wide_path.as_ptr(),
                windows_sys::Win32::Security::Authorization::SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut dacl,
                std::ptr::null_mut(),
                &mut security_descriptor,
            )
        };
        assert_eq!(status, 0);
        assert!(!dacl.is_null());
        assert_eq!(unsafe { (*dacl).AceCount }, 1);

        free_security_descriptor(security_descriptor);
    }
}
