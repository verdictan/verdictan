// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Windows trusted-execution primitives for the gateway execution runtime.
//!
//! Unix hosts prove that a pinned execution binary is trustworthy with `uid`,
//! mode bits, and `dev` plus `ino` identity. `std::fs::Metadata` exposes no
//! equivalent on Windows, so this module reads the real security descriptor and
//! the real file identity through Win32.
//!
//! The module supplies three capabilities:
//!
//! 1. [`has_static_system_ownership`] proves that the executable and every
//!    ancestor directory up to the trusted root is owned by a trusted Windows
//!    principal, and that no untrusted principal holds write, delete, modify,
//!    or full-control access.
//! 2. [`pinned_handle_matches_path`] compares `FILE_ID_INFO`, which is the
//!    Windows analogue of `dev` plus `ino`. It gives a volume serial number and
//!    a 128-bit file identifier.
//! 3. [`open_pinned_executable`] and [`ensure_same_identity`] pin the binary.
//!    `CreateProcess` accepts a path and not a handle, so Windows cannot
//!    execute a descriptor the way `execve` on `/proc/self/fd/N` can. The pin
//!    instead requests a deny-write, deny-delete share mode, and the identity
//!    is rechecked immediately before the spawn.
//!
//! Residual weakness against the Unix path: the ownership probe opens its own
//! handles, so a short window exists between the probe and the pin. The pinned
//! share mode, the trusted-owner requirement on every ancestor directory, and
//! the pre-spawn identity recheck close that window for every principal that is
//! not already trusted.

use std::ffi::c_void;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;

use windows_sys::Win32::Foundation::{LocalFree, ERROR_SUCCESS, HANDLE, HLOCAL};
use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
use windows_sys::Win32::Security::{
    GetAce, GetSidIdentifierAuthority, GetSidSubAuthority, GetSidSubAuthorityCount, IsValidSid,
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID,
};
use windows_sys::Win32::Storage::FileSystem::{
    FileIdInfo, GetFileInformationByHandleEx, FILE_FLAG_BACKUP_SEMANTICS, FILE_ID_INFO,
    FILE_SHARE_READ,
};

/// `SECURITY_NT_AUTHORITY`, the identifier authority of every built-in Windows
/// principal that this module trusts.
const NT_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 5];

/// Sub-authority chains of the principals that may own a trusted execution
/// binary or hold write access to it.
const TRUSTED_SUB_AUTHORITIES: &[&[u32]] = &[
    // NT AUTHORITY\SYSTEM — S-1-5-18
    &[18],
    // BUILTIN\Administrators — S-1-5-32-544
    &[32, 544],
    // NT SERVICE\TrustedInstaller
    &[
        80, 956008885, 3418522649, 1831038044, 1853292631, 2271478464,
    ],
];

/// `ACE_HEADER.AceType` values that grant access. `windows-sys` does not export
/// these `#define` constants, so they are restated from the documented ACE type
/// list.
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0x00;
const ACCESS_ALLOWED_OBJECT_ACE_TYPE: u8 = 0x05;
const ACCESS_ALLOWED_CALLBACK_ACE_TYPE: u8 = 0x09;
const ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE: u8 = 0x0B;

/// `INHERIT_ONLY_ACE`. An ACE with this flag does not apply to the object that
/// carries it, so it must not influence the trust decision.
const INHERIT_ONLY_ACE_FLAG: u8 = 0x08;

// Access-mask bits that let a principal change the bytes, the name, the
// location, or the security of a file or directory. `FILE_WRITE_DATA` and
// `FILE_APPEND_DATA` are named `FILE_ADD_FILE` and `FILE_ADD_SUBDIRECTORY` on a
// directory and carry the same bit values.
const FILE_WRITE_DATA: u32 = 0x0000_0002;
const FILE_APPEND_DATA: u32 = 0x0000_0004;
const FILE_WRITE_EA: u32 = 0x0000_0010;
const FILE_DELETE_CHILD: u32 = 0x0000_0040;
const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;
const DELETE: u32 = 0x0001_0000;
const WRITE_DAC: u32 = 0x0004_0000;
const WRITE_OWNER: u32 = 0x0008_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;

const MUTATING_RIGHTS: u32 = FILE_WRITE_DATA
    | FILE_APPEND_DATA
    | FILE_WRITE_EA
    | FILE_DELETE_CHILD
    | FILE_WRITE_ATTRIBUTES
    | DELETE
    | WRITE_DAC
    | WRITE_OWNER
    | GENERIC_ALL
    | GENERIC_WRITE;

/// A decoded security identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SecurityIdentifier {
    authority: [u8; 6],
    sub_authorities: Vec<u32>,
}

impl SecurityIdentifier {
    fn is_trusted(&self) -> bool {
        self.authority == NT_AUTHORITY
            && TRUSTED_SUB_AUTHORITIES.contains(&self.sub_authorities.as_slice())
    }
}

/// Owns the security descriptor that `GetSecurityInfo` allocates. The owner SID
/// and the DACL point into that allocation, so they stay valid only while this
/// value is alive.
struct SecurityDescriptor {
    raw: PSECURITY_DESCRIPTOR,
    owner: PSID,
    dacl: *mut ACL,
}

impl Drop for SecurityDescriptor {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        if self.raw.is_null() {
            return;
        }
        // SAFETY: `raw` was allocated by `GetSecurityInfo`, which documents
        // `LocalFree` as the matching release call. `Drop` runs once, so the
        // allocation is released exactly once.
        let _ = unsafe { LocalFree(self.raw as HLOCAL) };
    }
}

/// Reads the identifier authority and the sub-authority chain of a SID.
///
/// # Safety
///
/// `sid` must be null or point at a valid SID that stays alive for the call.
#[allow(unsafe_code)]
unsafe fn read_security_identifier(sid: PSID) -> Option<SecurityIdentifier> {
    if sid.is_null() || IsValidSid(sid) == 0 {
        return None;
    }
    let authority = GetSidIdentifierAuthority(sid);
    if authority.is_null() {
        return None;
    }
    let count = GetSidSubAuthorityCount(sid);
    if count.is_null() {
        return None;
    }
    let count = *count;
    let mut sub_authorities = Vec::with_capacity(usize::from(count));
    for index in 0..count {
        let value = GetSidSubAuthority(sid, u32::from(index));
        if value.is_null() {
            return None;
        }
        sub_authorities.push(*value);
    }
    Some(SecurityIdentifier {
        authority: (*authority).Value,
        sub_authorities,
    })
}

/// Reads the owner and the DACL of an already open file or directory handle.
#[allow(unsafe_code)]
fn load_security_descriptor(file: &File) -> Option<SecurityDescriptor> {
    let mut owner: PSID = std::ptr::null_mut();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut raw: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: the handle belongs to `file` and stays open for the call. Every
    // out-parameter is a live local, and the parameters that this call does not
    // request are passed as null, which `GetSecurityInfo` documents as "not
    // requested".
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle() as HANDLE,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut raw,
        )
    };
    if status != ERROR_SUCCESS {
        return None;
    }
    Some(SecurityDescriptor { raw, owner, dacl })
}

/// Reports whether an access mask lets the trustee change the object.
fn grants_mutating_rights(mask: u32) -> bool {
    mask & MUTATING_RIGHTS != 0
}

/// Reports whether every effective allow ACE that grants a mutating right names
/// a trusted principal.
///
/// # Safety
///
/// `dacl` must point at a valid DACL that stays alive for the call.
#[allow(unsafe_code)]
unsafe fn dacl_grants_only_trusted_writes(dacl: *const ACL) -> bool {
    for index in 0..u32::from((*dacl).AceCount) {
        let mut ace: *mut c_void = std::ptr::null_mut();
        if GetAce(dacl, index, &mut ace) == 0 || ace.is_null() {
            return false;
        }
        let header = ace.cast::<ACE_HEADER>();
        let ace_type = (*header).AceType;
        if (*header).AceFlags & INHERIT_ONLY_ACE_FLAG != 0 {
            continue;
        }
        if !matches!(
            ace_type,
            ACCESS_ALLOWED_ACE_TYPE
                | ACCESS_ALLOWED_CALLBACK_ACE_TYPE
                | ACCESS_ALLOWED_OBJECT_ACE_TYPE
                | ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
        ) {
            continue;
        }
        // The mask sits at the same offset in every allow ACE layout.
        let entry = ace.cast::<ACCESS_ALLOWED_ACE>();
        if !grants_mutating_rights((*entry).Mask) {
            continue;
        }
        if matches!(
            ace_type,
            ACCESS_ALLOWED_OBJECT_ACE_TYPE | ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
        ) {
            // An object ACE carries GUID fields between the mask and the
            // trustee, so the SID is not at `SidStart`. Fail closed.
            return false;
        }
        let sid = std::ptr::addr_of!((*entry).SidStart)
            .cast::<c_void>()
            .cast_mut();
        match read_security_identifier(sid) {
            Some(identifier) if identifier.is_trusted() => continue,
            _ => return false,
        }
    }
    true
}

/// Reports whether an open handle is owned by a trusted principal and grants no
/// mutating right to any other principal.
fn has_trusted_security_descriptor(file: &File) -> bool {
    let Some(descriptor) = load_security_descriptor(file) else {
        return false;
    };
    if descriptor.dacl.is_null() {
        // A null DACL grants full access to everyone.
        return false;
    }
    // SAFETY: the owner SID and the DACL borrow from `descriptor`, which is
    // alive for the whole expression.
    #[allow(unsafe_code)]
    let trusted = unsafe {
        read_security_identifier(descriptor.owner).is_some_and(|owner| owner.is_trusted())
            && dacl_grants_only_trusted_writes(descriptor.dacl)
    };
    trusted
}

/// Opens the execution binary for pinning.
///
/// The share mode omits `FILE_SHARE_WRITE` and `FILE_SHARE_DELETE`, so no other
/// process can write, truncate, rename, or delete the file while the returned
/// handle is open. Renaming needs `DELETE` access, so the pin also blocks a
/// rename-and-replace swap of the binary.
pub(crate) fn open_pinned_executable(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(path)
}

/// Opens a directory handle for a security-descriptor probe.
///
/// `FILE_FLAG_BACKUP_SEMANTICS` is required because Win32 refuses to open a
/// directory without it.
fn open_directory_probe(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
}

/// The Windows analogue of `dev` plus `ino`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    volume_serial_number: u64,
    file_id: [u8; 16],
}

#[allow(unsafe_code)]
fn file_identity(file: &File) -> io::Result<FileIdentity> {
    let mut info = FILE_ID_INFO::default();
    // SAFETY: the handle belongs to `file`, `info` is a live `FILE_ID_INFO`,
    // and the declared buffer size matches that allocation exactly.
    let queried = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle() as HANDLE,
            FileIdInfo,
            std::ptr::addr_of_mut!(info).cast::<c_void>(),
            std::mem::size_of::<FILE_ID_INFO>() as u32,
        )
    };
    if queried == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(FileIdentity {
        volume_serial_number: info.VolumeSerialNumber,
        file_id: info.FileId.Identifier,
    })
}

/// Reports whether the executable and every ancestor directory up to `root` is
/// owned by a trusted principal and grants no mutating right to any other
/// principal.
///
/// The ancestor walk mirrors the Unix branch: the chain must stay inside `root`
/// and must reach `root` itself. Windows has no mode bits, so the leaf check
/// requires a regular file instead of an execute bit.
pub(crate) fn has_static_system_ownership(root: &Path, executable: &Path) -> bool {
    let trusted_directory = |path: &Path| {
        open_directory_probe(path).is_ok_and(|handle| has_trusted_security_descriptor(&handle))
    };

    if executable == root {
        return trusted_directory(root);
    }

    let trusted_executable = open_pinned_executable(executable).is_ok_and(|handle| {
        handle.metadata().is_ok_and(|metadata| metadata.is_file())
            && has_trusted_security_descriptor(&handle)
    });
    if !trusted_executable {
        return false;
    }

    let mut directory = executable.parent();
    while let Some(path) = directory {
        if !path.starts_with(root) || !trusted_directory(path) {
            return false;
        }
        if path == root {
            return true;
        }
        directory = path.parent();
    }
    false
}

/// Reports whether the pinned handle and the current contents of `path` are the
/// same file, compared by volume serial number and 128-bit file identifier.
pub(crate) fn pinned_handle_matches_path(file: &File, path: &Path) -> bool {
    let Ok(pinned) = file_identity(file) else {
        return false;
    };
    let Ok(current) = open_pinned_executable(path).and_then(|handle| file_identity(&handle)) else {
        return false;
    };
    pinned == current
}

/// Rechecks the pinned identity immediately before a spawn.
///
/// `CreateProcess` resolves the program path again, so this call proves that the
/// path still names the validated file.
pub(crate) fn ensure_same_identity(file: &File, path: &Path) -> io::Result<()> {
    if pinned_handle_matches_path(file, path) {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        "pinned execution binary identity changed before spawn",
    ))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

    use super::*;
    use std::io::Write;

    fn identifier(authority: [u8; 6], sub_authorities: &[u32]) -> SecurityIdentifier {
        SecurityIdentifier {
            authority,
            sub_authorities: sub_authorities.to_vec(),
        }
    }

    #[test]
    fn local_system_is_trusted() {
        assert!(identifier(NT_AUTHORITY, &[18]).is_trusted());
    }

    #[test]
    fn administrators_is_trusted() {
        assert!(identifier(NT_AUTHORITY, &[32, 544]).is_trusted());
    }

    #[test]
    fn trusted_installer_is_trusted() {
        assert!(identifier(
            NT_AUTHORITY,
            &[80, 956008885, 3418522649, 1831038044, 1853292631, 2271478464]
        )
        .is_trusted());
    }

    #[test]
    fn builtin_users_is_not_trusted() {
        assert!(!identifier(NT_AUTHORITY, &[32, 545]).is_trusted());
    }

    #[test]
    fn authenticated_users_is_not_trusted() {
        assert!(!identifier(NT_AUTHORITY, &[11]).is_trusted());
    }

    #[test]
    fn everyone_is_not_trusted() {
        assert!(!identifier([0, 0, 0, 0, 0, 1], &[0]).is_trusted());
    }

    #[test]
    fn local_system_with_extra_sub_authority_is_not_trusted() {
        assert!(!identifier(NT_AUTHORITY, &[18, 1]).is_trusted());
    }

    #[test]
    fn domain_user_rid_is_not_trusted() {
        assert!(!identifier(NT_AUTHORITY, &[21, 1, 2, 3, 1001]).is_trusted());
    }

    #[test]
    fn read_and_execute_mask_is_not_mutating() {
        // FILE_GENERIC_READ | FILE_EXECUTE
        assert!(!grants_mutating_rights(0x0012_0089 | 0x0000_0020));
    }

    #[test]
    fn write_data_mask_is_mutating() {
        assert!(grants_mutating_rights(FILE_WRITE_DATA));
    }

    #[test]
    fn append_data_mask_is_mutating() {
        assert!(grants_mutating_rights(FILE_APPEND_DATA));
    }

    #[test]
    fn delete_mask_is_mutating() {
        assert!(grants_mutating_rights(DELETE));
    }

    #[test]
    fn delete_child_mask_is_mutating() {
        assert!(grants_mutating_rights(FILE_DELETE_CHILD));
    }

    #[test]
    fn write_dac_mask_is_mutating() {
        assert!(grants_mutating_rights(WRITE_DAC));
    }

    #[test]
    fn write_owner_mask_is_mutating() {
        assert!(grants_mutating_rights(WRITE_OWNER));
    }

    #[test]
    fn generic_all_mask_is_mutating() {
        assert!(grants_mutating_rights(GENERIC_ALL));
    }

    #[test]
    fn generic_write_mask_is_mutating() {
        assert!(grants_mutating_rights(GENERIC_WRITE));
    }

    #[test]
    fn write_attributes_mask_is_mutating() {
        assert!(grants_mutating_rights(FILE_WRITE_ATTRIBUTES));
    }

    #[test]
    fn empty_mask_is_not_mutating() {
        assert!(!grants_mutating_rights(0));
    }

    fn write_temp_file(directory: &Path, name: &str) -> std::path::PathBuf {
        let path = directory.join(name);
        let mut file = File::create(&path).expect("create temp file");
        file.write_all(b"verdictan-windows-trust-test")
            .expect("write temp file");
        path
    }

    #[test]
    fn system32_root_is_trusted() {
        let system_root = std::env::var("SystemRoot").expect("SystemRoot is set on Windows");
        let system32 = Path::new(&system_root)
            .join("System32")
            .canonicalize()
            .expect("canonicalize System32");
        assert!(has_static_system_ownership(&system32, &system32));
    }

    #[test]
    fn user_owned_directory_is_not_trusted() {
        let directory = tempfile::tempdir().expect("temp dir");
        let root = directory.path().canonicalize().expect("canonicalize root");
        assert!(!has_static_system_ownership(&root, &root));
    }

    #[test]
    fn user_owned_executable_is_not_trusted() {
        let directory = tempfile::tempdir().expect("temp dir");
        let root = directory.path().canonicalize().expect("canonicalize root");
        let executable = write_temp_file(&root, "candidate.exe");
        assert!(!has_static_system_ownership(&root, &executable));
    }

    #[test]
    fn executable_outside_root_is_not_trusted() {
        let inside = tempfile::tempdir().expect("temp dir");
        let outside = tempfile::tempdir().expect("temp dir");
        let root = inside.path().canonicalize().expect("canonicalize root");
        let executable = write_temp_file(
            &outside.path().canonicalize().expect("canonicalize outside"),
            "candidate.exe",
        );
        assert!(!has_static_system_ownership(&root, &executable));
    }

    #[test]
    fn file_identity_is_stable_across_handles() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = write_temp_file(directory.path(), "stable.bin");
        let first = open_pinned_executable(&path).expect("first pin");
        let second = open_pinned_executable(&path).expect("second pin");
        assert_eq!(
            file_identity(&first).expect("first identity"),
            file_identity(&second).expect("second identity")
        );
    }

    #[test]
    fn file_identity_differs_between_files() {
        let directory = tempfile::tempdir().expect("temp dir");
        let left = write_temp_file(directory.path(), "left.bin");
        let right = write_temp_file(directory.path(), "right.bin");
        let left = open_pinned_executable(&left).expect("pin left");
        let right = open_pinned_executable(&right).expect("pin right");
        assert_ne!(
            file_identity(&left).expect("left identity"),
            file_identity(&right).expect("right identity")
        );
    }

    #[test]
    fn pinned_handle_matches_its_own_path() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = write_temp_file(directory.path(), "pinned.bin");
        let pinned = open_pinned_executable(&path).expect("pin");
        assert!(pinned_handle_matches_path(&pinned, &path));
    }

    #[test]
    fn pinned_handle_does_not_match_a_different_path() {
        let directory = tempfile::tempdir().expect("temp dir");
        let pinned_path = write_temp_file(directory.path(), "pinned.bin");
        let other_path = write_temp_file(directory.path(), "other.bin");
        let pinned = open_pinned_executable(&pinned_path).expect("pin");
        assert!(!pinned_handle_matches_path(&pinned, &other_path));
    }

    #[test]
    fn pinned_handle_does_not_match_a_missing_path() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = write_temp_file(directory.path(), "pinned.bin");
        let pinned = open_pinned_executable(&path).expect("pin");
        assert!(!pinned_handle_matches_path(
            &pinned,
            &directory.path().join("absent.bin")
        ));
    }

    #[test]
    fn pin_denies_a_concurrent_write_open() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = write_temp_file(directory.path(), "locked.bin");
        let _pinned = open_pinned_executable(&path).expect("pin");
        assert!(OpenOptions::new().write(true).open(&path).is_err());
    }

    #[test]
    fn pin_denies_a_concurrent_delete() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = write_temp_file(directory.path(), "locked.bin");
        let _pinned = open_pinned_executable(&path).expect("pin");
        assert!(std::fs::remove_file(&path).is_err());
    }

    #[test]
    fn pin_denies_a_concurrent_rename() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = write_temp_file(directory.path(), "locked.bin");
        let _pinned = open_pinned_executable(&path).expect("pin");
        assert!(std::fs::rename(&path, directory.path().join("moved.bin")).is_err());
    }

    #[test]
    fn ensure_same_identity_accepts_the_pinned_path() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = write_temp_file(directory.path(), "pinned.bin");
        let pinned = open_pinned_executable(&path).expect("pin");
        assert!(ensure_same_identity(&pinned, &path).is_ok());
    }

    #[test]
    fn ensure_same_identity_rejects_a_different_file() {
        let directory = tempfile::tempdir().expect("temp dir");
        let pinned_path = write_temp_file(directory.path(), "pinned.bin");
        let other_path = write_temp_file(directory.path(), "other.bin");
        let pinned = open_pinned_executable(&pinned_path).expect("pin");
        let error = ensure_same_identity(&pinned, &other_path).expect_err("identity mismatch");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }
}
