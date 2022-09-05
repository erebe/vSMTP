/*
 * vSMTP mail transfer agent
 * Copyright (C) 2022 viridIT SAS
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program. If not, see https://www.gnu.org/licenses/.
 *
*/

/// Run a program as a background process
///
/// # Errors
///
/// see daemon(2) ERRORS
pub fn daemon(nochdir: bool, noclose: bool) -> anyhow::Result<()> {
    #[allow(unsafe_code)]
    // SAFETY: ffi call
    match unsafe { libc::daemon(i32::from(nochdir), i32::from(noclose)) } {
        0 => Ok(()),
        _ => Err(anyhow::anyhow!(
            "daemon: '{}'",
            std::io::Error::last_os_error()
        )),
    }
}

/// Set user identity
///
/// # Errors
///
/// see setuid(2) ERRORS
#[inline]
pub fn setuid(uid: libc::uid_t) -> anyhow::Result<i32> {
    #[allow(unsafe_code)]
    // SAFETY: ffi call
    match unsafe { libc::setuid(uid) } {
        -1 => Err(anyhow::anyhow!(
            "setuid: '{}'",
            std::io::Error::last_os_error()
        )),
        otherwise => Ok(otherwise),
    }
}

/// Set group identity
///
/// # Errors
///
/// see setgid(2) ERRORS
#[inline]
pub fn setgid(gid: libc::gid_t) -> anyhow::Result<i32> {
    #[allow(unsafe_code)]
    // SAFETY: ffi call
    match unsafe { libc::setgid(gid) } {
        -1 => Err(anyhow::anyhow!(
            "setgid: '{}'",
            std::io::Error::last_os_error()
        )),
        otherwise => Ok(otherwise),
    }
}

/// Initialize the supplementary group access list
///
/// # Errors
///
/// see initgroups(2) ERRORS
pub fn initgroups(user: &str, gid: libc::gid_t) -> anyhow::Result<()> {
    let user = std::ffi::CString::new(user)?;
    #[allow(unsafe_code)]
    // SAFETY: ffi call
    match unsafe { libc::initgroups(user.as_ptr(), gid) } {
        0 => Ok(()),
        _ => Err(anyhow::anyhow!(
            "initgroups: '{}'",
            std::io::Error::last_os_error()
        )),
    }
}

/// Change ownership of a file
///
/// # Errors
///
/// * `@path` cannot be convert to `CString`
/// * see chown(2) ERRORS
pub fn chown(path: &std::path::Path, user: Option<u32>, group: Option<u32>) -> anyhow::Result<()> {
    let path = std::ffi::CString::new(path.to_string_lossy().as_bytes())?;
    #[allow(unsafe_code)]
    // SAFETY: ffi call
    match unsafe {
        libc::chown(
            path.as_ptr(),
            user.unwrap_or(u32::MAX),
            group.unwrap_or(u32::MAX),
        )
    } {
        0 => Ok(()),
        otherwise => Err(anyhow::anyhow!(
            "failed to change file owner: ({}) '{}'",
            otherwise,
            std::io::Error::last_os_error()
        )),
    }
}

/// Returns the index of the network interface corresponding to the name `@name`
///
/// # Errors
///
/// * `@name` contain an internal 0 byte
///
/// see `if_nametoindex(2)` ERRORS
/// * ENXIO: No index found for the @name
pub fn if_nametoindex(name: &str) -> anyhow::Result<u32> {
    let ifname = std::ffi::CString::new(name)?;
    #[allow(unsafe_code)]
    // SAFETY: ffi call
    match unsafe { libc::if_nametoindex(ifname.as_ptr()) } {
        0 => Err(anyhow::anyhow!(
            "if_nametoindex: '{}'",
            std::io::Error::last_os_error()
        )),
        otherwise => Ok(otherwise),
    }
}

/// Returns the name of the network interface corresponding to the interface `@index`
///
/// # Errors
///
/// * No interface found for the `@index`
/// * Interface name is not utf8
pub fn if_indextoname(index: u32) -> anyhow::Result<String> {
    let mut buf = [0; libc::IF_NAMESIZE];

    #[allow(unsafe_code)]
    // SAFETY: ffi call
    match unsafe { libc::if_indextoname(index, buf.as_mut_ptr()) } {
        null if null.is_null() => Err(anyhow::anyhow!(
            "if_indextoname: '{}'",
            std::io::Error::last_os_error()
        )),
        // SAFETY: the foreign allocated is used correctly as specified in `CStr::from_ptr`
        _ => Ok(unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) }
            .to_str()?
            .to_string()),
    }
}

/// Get user's home directory
///
/// # Errors
///
/// * see getpwuid(2) ERRORS
/// * the filepath does not contain valid utf8 data
pub fn getpwuid(uid: libc::uid_t) -> anyhow::Result<std::path::PathBuf> {
    #[allow(unsafe_code)]
    // SAFETY: ffi call
    let passwd = unsafe { libc::getpwuid(uid) };
    #[allow(unsafe_code)]
    // SAFETY: `passwd` is a valid pointer
    if passwd.is_null() || unsafe { *passwd }.pw_dir.is_null() {
        anyhow::bail!("getpwuid: '{}'", std::io::Error::last_os_error());
    }
    #[allow(unsafe_code)]
    // SAFETY: the foreign allocated is used correctly as specified in `CStr::from_ptr`
    Ok(unsafe { std::ffi::CStr::from_ptr((*passwd).pw_dir) }
        .to_str()?
        .into())
}
