//! Crash-safe file primitives: private directories, atomic replace, durable append.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;

use crate::Result;

/// Create `dir` (and parents) readable only by the owner.
pub fn create_private_dir(dir: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
        let mode = std::fs::metadata(dir)?.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    #[cfg(windows)]
    {
        std::fs::create_dir_all(dir)?;
        win::restrict_to_owner(dir)?;
    }
    #[cfg(not(any(unix, windows)))]
    std::fs::create_dir_all(dir)?;
    Ok(())
}

/// Whether only this user (and, on Windows, the system and the administrators, who can take any
/// file anyway) can reach `dir`: its mode on Unix, its access list on Windows. When it isn't, it is
/// made so (this user owns it); an error says it couldn't be.
pub fn ensure_private_dir(dir: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir)?.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    #[cfg(windows)]
    if !win::owner_only(dir)? {
        win::restrict_to_owner(dir)?;
        if !win::owner_only(dir)? {
            return Err(crate::Error::KeyStore(format!(
                "{} can be read by other users, and its access list couldn't be narrowed",
                dir.display()
            )));
        }
    }
    #[cfg(not(any(unix, windows)))]
    let _ = dir;
    Ok(())
}

/// Create a fresh file at `path` for writing: never an existing file (`O_EXCL`), never through a
/// symlink (`O_NOFOLLOW`), and, when `private`, 0600 from the start and again on the open file (so
/// a umask or an odd filesystem can't leave it wider).
fn create_fresh(path: &Path, private: bool) -> std::io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
        if private {
            opts.mode(0o600);
        }
    }
    let f = opts.open(path)?;
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    let _ = private;
    Ok(f)
}

/// A temporary name beside `path` that nobody can guess: `.<name>.<16 random hex>.tmp`.
fn temp_name(dir: &Path, name: &str) -> Result<std::path::PathBuf> {
    let mut r = [0u8; 8];
    getrandom::fill(&mut r).map_err(|e| crate::Error::Store(format!("no randomness: {e}")))?;
    let hex: String = r.iter().map(|b| format!("{b:02x}")).collect();
    Ok(dir.join(format!(".{name}.{hex}.tmp")))
}

/// Replace `path` with `bytes` so that a crash leaves either the old file or the new one: write a
/// fresh temporary file beside it (random name, created exclusively, no symlinks followed), fsync
/// it, rename it over, then fsync the directory. The temporary file is removed on any failure.
pub fn write_atomic(path: &Path, bytes: &[u8], private: bool) -> Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = temp_name(dir, &name)?;
    let written = (|| -> std::io::Result<()> {
        let mut f = create_fresh(&tmp, private)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path)
    })();
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.into());
    }
    sync_dir(dir);
    Ok(())
}

/// Fsync a directory so a rename or a new file in it survives a crash. Best effort: not every
/// platform can open a directory.
pub fn sync_dir(dir: &Path) {
    #[cfg(unix)]
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
    #[cfg(not(unix))]
    let _ = dir;
}

/// Open `path` for appending, creating it 0600. Never through a symlink; an existing file must be
/// a regular file this user owns, and is narrowed back to 0600 if something widened it.
pub fn open_append(path: &Path) -> Result<File> {
    let mut opts = OpenOptions::new();
    opts.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
        opts.custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
    }
    let f = opts.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let meta = f.metadata()?;
        if !meta.is_file() {
            return Err(crate::Error::Store(format!(
                "{} isn't a regular file",
                path.display()
            )));
        }
        if meta.uid() != rustix::process::getuid().as_raw() {
            return Err(crate::Error::Store(format!(
                "{} belongs to another user",
                path.display()
            )));
        }
        if meta.mode() & 0o077 != 0 {
            f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
    }
    Ok(f)
}

/// Whether every entry of `path`'s access list that grants anything names this user, the system
/// or the administrators.
#[cfg(windows)]
pub fn owner_only(path: &Path) -> Result<bool> {
    Ok(win::owner_only(path)?)
}

/// Owner-only access lists on Windows: the state and key folders get a protected DACL granting
/// only the current user (inherited by what is created inside), and are checked before keys are
/// read from them.
#[cfg(windows)]
#[allow(unsafe_code)]
mod win {
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr::{null, null_mut};

    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_SUCCESS, GENERIC_ALL, HANDLE, LocalFree,
    };
    use windows_sys::Win32::Security::Authorization::{
        EXPLICIT_ACCESS_W, GetNamedSecurityInfoW, NO_MULTIPLE_TRUSTEE, SE_FILE_OBJECT, SET_ACCESS,
        SetEntriesInAclW, SetNamedSecurityInfoW, TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_W,
    };
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation, CopySid,
        DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation, GetLengthSid,
        GetTokenInformation, IsWellKnownSid, PROTECTED_DACL_SECURITY_INFORMATION, PSID,
        SUB_CONTAINERS_AND_OBJECTS_INHERIT, TOKEN_QUERY, TOKEN_USER, TokenUser,
        WinBuiltinAdministratorsSid, WinLocalSystemSid,
    };
    use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    fn wide(p: &Path) -> Vec<u16> {
        p.as_os_str().encode_wide().chain(Some(0)).collect()
    }

    fn win_err(code: u32) -> io::Error {
        io::Error::from_raw_os_error(code as i32)
    }

    /// The current user's SID, copied out of the process token.
    fn user_sid() -> io::Result<Vec<u8>> {
        // SAFETY: plain Win32 calls with buffers sized as the API reports; the token handle is
        // closed on every path.
        unsafe {
            let mut token: HANDLE = null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return Err(io::Error::last_os_error());
            }
            let mut len = 0u32;
            GetTokenInformation(token, TokenUser, null_mut(), 0, &mut len);
            let mut buf = vec![0u8; len as usize];
            let ok = GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), len, &mut len);
            CloseHandle(token);
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            let tu = &*(buf.as_ptr() as *const TOKEN_USER);
            let sid_len = GetLengthSid(tu.User.Sid);
            let mut out = vec![0u8; sid_len as usize];
            if CopySid(sid_len, out.as_mut_ptr().cast(), tu.User.Sid) == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(out)
        }
    }

    /// Replace `path`'s DACL with one entry, the current user with full control, inherited by
    /// everything inside, and stop inheriting the parent's.
    pub fn restrict_to_owner(path: &Path) -> io::Result<()> {
        let mut sid = user_sid()?;
        let name = wide(path);
        // SAFETY: `sid` and `name` outlive the calls; the ACL SetEntriesInAclW allocates is freed
        // with LocalFree.
        unsafe {
            let ea = EXPLICIT_ACCESS_W {
                grfAccessPermissions: GENERIC_ALL,
                grfAccessMode: SET_ACCESS,
                grfInheritance: SUB_CONTAINERS_AND_OBJECTS_INHERIT,
                Trustee: TRUSTEE_W {
                    pMultipleTrustee: null_mut(),
                    MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                    TrusteeForm: TRUSTEE_IS_SID,
                    TrusteeType: TRUSTEE_IS_USER,
                    ptstrName: sid.as_mut_ptr().cast(),
                },
            };
            let mut acl: *mut ACL = null_mut();
            let r = SetEntriesInAclW(1, &ea, null(), &mut acl);
            if r != ERROR_SUCCESS {
                return Err(win_err(r));
            }
            let r = SetNamedSecurityInfoW(
                name.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                acl,
                null(),
            );
            LocalFree(acl.cast());
            if r != ERROR_SUCCESS {
                return Err(win_err(r));
            }
        }
        Ok(())
    }

    /// Whether every entry that grants access to `path` names the current user, the system or
    /// the administrators. A missing (null) DACL grants everyone everything: not owner-only.
    pub fn owner_only(path: &Path) -> io::Result<bool> {
        let mut me = user_sid()?;
        let name = wide(path);
        // SAFETY: the security descriptor GetNamedSecurityInfoW returns owns the DACL we walk, and
        // is freed with LocalFree after the walk; each ACE is read within the ACL's bounds as
        // GetAce reports them.
        unsafe {
            let mut dacl: *mut ACL = null_mut();
            let mut sd = null_mut();
            let r = GetNamedSecurityInfoW(
                name.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut sd,
            );
            if r != ERROR_SUCCESS {
                return Err(win_err(r));
            }
            let mut ok = !dacl.is_null();
            if ok {
                let mut info: ACL_SIZE_INFORMATION = std::mem::zeroed();
                if GetAclInformation(
                    dacl,
                    (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
                    std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                    AclSizeInformation,
                ) == 0
                {
                    LocalFree(sd);
                    return Err(io::Error::last_os_error());
                }
                for i in 0..info.AceCount {
                    let mut ace = null_mut();
                    if GetAce(dacl, i, &mut ace) == 0 {
                        ok = false;
                        break;
                    }
                    let header = &*(ace as *const ACE_HEADER);
                    if u32::from(header.AceType) != ACCESS_ALLOWED_ACE_TYPE {
                        // Deny entries only narrow access; other kinds aren't expected here.
                        continue;
                    }
                    let allowed = ace as *const ACCESS_ALLOWED_ACE;
                    let sid: PSID = (&raw const (*allowed).SidStart) as PSID;
                    let mine = EqualSid(sid, me.as_mut_ptr().cast()) != 0;
                    let trusted = IsWellKnownSid(sid, WinLocalSystemSid) != 0
                        || IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0;
                    if !mine && !trusted {
                        ok = false;
                        break;
                    }
                }
            }
            LocalFree(sd);
            Ok(ok)
        }
    }
}

#[cfg(test)]
pub(crate) fn temp_dir(tag: &str) -> std::path::PathBuf {
    let mut r = [0u8; 8];
    getrandom::fill(&mut r).unwrap();
    let hex: String = r.iter().map(|b| format!("{b:02x}")).collect();
    let d = std::env::temp_dir().join(format!("hooks-client-{tag}-{hex}"));
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_replaces_and_leaves_no_temp() {
        let dir = temp_dir("atomic");
        let p = dir.join("f.json");
        write_atomic(&p, b"one", false).unwrap();
        write_atomic(&p, b"two", false).unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"two");
        let names: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names.len(), 1);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn temp_names_are_random_and_created_exclusively() {
        let dir = temp_dir("tmpname");
        let a = temp_name(&dir, "f.json").unwrap();
        let b = temp_name(&dir, "f.json").unwrap();
        assert_ne!(a, b);
        let n = a.file_name().unwrap().to_string_lossy().into_owned();
        assert!(
            n.starts_with(".f.json.") && n.ends_with(".tmp") && n.len() == ".f.json.".len() + 20
        );
        // An existing file at the temporary name is never opened or truncated.
        std::fs::write(&a, b"someone else's").unwrap();
        assert!(create_fresh(&a, true).is_err());
        assert_eq!(std::fs::read(&a).unwrap(), b"someone else's");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_planted_symlink_is_never_followed() {
        let dir = temp_dir("symlink");
        let target = dir.join("target");
        std::fs::write(&target, b"keep").unwrap();
        let link = dir.join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(create_fresh(&link, true).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"keep");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn an_existing_append_file_is_narrowed_back_to_0600_and_never_a_symlink() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("append-mode");
        let p = dir.join("inbox.jsonl");
        std::fs::write(&p, b"x\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        let mut f = open_append(&p).unwrap();
        f.write_all(b"y\n").unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(std::fs::read(&p).unwrap(), b"x\ny\n");
        let target = dir.join("elsewhere");
        std::fs::write(&target, b"keep").unwrap();
        let link = dir.join("seen.jsonl");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(open_append(&link).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"keep");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_widened_private_dir_is_narrowed_again() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("dir-mode");
        let keys = dir.join("keys");
        create_private_dir(&keys).unwrap();
        std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o755)).unwrap();
        ensure_private_dir(&keys).unwrap();
        let mode = std::fs::metadata(&keys).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn a_private_dir_is_owner_only_on_windows_and_a_widened_one_is_narrowed() {
        let dir = temp_dir("acl");
        let keys = dir.join("keys");
        create_private_dir(&keys).unwrap();
        assert!(win::owner_only(&keys).unwrap());
        // A folder made the ordinary way inherits the temp folder's list, which is wider.
        let plain = dir.join("plain");
        std::fs::create_dir(&plain).unwrap();
        ensure_private_dir(&plain).unwrap();
        assert!(win::owner_only(&plain).unwrap());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn private_files_are_0600_whatever_the_umask_allows() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("mode");
        let p = dir.join("secret");
        write_atomic(&p, b"x", true).unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
