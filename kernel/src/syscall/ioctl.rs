// SPDX-License-Identifier: MPL-2.0
use ostd::early_println;
use super::SyscallReturn;
use crate::{
    fs::{
        file_table::{FdFlags, FileDesc},
        utils::{IoctlCmd, StatusFlags},
    },
    prelude::*,
    crypto::crypto::{encrypt, decrypt},
};

pub fn sys_ioctl(fd: FileDesc, cmd: u32, arg: Vaddr, ctx: &Context) -> Result<SyscallReturn> {
    let ioctl_cmd = IoctlCmd::try_from(cmd)?;
    debug!(
        "fd = {}, ioctl_cmd = {:?}, arg = 0x{:x}",
        fd, ioctl_cmd, arg
    );

    let file = {
        let file_table = ctx.process.file_table().lock();
        file_table.get_file(fd)?.clone()
    };
    let res = match ioctl_cmd {
        IoctlCmd::FIONBIO => {
            let is_nonblocking = ctx.user_space().read_val::<i32>(arg)? != 0;
            let mut flags = file.status_flags();
            flags.set(StatusFlags::O_NONBLOCK, is_nonblocking);
            file.set_status_flags(flags)?;
            0
        }
        IoctlCmd::FIOASYNC => {
            let is_async = ctx.user_space().read_val::<i32>(arg)? != 0;
            let mut flags = file.status_flags();

            // Set `O_ASYNC` flags will send `SIGIO` signal to a process when
            // I/O is possible, user should call `fcntl(fd, F_SETOWN, pid)`
            // first to let the kernel know just whom to notify.
            flags.set(StatusFlags::O_ASYNC, is_async);
            file.set_status_flags(flags)?;
            0
        }
        IoctlCmd::FIOCLEX => {
            // Sets the close-on-exec flag of the file.
            // Follow the implementation of fcntl()

            let flags = FdFlags::CLOEXEC;
            let file_table = ctx.process.file_table().lock();
            let entry = file_table.get_entry(fd)?;
            entry.set_flags(flags);
            0
        }
        IoctlCmd::FIONCLEX => {
            // Clears the close-on-exec flag of the file.
            let file_table = ctx.process.file_table().lock();
            let entry = file_table.get_entry(fd)?;
            entry.set_flags(entry.flags() & (!FdFlags::CLOEXEC));
            0
        }
        IoctlCmd::CIOCCRYPT => {
            // Encrypt
            let max_string_len = 256;
            let input: CString = read_cstring_vec(arg, max_string_len, ctx)?;
            let input_bytes: &[u8] = input.as_bytes();
            encrypt(input_bytes);
            0
        }
        IoctlCmd::CIOCXCRYPT => {
            // Decrypt
            decrypt();
            0
        }
        _ => file.ioctl(ioctl_cmd, arg)?,
    };
    Ok(SyscallReturn::Return(res as _))
}

fn read_cstring_vec(
    read_ptr: Vaddr,
    max_string_len: usize,
    ctx: &Context,
) -> Result<CString> {
    let mut res = CString::default();
    // On Linux, argv pointer and envp pointer can be specified as NULL.
    if read_ptr == 0 {
        return Ok(res);
    }
    let user_space = ctx.user_space();
    let cstring_ptr = user_space.read_val::<usize>(read_ptr)?;
    if cstring_ptr == 0 {
        return_errno_with_message!(Errno::E2BIG, "Cannot find null pointer in vector");
    }
    let cstring = user_space.read_cstring(cstring_ptr, max_string_len)?;
    early_println!("{:?} {:?}", cstring_ptr, cstring);
    res = cstring;
    Ok(res)
}