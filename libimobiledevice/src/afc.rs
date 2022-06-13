// Copyright 2020-2022 Yang Hongbo, Qingdao IotPi Information Technology, Ltd.
// This file is part of libimobiledeivce.
// libimobiledevice-rs is free software: you can redistribute it and/or
// modify it under the terms of the GNU General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
// libimobiledevice-rs is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// General Public License for more details.
// You should have received a copy of the GNU General Public License
// along with libimobiledevice-rs. If not, see <https://www.gnu.org/licenses/>.

use std::cell::RefCell;
use std::collections::HashMap;
use std::error::Error;
use std::ffi::{CStr, CString};
use std::fmt;
use std::os::raw::c_char;
use std::ptr::null_mut;
use std::rc::Rc;
use std::time::SystemTime;

use super::ffi;
use super::idevice::Device;
use super::lockdownd::LockdowndServiceDescriptor;

pub type AfcResult<T> = Result<T, AfcError>;

#[derive(Debug, Clone)]
pub struct AfcError(pub ffi::afc_error_t);

impl Error for AfcError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

impl fmt::Display for AfcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AfcError({})", self.0 as i32)
    }
}

type AfcClientRef = RefCell<ffi::afc_client_t>;
struct _AfcClient(AfcClientRef);

pub struct AfcClient(Rc<_AfcClient>);

impl Drop for _AfcClient {
    fn drop(&mut self) {
        unsafe {
            ffi::afc_client_free(*self.0.borrow());
        }
    }
}

impl AfcClient {
    pub fn new(device: &Device, service: &LockdowndServiceDescriptor) -> AfcResult<Self> {
        let mut client: ffi::afc_client_t = null_mut();
        let error =
            unsafe { ffi::afc_client_new(*device.0.borrow(), *service.0.borrow(), &mut client) };

        match error {
            ffi::afc_error_t::AFC_E_SUCCESS => Ok(Self(Rc::new(_AfcClient(RefCell::new(client))))),
            other => Err(AfcError(other)),
        }
    }

    pub fn file_open(
        &self,
        filename: &str,
        file_mode: ffi::afc_file_mode_t,
    ) -> AfcResult<FileHandle> {
        FileHandle::open(self.0.clone(), filename, file_mode)
    }

    pub fn get_device_info(&self) -> AfcResult<HashMap<String, String>> {
        let mut device_info_pp: *mut *mut c_char = null_mut();
        let error =
            unsafe { ffi::afc_get_device_info(*(self.0.as_ref().0.borrow()), &mut device_info_pp) };

        match error {
            ffi::afc_error_t::AFC_E_SUCCESS => {
                assert!(!device_info_pp.is_null());
                let mut device_info = HashMap::<String, String>::new();

                let mut key: Option<String> = None;
                for i in 0.. {
                    unsafe {
                        let p = device_info_pp.offset(i);
                        let first_byte = p.read_unaligned() as i8;
                        if first_byte == 0 {
                            break;
                        }
                        let cstr = CStr::from_ptr(*p);
                        if let Ok(str) = cstr.to_str() {
                            let s = str.to_string();
                            if let Some(key) = key.take() {
                                device_info.insert(key, s);
                            } else {
                                key = Some(s);
                            }
                        } else {
                            // failed to extract c string
                            return Err(AfcError(ffi::afc_error_t::AFC_E_INTERNAL_ERROR));
                        }
                    }
                }
                let _error = unsafe { ffi::afc_dictionary_free(device_info_pp) };
                Ok(device_info)
            }
            other => Err(AfcError(other)),
        }
    }

    pub fn remove_path(&self, path: &str) -> AfcResult<()> {
        let file_path =
            CString::new(path).map_err(|_| AfcError(ffi::afc_error_t::AFC_E_INVALID_ARG))?;
        let error =
            unsafe { ffi::afc_remove_path(*self.0.as_ref().0.borrow(), file_path.as_ptr()) };

        match error {
            ffi::afc_error_t::AFC_E_SUCCESS => Ok(()),
            other => Err(AfcError(other)),
        }
    }

    pub fn rename_path(&self, from: &str, to: &str) -> AfcResult<()> {
        let from = CString::new(from).map_err(|_| AfcError(ffi::afc_error_t::AFC_E_INVALID_ARG))?;
        let to = CString::new(to).map_err(|_| AfcError(ffi::afc_error_t::AFC_E_INVALID_ARG))?;
        let error = unsafe {
            ffi::afc_rename_path(*self.0.as_ref().0.borrow(), from.as_ptr(), to.as_ptr())
        };

        match error {
            ffi::afc_error_t::AFC_E_SUCCESS => Ok(()),
            other => Err(AfcError(other)),
        }
    }

    pub fn make_directory(&self, path: &str) -> AfcResult<()> {
        let path = CString::new(path).map_err(|_| AfcError(ffi::afc_error_t::AFC_E_INVALID_ARG))?;
        let error = unsafe { ffi::afc_make_directory(*self.0.as_ref().0.borrow(), path.as_ptr()) };

        match error {
            ffi::afc_error_t::AFC_E_SUCCESS => Ok(()),
            other => Err(AfcError(other)),
        }
    }

    pub fn truncate(&self, path: &str, newsize: u64) -> AfcResult<()> {
        let path = CString::new(path).map_err(|_| AfcError(ffi::afc_error_t::AFC_E_INVALID_ARG))?;
        let error =
            unsafe { ffi::afc_truncate(*self.0.as_ref().0.borrow(), path.as_ptr(), newsize) };

        match error {
            ffi::afc_error_t::AFC_E_SUCCESS => Ok(()),
            other => Err(AfcError(other)),
        }
    }

    pub fn make_link(
        &self,
        link_type: ffi::afc_link_type_t,
        target: &str,
        link: &str,
    ) -> AfcResult<()> {
        let target =
            CString::new(target).map_err(|_| AfcError(ffi::afc_error_t::AFC_E_INVALID_ARG))?;
        let link = CString::new(link).map_err(|_| AfcError(ffi::afc_error_t::AFC_E_INVALID_ARG))?;
        let error = unsafe {
            ffi::afc_make_link(
                *self.0.as_ref().0.borrow(),
                link_type,
                target.as_ptr(),
                link.as_ptr(),
            )
        };

        match error {
            ffi::afc_error_t::AFC_E_SUCCESS => Ok(()),
            other => Err(AfcError(other)),
        }
    }

    pub fn set_file_time(&self, path: &str, mtime: SystemTime) -> AfcResult<()> {
        let path = CString::new(path).map_err(|_| AfcError(ffi::afc_error_t::AFC_E_INVALID_ARG))?;

        let dur = match mtime.duration_since(SystemTime::UNIX_EPOCH) {
            Ok(duration) => duration,
            // Is this usage correct?
            Err(earlier) => earlier.duration(),
        };

        let file_time = dur.as_nanos() as u64;
        let error = unsafe {
            ffi::afc_set_file_time(*self.0.as_ref().0.borrow(), path.as_ptr(), file_time)
        };

        match error {
            ffi::afc_error_t::AFC_E_SUCCESS => Ok(()),
            other => Err(AfcError(other)),
        }
    }

    pub fn remove_path_and_contents(&self, path: &str) -> AfcResult<()> {
        let path = CString::new(path).map_err(|_| AfcError(ffi::afc_error_t::AFC_E_INVALID_ARG))?;
        let error = unsafe {
            ffi::afc_remove_path_and_contents(*self.0.as_ref().0.borrow(), path.as_ptr())
        };

        match error {
            ffi::afc_error_t::AFC_E_SUCCESS => Ok(()),
            other => Err(AfcError(other)),
        }
    }
}

pub struct FileHandle {
    handle: u64,
    afc: Rc<_AfcClient>,
}

impl FileHandle {
    fn open(
        afc: Rc<_AfcClient>,
        filename: &str,
        file_mode: ffi::afc_file_mode_t,
    ) -> AfcResult<Self> {
        let filename =
            CString::new(filename).map_err(|_| AfcError(ffi::afc_error_t::AFC_E_INVALID_ARG))?;
        let mut handle: u64 = 0;
        let error = unsafe {
            ffi::afc_file_open(*afc.0.borrow(), filename.as_ptr(), file_mode, &mut handle)
        };
        match error {
            ffi::afc_error_t::AFC_E_SUCCESS => Ok(Self { handle, afc }),
            other => Err(AfcError(other)),
        }
    }

    pub fn lock(&self, operation: ffi::afc_lock_op_t) -> AfcResult<()> {
        let error = unsafe { ffi::afc_file_lock(*self.afc.0.borrow(), self.handle, operation) };
        match error {
            ffi::afc_error_t::AFC_E_SUCCESS => Ok(()),
            other => Err(AfcError(other)),
        }
    }

    pub fn read(&self, data: &mut dyn AsMut<Vec<u8>>, length: u32) -> AfcResult<u32> {
        let mut read_length = 0u32;
        let out_data = data.as_mut();

        if out_data.len() < (length as usize) {
            return Err(AfcError(ffi::afc_error_t::AFC_E_INVALID_ARG));
        }
        let error = unsafe {
            ffi::afc_file_read(
                *self.afc.0.borrow(),
                self.handle,
                out_data.as_mut_ptr() as *mut c_char,
                length,
                &mut read_length,
            )
        };

        match error {
            ffi::afc_error_t::AFC_E_SUCCESS => Ok(read_length),
            other => Err(AfcError(other)),
        }
    }

    pub fn write(&self, data: &[u8]) -> AfcResult<u32> {
        let mut bytes: u32 = 0;
        let error = unsafe {
            ffi::afc_file_write(
                *self.afc.0.borrow(),
                self.handle,
                data.as_ptr() as *const c_char,
                data.len() as u32,
                &mut bytes,
            )
        };

        match error {
            ffi::afc_error_t::AFC_E_SUCCESS => Ok(bytes),
            other => Err(AfcError(other)),
        }
    }

    pub fn seek(&self, offset: i64, whence: i32) -> AfcResult<()> {
        let error =
            unsafe { ffi::afc_file_seek(*self.afc.0.borrow(), self.handle, offset, whence) };

        match error {
            ffi::afc_error_t::AFC_E_SUCCESS => Ok(()),
            other => Err(AfcError(other)),
        }
    }

    pub fn tell(&self) -> AfcResult<u64> {
        let mut position: u64 = 0;
        let error = unsafe { ffi::afc_file_tell(*self.afc.0.borrow(), self.handle, &mut position) };

        match error {
            ffi::afc_error_t::AFC_E_SUCCESS => Ok(position),
            other => Err(AfcError(other)),
        }
    }

    pub fn truncate(&self, newsize: u64) -> AfcResult<()> {
        let error = unsafe { ffi::afc_file_truncate(*self.afc.0.borrow(), self.handle, newsize) };

        match error {
            ffi::afc_error_t::AFC_E_SUCCESS => Ok(()),
            other => Err(AfcError(other)),
        }
    }
}

impl Drop for FileHandle {
    fn drop(&mut self) {
        unsafe {
            let error = ffi::afc_file_close(*self.afc.0.borrow(), self.handle);
            if error != ffi::afc_error_t::AFC_E_SUCCESS {
                eprintln!("failed to afc_file_close: {}", error as i32);
            }
        }
    }
}
