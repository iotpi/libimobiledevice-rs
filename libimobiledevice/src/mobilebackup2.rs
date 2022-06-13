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
use std::rc::Rc;

use std::error::Error;
use std::ffi::{CStr, CString};
use std::fmt;
use std::io;
use std::mem::size_of;
use std::os::raw::{c_char, c_void};
use std::ptr::{null, null_mut};

use libc;
use paste;

use libplist::plist::{plist_t, Plist};

use super::ffi;
use super::idevice::Device;
use super::lockdownd::LockdowndServiceDescriptor;

pub type Mobilebackup2Result<T> = Result<T, Mobilebackup2Error>;

#[derive(Debug, Clone)]
pub struct Mobilebackup2Error(pub ffi::mobilebackup2_error_t);

impl Error for Mobilebackup2Error {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

impl fmt::Display for Mobilebackup2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Mobilebackup2Error({})", self.0 as i32)
    }
}

type Mobilebackup2ClientRef = RefCell<ffi::mobilebackup2_client_t>;

pub struct Mobilebackup2Client {
    pub(crate) client: Mobilebackup2ClientRef,
    pub(crate) _device: Rc<Device>,
}

#[derive(Debug)]
pub enum ReceivedMessage {
    DownloadFiles(Plist),       // DLMessageDownloadFiles
    UploadFiles(Plist),         // DLMessageUploadFiles
    MoveFiles(Plist),           // DLMessageMoveFiles
    MoveItems(Plist),           // DLMessageMoveItems
    RemoveFiles(Plist),         // DLMessageRemoveFiles
    RemoveItems(Plist),         // DLMessageRemoveItems
    CopyItem(Plist),            // DLMessageCopyItem
    GetFreeDiskSpace,           // DLMessageGetFreeDiskSpace
    ContentsOfDirectory(Plist), // DLContentsofdirectory
    CreateDirectory(Plist),     // DLMessageCreatedirectory
    Disconnect,                 // DLMessageDisconnect
    ProcessMessage(Plist),      // DLMessageProcessMessage
    PurgeDiskSpace,             // DLMessagePurgeDiskSpace
    Unknown(String),            // not handled
    None,                       // not returned
}

// #[derive(Debug)]
// pub struct ReceivedMessage {
//     pub message: Plist,
//     pub ident: ReceivedMessageType,
// }

macro_rules! impl_receive_raw {
    ($vis:vis, $ty:ident) => {
        paste::item! {
            $vis fn [<receive_raw_ $ty>](&self) -> Mobilebackup2Result<$ty>
            {
                let mut data:$ty = 0;
                let size_of_type = size_of::<$ty>();
                let length = size_of_type as u32;
                let mut read_length: u32 = 0;

                let error = unsafe {
                    let pointer: *mut $ty = &mut data;
                    ffi::mobilebackup2_receive_raw(*self.client.borrow(), pointer.cast::<c_char>(), length, &mut read_length)
                };

                if 0 == read_length {
                    return Err(Mobilebackup2Error(ffi::mobilebackup2_error_t::MOBILEBACKUP2_E_RECEIVE_TIMEOUT));
                }

                match error {
                    ffi::mobilebackup2_error_t::MOBILEBACKUP2_E_SUCCESS => {
                        let data = data.to_be();
                        Ok(data)
                    },
                    other => Err(Mobilebackup2Error(other)),
                }
            }
        }
    };
}

macro_rules! impl_send_raw {
    ($vis:vis, $ty:ident) => {
        paste::item! {
            $vis fn [<send_raw_ $ty>](&self, data: $ty) -> Mobilebackup2Result<()>
            {

                let data = data.to_be_bytes();
                let mut bytes: u32 = 0;
                let error = unsafe {
                    ffi::mobilebackup2_send_raw(*self.client.borrow(), data.as_ptr() as *const c_char, data.len() as u32, &mut bytes)
                };
                match error {
                    ffi::mobilebackup2_error_t::MOBILEBACKUP2_E_SUCCESS => {
                        Ok(())
                    },
                    other => Err(Mobilebackup2Error(other))
                }
            }
        }
    };
}

impl Mobilebackup2Client {
    pub fn new(
        device: Rc<Device>,
        service: &LockdowndServiceDescriptor,
    ) -> Mobilebackup2Result<Self> {
        let mut client: ffi::mobilebackup2_client_t = null_mut();
        let error = unsafe {
            ffi::mobilebackup2_client_new(*device.0.borrow(), *service.0.borrow(), &mut client)
        };

        match error {
            ffi::mobilebackup2_error_t::MOBILEBACKUP2_E_SUCCESS => Ok(Self {
                client: RefCell::new(client),
                _device: device,
            }),
            other => Err(Mobilebackup2Error(other)),
        }
    }

    pub fn version_exchange(&self, local_versions: &[f64]) -> Mobilebackup2Result<f64> {
        let mut remote_version: f64 = 0.0;
        let error = unsafe {
            ffi::mobilebackup2_version_exchange(
                *self.client.borrow(),
                local_versions.as_ptr() as *mut _,
                local_versions.len() as c_char,
                &mut remote_version,
            )
        };
        match error {
            ffi::mobilebackup2_error_t::MOBILEBACKUP2_E_SUCCESS => Ok(remote_version),
            other => Err(Mobilebackup2Error(other)),
        }
    }

    pub fn send_request(
        &self,
        request: &str,
        target_identifier: &str,
        source_identifier: Option<&str>,
        options: Option<&Plist>,
    ) -> Mobilebackup2Result<()> {
        let request = CString::new(request).map_err(|_| {
            Mobilebackup2Error(ffi::mobilebackup2_error_t::MOBILEBACKUP2_E_INVALID_ARG)
        })?;

        let target_identifier = CString::new(target_identifier).map_err(|_| {
            Mobilebackup2Error(ffi::mobilebackup2_error_t::MOBILEBACKUP2_E_INVALID_ARG)
        })?;

        let source: Option<CString>;
        if let Some(source_identifier) = source_identifier {
            source = Some(CString::new(source_identifier).map_err(|_| {
                Mobilebackup2Error(ffi::mobilebackup2_error_t::MOBILEBACKUP2_E_INVALID_ARG)
            })?);
        } else {
            source = None;
        }

        let request: *const c_char = request.as_ptr();
        let target_identifier: *const c_char = target_identifier.as_ptr();
        // use &source to preventing from deallocting
        let source_identifier: *const c_char = if let Some(s) = &source {
            s.as_ptr()
        } else {
            null()
        };

        let options = if let Some(plist) = options {
            Plist::into_raw(plist.clone())
        } else {
            null_mut()
        };

        let error = unsafe {
            ffi::mobilebackup2_send_request(
                *self.client.borrow(),
                request,
                target_identifier,
                source_identifier,
                options,
            )
        };

        Plist::from_raw(options);

        match error {
            ffi::mobilebackup2_error_t::MOBILEBACKUP2_E_SUCCESS => Ok(()),
            other => Err(Mobilebackup2Error(other)),
        }
    }

    pub fn receive_message(&self) -> Mobilebackup2Result<ReceivedMessage> {
        let mut plist: plist_t = null_mut();
        let mut message: *mut c_char = null_mut();
        let error = unsafe {
            ffi::mobilebackup2_receive_message(*self.client.borrow(), &mut plist, &mut message)
        };
        match error {
            ffi::mobilebackup2_error_t::MOBILEBACKUP2_E_SUCCESS => {
                if let Some(plist) = Plist::from_raw(plist) {
                    let received_message: ReceivedMessage;
                    if !message.is_null() {
                        let message = unsafe { CStr::from_ptr(message).to_str() };
                        let message = message.map_err(|err| {
                            eprintln!(
                                "{}",
                                format!(
                                    "failed to convert CStr to str({}) ({} @ {})",
                                    err,
                                    std::file!(),
                                    std::line!()
                                )
                                .as_str()
                            );

                            Mobilebackup2Error(
                                ffi::mobilebackup2_error_t::MOBILEBACKUP2_E_UNKNOWN_ERROR,
                            )
                        })?;
                        received_message = match message {
                            "DLMessageDownloadFiles" => ReceivedMessage::DownloadFiles(plist),
                            "DLMessageUploadFiles" => ReceivedMessage::UploadFiles(plist),
                            "DLMessageMoveFiles" => ReceivedMessage::MoveFiles(plist),
                            "DLMessageMoveItems" => ReceivedMessage::MoveItems(plist),
                            "DLMessageCopyItem" => ReceivedMessage::CopyItem(plist),
                            "DLMessageRemoveFiles" => ReceivedMessage::RemoveFiles(plist),
                            "DLMessageRemoveItems" => ReceivedMessage::RemoveItems(plist),
                            "DLMessageProcessMessage" => ReceivedMessage::ProcessMessage(plist),
                            "DLMessageGetFreeDiskSpace" => ReceivedMessage::GetFreeDiskSpace,
                            "DLContentsOfDirectory" => ReceivedMessage::ContentsOfDirectory(plist),
                            "DLMessageCreateDirectory" => ReceivedMessage::CreateDirectory(plist),
                            other => ReceivedMessage::Unknown(String::from(other)),
                        };
                    } else {
                        received_message = ReceivedMessage::None;
                    }
                    Ok(received_message)
                } else {
                    Err(Mobilebackup2Error(
                        ffi::mobilebackup2_error_t::MOBILEBACKUP2_E_PLIST_ERROR,
                    ))
                }
            }
            other => Err(Mobilebackup2Error(other)),
        }
    }

    // out_data is a pre allocated Vec<u8> as buffer,
    // length is the length of data need to be read
    // length is less or equal than length of out_data
    pub fn receive_raw(
        &self,
        out_data: &mut dyn AsMut<Vec<u8>>,
        length: u32,
    ) -> Mobilebackup2Result<u32> {
        let mut read_length: u32 = 0;
        let out_data = out_data.as_mut();
        if out_data.len() < (length as usize) {
            return Err(Mobilebackup2Error(
                ffi::mobilebackup2_error_t::MOBILEBACKUP2_E_INVALID_ARG,
            ));
        }
        let error = unsafe {
            ffi::mobilebackup2_receive_raw(
                *self.client.borrow(),
                out_data.as_mut_ptr() as *mut c_char,
                length,
                &mut read_length,
            )
        };

        if 0 == read_length {
            return Err(Mobilebackup2Error(
                ffi::mobilebackup2_error_t::MOBILEBACKUP2_E_RECEIVE_TIMEOUT,
            ));
        }

        match error {
            ffi::mobilebackup2_error_t::MOBILEBACKUP2_E_SUCCESS => Ok(read_length),
            other => Err(Mobilebackup2Error(other)),
        }
    }

    impl_receive_raw!(pub, u32);
    impl_receive_raw!(pub, i8);
    impl_receive_raw!(pub, u8);

    pub fn send_raw(&self, data: &[u8]) -> Mobilebackup2Result<()> {
        let mut bytes: u32 = 0;
        let error = unsafe {
            ffi::mobilebackup2_send_raw(
                *self.client.borrow(),
                data.as_ptr() as *const c_char,
                data.len() as u32,
                &mut bytes,
            )
        };
        match error {
            ffi::mobilebackup2_error_t::MOBILEBACKUP2_E_SUCCESS => Ok(()),
            other => Err(Mobilebackup2Error(other)),
        }
    }

    impl_send_raw!(pub, u32);
    impl_send_raw!(pub, i8);

    pub fn send_status_response(
        &self,
        status_code: i32,
        status1: Option<&str>,
        status2: Option<Plist>,
    ) -> Mobilebackup2Result<()> {
        let status1: Option<CString> = if let Some(value) = status1 {
            CString::new(value)
                .map_err(|_| {
                    Mobilebackup2Error(ffi::mobilebackup2_error_t::MOBILEBACKUP2_E_INVALID_ARG)
                })
                .ok()
        } else {
            None
        };

        // use reference to prevent from status1 being deallocted
        let status1_cstr: *const c_char = if let Some(status1) = &status1 {
            status1.as_ptr()
        } else {
            null()
        };

        let errplist: plist_t = if let Some(plist) = status2 {
            Plist::into_raw(plist)
        } else {
            null_mut()
        };

        let error = unsafe {
            ffi::mobilebackup2_send_status_response(
                *self.client.borrow(),
                status_code,
                status1_cstr,
                errplist,
            )
        };

        Plist::from_raw(errplist);

        match error {
            ffi::mobilebackup2_error_t::MOBILEBACKUP2_E_SUCCESS => Ok(()),
            other => Err(Mobilebackup2Error(other)),
        }
    }

    pub fn send_os_status_response(
        &self,
        errno: i32,
        desc: Option<&str>,
    ) -> Mobilebackup2Result<()> {
        let cstr: Option<CString> = if let Some(desc) = desc {
            CString::new(desc).ok()
        } else {
            None
        };

        let errstr: *const c_char = if let Some(cstr) = &cstr {
            cstr.as_ptr()
        } else {
            let errstr = unsafe { libc::strerror(errno) };
            errstr as *const c_char
        };

        let error = unsafe {
            ffi::mobilebackup2_send_status_response(
                *self.client.borrow(),
                errno,
                errstr,
                null_mut(),
            )
        };

        if cstr.is_none() {
            unsafe { libc::free(errstr as *mut c_void) };
        }

        match error {
            ffi::mobilebackup2_error_t::MOBILEBACKUP2_E_SUCCESS => Ok(()),
            other => Err(Mobilebackup2Error(other)),
        }
    }

    pub fn send_last_os_status_response(&self) -> Mobilebackup2Result<io::Error> {
        let oserror = io::Error::last_os_error();
        let errno = oserror.raw_os_error().unwrap();
        self.send_os_status_response(errno, None)?;

        Ok(oserror)
    }
}

impl Drop for Mobilebackup2Client {
    fn drop(&mut self) {
        unsafe {
            ffi::mobilebackup2_client_free(*self.client.borrow());
        }
    }
}

impl ReceivedMessage {
    pub fn overall_progress(&self) -> f64 {
        let item: Option<Plist> = match &self {
            ReceivedMessage::DownloadFiles(plist) => plist.array_get_item(3),
            ReceivedMessage::UploadFiles(plist) => plist.array_get_item(2),
            ReceivedMessage::MoveFiles(plist) | ReceivedMessage::MoveItems(plist) => {
                plist.array_get_item(3)
            }
            ReceivedMessage::RemoveFiles(plist) | ReceivedMessage::RemoveItems(plist) => {
                plist.array_get_item(3)
            }
            _ => None,
        };

        if let Some(plist) = item {
            plist.real_value().unwrap_or(0.0)
        } else {
            0.0
        }
    }
}
