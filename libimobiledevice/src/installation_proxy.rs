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

use super::ffi;
use super::idevice::Device;
use super::lockdownd::LockdowndServiceDescriptor;
use libplist::{ffi::plist_t, plist::Plist};
use std::cell::RefCell;
use std::collections::HashMap;
use std::error::Error;
use std::ffi::CString;
use std::fmt;
use std::ptr::null_mut;
use std::rc::Rc;

pub type InstproxyResult<T> = Result<T, InstproxyError>;

#[derive(Debug, Clone)]
pub struct InstproxyError(ffi::instproxy_error_t);

impl Error for InstproxyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

impl fmt::Display for InstproxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "InstproxyError({})", self.0 as i32)
    }
}

type InstproxyClientRef = RefCell<ffi::instproxy_client_t>;
pub struct InstproxyClient {
    client: InstproxyClientRef,
    _device: Rc<Device>,
}

impl InstproxyClient {
    pub fn new(device: Rc<Device>, service: &LockdowndServiceDescriptor) -> InstproxyResult<Self> {
        let mut client: ffi::instproxy_client_t = null_mut();
        let error = unsafe {
            ffi::instproxy_client_new(*device.0.borrow(), *service.0.borrow(), &mut client)
        };

        match error {
            ffi::instproxy_error_t::INSTPROXY_E_SUCCESS => Ok(Self {
                client: RefCell::new(client),
                _device: device,
            }),
            other => Err(InstproxyError(other)),
        }
    }

    pub fn start_service(device: Rc<Device>, label: &str) -> InstproxyResult<Self> {
        let label = CString::new(label).expect("failed to convert str");
        let mut client: ffi::instproxy_client_t = null_mut();
        let error = unsafe {
            ffi::instproxy_client_start_service(*device.0.borrow(), &mut client, label.as_ptr())
        };

        match error {
            ffi::instproxy_error_t::INSTPROXY_E_SUCCESS => Ok(Self {
                client: RefCell::new(client),
                _device: device,
            }),
            other => Err(InstproxyError(other)),
        }
    }

    pub fn browse(&self, options: &ClientOptions) -> InstproxyResult<Option<Plist>> {
        let mut apps: plist_t = null_mut();
        if let Some(options_node) = options.0.node() {
            let error = unsafe {
                ffi::instproxy_browse(*self.client.borrow(), *options_node.borrow(), &mut apps)
            };
            match error {
                ffi::instproxy_error_t::INSTPROXY_E_SUCCESS => Ok(Plist::from_raw(apps)),
                other => Err(InstproxyError(other)),
            }
        } else {
            Err(InstproxyError(
                ffi::instproxy_error_t::INSTPROXY_E_PLIST_ERROR,
            ))
        }
    }
}

pub enum OptionsType {
    String(String),
    Bool(bool),
    Plist(Plist),
}

pub struct ClientOptions(Plist);

impl ClientOptions {
    pub fn new() -> Option<Self> {
        let plist = unsafe { ffi::instproxy_client_options_new() };

        let plist = Plist::from_raw(plist)?;
        Some(Self(plist))
    }

    pub fn add(&mut self, options: HashMap<String, OptionsType>) {
        for (key, value) in options {
            match value {
                OptionsType::String(value) => {
                    if let Some(value) = Plist::new_string(&value) {
                        self.0.dict_set_item(&key, value);
                    }
                }
                OptionsType::Bool(value) => {
                    if let Some(value) = Plist::new_bool(value) {
                        self.0.dict_set_item(&key, value);
                    }
                }
                OptionsType::Plist(value) => {
                    self.0.dict_set_item(&key, value);
                }
            }
        }
    }

    pub fn set_return_attributes(&mut self, attributes: Vec<String>) {
        if let Some(mut plist) = Plist::new_array() {
            for attr in attributes {
                if let Some(attr) = Plist::new_string(&attr) {
                    plist.array_append_item(attr);
                }
            }
            self.0.dict_set_item("ReturnAttributes", plist);
        }
    }
}

impl fmt::Debug for ClientOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ClientOptions {{ {:#?} }}", self.0)
    }
}
