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

use std::ffi::CString;
use std::os::raw::c_char;
use std::ptr::null_mut;

use libplist::{ffi::plist_t, plist::Plist};
use std::error::Error;
use std::fmt;

use super::ffi;
use super::idevice::Device;

pub type LockdowndResult<T> = Result<T, LockdowndError>;

#[derive(Debug, Clone)]
pub struct LockdowndError(ffi::lockdownd_error_t);

impl Error for LockdowndError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

impl fmt::Display for LockdowndError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LockdowndError({})", self.0 as i32)
    }
}

type LockdowndClientRef = RefCell<ffi::lockdownd_client_t>;

pub struct LockdownPairRecord {}

pub struct LockdowndClient {
    pub(crate) client: LockdowndClientRef,
    pub(crate) _device: Rc<Device>,
}

impl LockdowndClient {
    pub fn new_simple(device: Rc<Device>, label: &str) -> LockdowndResult<LockdowndClient> {
        Self::internal_new(device, label, true)
    }

    pub fn new_with_handshake(device: Rc<Device>, label: &str) -> LockdowndResult<LockdowndClient> {
        Self::internal_new(device, label, false)
    }

    fn internal_new(
        device: Rc<Device>,
        label: &str,
        is_simple: bool,
    ) -> LockdowndResult<LockdowndClient> {
        let mut client: ffi::lockdownd_client_t = null_mut();

        let error: ffi::lockdownd_error_t;
        let cstr = CString::new(label).expect("Failed to convert label");
        if is_simple {
            unsafe {
                error = ffi::lockdownd_client_new(*device.0.borrow(), &mut client, cstr.as_ptr());
            }
        } else {
            unsafe {
                error = ffi::lockdownd_client_new_with_handshake(
                    *device.0.borrow(),
                    &mut client,
                    cstr.as_ptr(),
                );
            }
        }
        match error {
            ffi::lockdownd_error_t::LOCKDOWN_E_SUCCESS => Ok(Self {
                client: RefCell::new(client),
                _device: device,
            }),
            other => Err(LockdowndError(other)),
        }
    }

    pub fn set_value(
        &self,
        domain: Option<&str>,
        key: Option<&str>,
        value: Plist,
    ) -> LockdowndResult<()> {
        let domain_cstr_p: *mut c_char;
        if let Some(domain) = domain {
            domain_cstr_p = CString::new(domain)
                .expect("failed to convert domain to cstr")
                .into_raw();
        } else {
            domain_cstr_p = null_mut();
        }

        let key_cstr_p: *mut c_char;
        if let Some(key) = key {
            key_cstr_p = CString::new(key)
                .expect("failed to convert key to cstr")
                .into_raw();
        } else {
            key_cstr_p = null_mut();
        }

        let error;
        unsafe {
            let domain_ptr = domain_cstr_p;
            let key_ptr = key_cstr_p;
            let value_ptr = Plist::into_raw(value);
            error = ffi::lockdownd_set_value(*self.client.borrow(), domain_ptr, key_ptr, value_ptr);
            if !domain_cstr_p.is_null() {
                let _ = CString::from_raw(domain_cstr_p);
            }
            if !key_cstr_p.is_null() {
                let _ = CString::from_raw(key_cstr_p);
            }
        }

        match error {
            ffi::lockdownd_error_t::LOCKDOWN_E_SUCCESS => Ok(()),
            other => Err(LockdowndError(other)),
        }
    }

    pub fn get_value(
        &self,
        domain: Option<&str>,
        key: Option<&str>,
    ) -> LockdowndResult<Option<Plist>> {
        let domain_cstr_p: *mut c_char;
        if let Some(domain) = domain {
            domain_cstr_p = CString::new(domain)
                .expect("failed to convert domain to cstr")
                .into_raw();
        } else {
            domain_cstr_p = null_mut();
        }

        let key_cstr_p: *mut c_char;
        if let Some(key) = key {
            key_cstr_p = CString::new(key)
                .expect("failed to convert key to cstr")
                .into_raw();
        } else {
            key_cstr_p = null_mut();
        }

        let mut value: plist_t = null_mut();
        let error;
        unsafe {
            let domain_ptr = domain_cstr_p;
            let key_ptr = key_cstr_p;
            error =
                ffi::lockdownd_get_value(*self.client.borrow(), domain_ptr, key_ptr, &mut value);
            if !domain_cstr_p.is_null() {
                let _ = CString::from_raw(domain_cstr_p);
            }
            if !key_cstr_p.is_null() {
                let _ = CString::from_raw(key_cstr_p);
            }
        }

        match error {
            ffi::lockdownd_error_t::LOCKDOWN_E_SUCCESS => Ok(Plist::from_raw(value)),
            other => Err(LockdowndError(other)),
        }
    }

    pub fn validate_pair(&self, _record: Option<LockdownPairRecord>) -> LockdowndResult<()> {
        let error = unsafe { ffi::lockdownd_validate_pair(*self.client.borrow(), null_mut()) };
        match error {
            ffi::lockdownd_error_t::LOCKDOWN_E_SUCCESS => Ok(()),
            other => Err(LockdowndError(other)),
        }
    }

    pub fn start_service(&self, identifier: &[u8]) -> LockdowndResult<LockdowndServiceDescriptor> {
        let service = LockdowndServiceDescriptor::new();
        let error = unsafe {
            ffi::lockdownd_start_service(
                *self.client.borrow(),
                identifier.as_ptr() as *mut c_char,
                &mut *service.0.borrow_mut(),
            )
        };
        match error {
            ffi::lockdownd_error_t::LOCKDOWN_E_SUCCESS => {
                if !service.0.borrow().is_null() && service.port() != 0 {
                    Ok(service)
                } else {
                    Err(LockdowndError(
                        ffi::lockdownd_error_t::LOCKDOWN_E_INVALID_SERVICE,
                    ))
                }
            }
            other => Err(LockdowndError(other)),
        }
    }

    pub fn start_service_with_escrow_bag(
        &self,
        identifier: &[u8],
    ) -> LockdowndResult<LockdowndServiceDescriptor> {
        let service = LockdowndServiceDescriptor::new();
        let error = unsafe {
            ffi::lockdownd_start_service_with_escrow_bag(
                *self.client.borrow(),
                identifier.as_ptr() as *mut c_char,
                &mut *service.0.borrow_mut(),
            )
        };
        match error {
            ffi::lockdownd_error_t::LOCKDOWN_E_SUCCESS => Ok(service),
            other => Err(LockdowndError(other)),
        }
    }
}

impl Drop for LockdowndClient {
    fn drop(&mut self) {
        unsafe {
            ffi::lockdownd_client_free(*self.client.borrow());
        }
    }
}

type LockdowndServiceDescriptorRef = RefCell<ffi::lockdownd_service_descriptor_t>;
pub struct LockdowndServiceDescriptor(pub LockdowndServiceDescriptorRef);

impl LockdowndServiceDescriptor {
    pub fn from(data: ffi::lockdownd_service_descriptor_t) -> Self {
        Self(RefCell::new(data))
    }

    pub fn new() -> Self {
        Self(RefCell::new(std::ptr::null_mut()))
    }

    pub fn port(&self) -> u16 {
        // self.0.borrow().port
        let p = *self.0.borrow();
        if !p.is_null() {
            unsafe { (*p).port }
        } else {
            0
        }
    }

    pub fn ssl_enabled(&self) -> bool {
        let p = *self.0.borrow();
        if !p.is_null() {
            unsafe {
                if 0 == (*p).ssl_enabled {
                    false
                } else {
                    true
                }
            }
        } else {
            false
        }
    }
}

impl Drop for LockdowndServiceDescriptor {
    fn drop(&mut self) {
        let p = *self.0.borrow();
        if !p.is_null() {
            unsafe {
                ffi::lockdownd_service_descriptor_free(p);
            }
        }
    }
}
