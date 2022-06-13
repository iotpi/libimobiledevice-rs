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
use std::error::Error;
use std::ffi::{CStr, CString};
use std::fmt;
use std::os::raw::c_void;
use std::ptr::null_mut;

use super::ffi;

pub type DeviceResult<T> = Result<T, DeviceError>;

#[derive(Debug, Clone)]
pub struct DeviceError(ffi::idevice_error_t);

impl Error for DeviceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

impl fmt::Display for DeviceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeviceError({})", self.0 as i32)
    }
}

pub(crate) type DeviceRef = RefCell<ffi::idevice_t>;
pub struct Device(pub(crate) DeviceRef);

impl Drop for Device {
    fn drop(&mut self) {
        unsafe {
            let device_ptr = *self.0.borrow_mut();
            if !device_ptr.is_null() {
                ffi::idevice_free(*self.0.borrow_mut());
            }
        }
    }
}

impl Device {
    pub fn new_with_options(
        udid: Option<&str>,
        options: ffi::idevice_options,
    ) -> DeviceResult<Device> {
        let device = Device(RefCell::new(std::ptr::null_mut()));

        // If I use Option<CString>, during unwrap().as_ptr(), it will be dealloced
        let udid_cstr = CString::new(udid.unwrap_or("")).expect("udid is not string value type");

        // Must keep udid_cstr alive!
        let udid_ptr: *const std::os::raw::c_char;
        if udid.is_some() {
            udid_ptr = udid_cstr.as_ptr();
        } else {
            udid_ptr = std::ptr::null();
        }
        unsafe {
            let error =
                ffi::idevice_new_with_options(&mut *device.0.borrow_mut(), udid_ptr, options);
            match error {
                ffi::idevice_error_t::IDEVICE_E_SUCCESS => Ok(device),
                other => DeviceResult::Err(DeviceError(other)),
            }
        }
    }

    pub fn get_udid(&self) -> DeviceResult<String> {
        let mut udid_ptr: *mut std::os::raw::c_char = null_mut();
        match unsafe { ffi::idevice_get_udid(*self.0.borrow(), &mut udid_ptr) } {
            ffi::idevice_error_t::IDEVICE_E_SUCCESS => {
                if !udid_ptr.is_null() {
                    let udid_str = unsafe { CStr::from_ptr(udid_ptr) }
                        .to_str()
                        .expect("failed to convert udid");
                    return Ok(String::from(udid_str));
                } else {
                    return Err(DeviceError(ffi::idevice_error_t::IDEVICE_E_UNKNOWN_ERROR));
                }
            }
            other => Err(DeviceError(other)),
        }
    }
}

pub struct DeviceInfo {
    pub udid: String,
    pub conn_type: ffi::idevice_connection_type,
    pub conn_data: *mut ::std::os::raw::c_void,
}

pub type DeviceListResult = DeviceResult<Vec<DeviceInfo>>;
pub fn get_device_list_extended() -> DeviceListResult {
    let mut devices: *mut ffi::idevice_info_t = ::std::ptr::null_mut();
    let mut count: ::std::os::raw::c_int = 0;
    unsafe {
        match ffi::idevice_get_device_list_extended(&mut devices, &mut count) {
            ffi::idevice_error_t::IDEVICE_E_SUCCESS => {
                let mut i: isize = 0;
                let count: isize = count as isize;
                let mut results: Vec<DeviceInfo> = Vec::new();
                while i < count {
                    let info: ffi::idevice_info_t = *devices.offset(i);
                    let udid = CStr::from_ptr((*info).udid);
                    let device_info = DeviceInfo {
                        udid: udid.to_string_lossy().into_owned(),
                        conn_type: (*info).conn_type,
                        conn_data: (*info).conn_data,
                    };
                    results.push(device_info);
                    i += 1;
                }
                ffi::idevice_device_list_extended_free(devices);
                Ok(results)
            }
            other => DeviceResult::Err(DeviceError(other)),
        }
    }
}

#[derive(Debug)]
pub struct DeviceEvent {
    pub event: ffi::idevice_event_type,
    pub udid: String,
    pub conn_type: ffi::idevice_connection_type,
}

impl DeviceEvent {}

trait DeviceEventClosureTrait {
    fn ptr(&self) -> *mut c_void;
}

struct DeviceEventClosure<F> {
    closure_ptr: *mut F,
}

impl<F> DeviceEventClosure<F> {
    fn new(callback: F) -> Self {
        let closure_ptr = Box::into_raw(Box::new(callback)) as *const _ as *mut F;
        Self { closure_ptr }
    }
}

impl<F> DeviceEventClosureTrait for DeviceEventClosure<F>
where
    F: Fn(DeviceEvent),
{
    fn ptr(&self) -> *mut c_void {
        self.closure_ptr as *mut _
    }
}

impl<F> Drop for DeviceEventClosure<F> {
    fn drop(&mut self) {
        unsafe { Box::from_raw(self.closure_ptr as *mut F) };
    }
}

pub struct DeviceEventSubscriber {
    closure: Box<dyn DeviceEventClosureTrait>,
}

impl Drop for DeviceEventSubscriber {
    fn drop(&mut self) {
        unsafe {
            ffi::idevice_event_unsubscribe();
        }
    }
}

impl DeviceEventSubscriber {
    pub fn new<F>(callback: F) -> DeviceResult<Self>
    where
        F: Fn(DeviceEvent) + 'static,
    {
        unsafe extern "C" fn trampoline<F>(n: *const ffi::idevice_event_t, data: *mut c_void)
        where
            F: Fn(DeviceEvent),
        {
            let udid = CStr::from_ptr((*n).udid).to_string_lossy().into_owned();
            let event = DeviceEvent {
                event: (*n).event,
                udid,
                conn_type: (*n).conn_type,
            };
            let closure_ptr = data as *mut F;
            let closure = &mut (*closure_ptr);
            closure(event);
        }

        let closure = DeviceEventClosure::new(callback);
        let subscriber = Self {
            closure: Box::new(closure),
        };
        let closure_ref = subscriber.closure.as_ref();
        let error =
            unsafe { ffi::idevice_event_subscribe(Some(trampoline::<F>), closure_ref.ptr()) };

        match error {
            ffi::idevice_error_t::IDEVICE_E_SUCCESS => Ok(subscriber),
            other => Err(DeviceError(other)),
        }
    }
}
