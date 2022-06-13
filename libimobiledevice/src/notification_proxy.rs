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
use std::cell::RefCell;
use std::error::Error;
use std::ffi::CStr;
use std::fmt;
use std::os::raw::{c_char, c_void};
use std::ptr::{null, null_mut};
use std::rc::Rc;

pub type NpResult<T> = Result<T, NpError>;

#[derive(Debug, Clone)]
pub struct NpError(ffi::np_error_t);

impl Error for NpError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

impl fmt::Display for NpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NpError({})", self.0 as i32)
    }
}

type NpClientRef = RefCell<ffi::np_client_t>;

pub trait NpClientTrait {
    fn observe_notifications(&self, notification_spec: &[&[u8]]) -> NpResult<()>;
    fn post_notification(&self, notification: &[u8]) -> NpResult<()>;
}

trait NpClientClosureTrait {
    fn ptr(&self) -> *mut c_void;
}

struct NpClientClosure<F> {
    closure_ptr: *mut F,
}

impl<F> NpClientClosure<F> {
    fn new(callback: F) -> Self {
        let closure_ptr = Box::into_raw(Box::new(callback)) as *const _ as *mut F;
        Self { closure_ptr }
    }
}

impl<F> NpClientClosureTrait for NpClientClosure<F>
where
    F: Fn(&str),
{
    fn ptr(&self) -> *mut c_void {
        self.closure_ptr as *mut _
    }
}

impl<F> Drop for NpClientClosure<F> {
    fn drop(&mut self) {
        // println!("drop NpClientClosure");
        unsafe { Box::from_raw(self.closure_ptr as *mut F) };
    }
}

pub struct NpClient {
    private: NpClientRef,
    _device: Rc<Device>,
    closure: RefCell<Option<Box<dyn NpClientClosureTrait>>>,
}

impl NpClient {
    pub fn new(device: Rc<Device>, service: &LockdowndServiceDescriptor) -> NpResult<Self> {
        let mut client: ffi::np_client_t = null_mut();
        let error =
            unsafe { ffi::np_client_new(*device.0.borrow(), *service.0.borrow(), &mut client) };

        match error {
            ffi::np_error_t::NP_E_SUCCESS => {
                Ok(Self {
                    private: RefCell::new(client),
                    _device: device,
                    // callback: RefCell::new(None),
                    closure: RefCell::new(None),
                })
            }
            other => Err(NpError(other)),
        }
    }

    // Ref: https://s3.amazonaws.com/temp.michaelfbryan.com/callbacks/index.html
    // http://aatch.github.io/blog/2015/01/17/unboxed-closures-and-ffi-callbacks/
    // https://blog.seantheprogrammer.com/neat-rust-tricks-passing-rust-closures-to-c
    // unsafe fn unpack_closure<F>(closure: &mut F) -> (*mut c_void, NpClientCallback)
    // where F: Fn(&str),
    // {

    //     (closure as *const _ as *mut c_void, trampoline::<F>)
    // }

    pub fn set_notify_callback<F>(&self, callback: F) -> NpResult<()>
    where
        F: Fn(&str) + 'static,
    {
        unsafe extern "C" fn trampoline<F>(n: *const c_char, data: *mut c_void)
        where
            F: Fn(&str),
        {
            // println!("called inside trampoline");

            let notification = CStr::from_ptr(n)
                .to_str()
                .expect("failed to convert notification");
            // println!("notification: {:?}", notification);
            let closure_ptr = data as *mut F;
            let closure = &mut (*closure_ptr);
            closure(notification);
        }

        let closure = NpClientClosure::new(callback);
        let mut closure_cell = self.closure.borrow_mut();
        *closure_cell = Some(Box::new(closure));

        let closure = closure_cell.as_ref().unwrap();
        let error = unsafe {
            ffi::np_set_notify_callback(
                *self.private.borrow(),
                Some(trampoline::<F>),
                closure.ptr(),
            )
        };

        match error {
            ffi::np_error_t::NP_E_SUCCESS => Ok(()),
            other => Err(NpError(other)),
        }
    }

    // fn drop_closure(&mut self)
    // {
    //     let p = *self.private.borrow();
    //     if !p.is_null() {
    //         unsafe {
    //             ffi::np_set_notify_callback(p, None, null_mut());

    //             let closure_ptr = self.closure.replace(null_mut());
    //             if !closure_ptr.is_null() {
    //                 unsafe { Box::from_raw((closure_ptr)) };
    //             }

    //             ffi::np_client_free(p);
    //         }
    //     }
    // }
}

impl NpClientTrait for NpClient {
    fn observe_notifications(&self, notification_spec: &[&[u8]]) -> NpResult<()> {
        // notification_spec needs NULL as end flag
        let mut spec: Vec<*const u8> = Vec::<_>::with_capacity(notification_spec.len() + 1);
        for n in notification_spec {
            spec.push(n.as_ptr());
        }
        spec.push(null());

        let mut spec = std::mem::ManuallyDrop::new(spec);
        let error;
        unsafe {
            let ptr = spec.as_mut_ptr();
            let len = spec.len();
            let cap = spec.capacity();
            error =
                ffi::np_observe_notifications(*self.private.borrow(), ptr as *mut *const c_char);
            Vec::from_raw_parts(ptr, len, cap);
        };

        match error {
            ffi::np_error_t::NP_E_SUCCESS => Ok(()),
            other => Err(NpError(other)),
        }
    }

    fn post_notification(&self, notification: &[u8]) -> NpResult<()> {
        let error = unsafe {
            ffi::np_post_notification(
                *self.private.borrow(),
                notification.as_ptr() as *const c_char,
            )
        };
        match error {
            ffi::np_error_t::NP_E_SUCCESS => Ok(()),
            other => Err(NpError(other)),
        }
    }
}

impl Drop for NpClient {
    fn drop(&mut self) {
        println!("NpClient is being freed");

        let p = *self.private.borrow();
        unsafe {
            ffi::np_client_free(p);
        }
    }
}
