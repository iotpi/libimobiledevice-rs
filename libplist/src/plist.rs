// Copyright 2020-2022 Yang Hongbo, Qingdao IotPi Information Technology, Ltd.
// This file is part of libimobiledeivce-rs.
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

use libc::{c_char, c_void};
use std::cell::RefCell;
use std::ffi::{CStr, CString};
use std::fmt;
use std::io;
use std::io::Read;
use std::ptr::null_mut;
use std::rc::Rc;
use std::time::SystemTime;

use chrono::prelude::{DateTime, TimeZone, Utc};

use super::ffi::{self, plist_type};

pub use super::ffi::plist_t;

const SECONDS_FROM_2001_01_01: i64 = 978307200;

pub type PlistRef = Rc<RefCell<plist_t>>;

pub enum Plist {
    Boolean(PlistRef),
    Uint(PlistRef),
    Real(PlistRef),
    String(PlistRef),
    Array(PlistRef),
    Dict(PlistRef),
    Date(PlistRef),
    Data(PlistRef),
    Key(PlistRef),
    Uid(PlistRef),
    None,
}

impl Drop for Plist {
    fn drop(&mut self) {
        if let Some(plist) = self.node() {
            if plist.borrow().is_null() == false {
                unsafe {
                    ffi::plist_free(*plist.borrow());
                }
            }
        }
    }
}

impl Plist {
    pub fn from_raw(data: plist_t) -> Option<Self> {
        if data.is_null() == false {
            let plist_ref = Rc::new(RefCell::new(data));
            let ty = unsafe { ffi::plist_get_node_type(data) };
            let plist = match ty {
                plist_type::PLIST_BOOLEAN => Plist::Boolean(plist_ref),
                plist_type::PLIST_UINT => Plist::Uint(plist_ref),
                plist_type::PLIST_REAL => Plist::Real(plist_ref),
                plist_type::PLIST_STRING => Plist::String(plist_ref),
                plist_type::PLIST_ARRAY => Plist::Array(plist_ref),
                plist_type::PLIST_DICT => Plist::Dict(plist_ref),
                plist_type::PLIST_DATE => Plist::Date(plist_ref),
                plist_type::PLIST_DATA => Plist::Data(plist_ref),
                plist_type::PLIST_KEY => Plist::Key(plist_ref),
                plist_type::PLIST_UID => Plist::Uid(plist_ref),
                _ => Plist::None,
            };
            Some(plist)
        } else {
            None
        }
    }

    pub fn into_raw(node: Self) -> plist_t {
        if let Some(node) = node.node() {
            let plist = *node.borrow();
            *node.borrow_mut() = null_mut();
            return plist;
        }
        null_mut()
    }

    pub fn from<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut plist: plist_t = null_mut();
        let mut buffer = Vec::new();
        let size = reader.read_to_end(&mut buffer)?;
        unsafe {
            ffi::plist_from_memory(buffer.as_ptr() as *const c_char, size as u32, &mut plist)
        };

        Ok(Plist::from_raw(plist).ok_or_else(|| {
            let err = format!("failed to convert data to plist");
            io::Error::new(io::ErrorKind::InvalidData, err)
        })?)
    }

    pub fn node(&self) -> Option<PlistRef> {
        match self {
            Plist::None => None,
            Plist::Boolean(plist)
            | Plist::Uint(plist)
            | Plist::Real(plist)
            | Plist::String(plist)
            | Plist::Array(plist)
            | Plist::Dict(plist)
            | Plist::Date(plist)
            | Plist::Data(plist)
            | Plist::Key(plist)
            | Plist::Uid(plist) => Some(plist.clone()),
        }
    }

    // pub fn node_type(&self) -> PlistType {
    //     let ty;
    //     unsafe {
    //         ty = ffi::plist_get_node_type(self.0.borrow().0);
    //     }
    //     match ty {
    //         plist_type::PLIST_BOOLEAN => PlistType::Boolean,
    //         plist_type::PLIST_UINT => PlistType::Uint,
    //         plist_type::PLIST_REAL => PlistType::Real,
    //         plist_type::PLIST_STRING => PlistType::String,
    //         plist_type::PLIST_ARRAY => PlistType::Array,
    //         plist_type::PLIST_DICT => PlistType::Dict,
    //         plist_type::PLIST_DATE => PlistType::Date,
    //         plist_type::PLIST_KEY => PlistType::Key,
    //         plist_type::PLIST_UID => PlistType::Uid,
    //         _ => PlistType::None,
    //     }
    // }

    pub fn new_dict() -> Option<Self> {
        let value = unsafe { ffi::plist_new_dict() };
        Self::from_raw(value)
    }

    pub fn new_array() -> Option<Self> {
        let value = unsafe { ffi::plist_new_array() };
        Self::from_raw(value)
    }

    pub fn new_string(value: &str) -> Option<Self> {
        let value = CString::new(value).expect(format!("failed to convert {}", value).as_str());

        let plist = unsafe { ffi::plist_new_string(value.as_ptr()) };

        Self::from_raw(plist)
    }

    pub fn new_date(datetime: DateTime<Utc>) -> Option<Self> {
        // let dt_20010101 = Utc.ymd(2001, 1, 1).and_hms(0, 0, 0);
        // let secs = (datetime.timestamp() - dt_20010101.timestamp()) as i32;
        let secs = (datetime.timestamp() - SECONDS_FROM_2001_01_01) as i32;
        let usecs = datetime.timestamp_subsec_micros() as i32;
        let plist = unsafe { ffi::plist_new_date(secs, usecs) };
        Self::from_raw(plist)
    }

    pub fn new_date_from_systime(datetime: SystemTime) -> Option<Self> {
        // let dt_20010101 = Utc.ymd(2001, 1, 1).and_hms(0, 0, 0);
        // let secs = (datetime.timestamp() - dt_20010101.timestamp()) as i32;
        let duration = datetime.duration_since(SystemTime::UNIX_EPOCH).ok()?;
        let secs = duration.as_secs();
        let usecs = duration.subsec_micros() as i32;
        let secs = (secs as i64 - SECONDS_FROM_2001_01_01) as i32;
        let plist = unsafe { ffi::plist_new_date(secs, usecs) };
        Self::from_raw(plist)
    }

    pub fn new_bool(value: bool) -> Option<Self> {
        let value: u8 = if value { 1 } else { 0 };
        let plist = unsafe { ffi::plist_new_bool(value) };

        Self::from_raw(plist)
    }

    pub fn new_uint(value: u64) -> Option<Self> {
        let plist = unsafe { ffi::plist_new_uint(value) };
        Self::from_raw(plist)
    }

    pub fn new_int(value: i64) -> Option<Self> {
        let plist = unsafe { ffi::plist_new_uint(value as u64) };
        Self::from_raw(plist)
    }

    pub fn bool_value(&self) -> Option<bool> {
        if let Plist::Boolean(plist) = self {
            let mut bl: u8 = 0;
            let node = plist.borrow();
            unsafe { ffi::plist_get_bool_val(*node, &mut bl) };
            if bl == 0 {
                Some(false)
            } else {
                Some(true)
            }
        } else {
            None
        }
    }

    pub fn string_value(&self) -> Option<String> {
        if let Plist::String(plist) = self {
            let mut len_str: u64 = 0;
            let val_char_p: *const c_char;
            let node = plist.borrow();
            val_char_p = unsafe { ffi::plist_get_string_ptr(*node, &mut len_str) };
            if val_char_p.is_null() {
                None
            } else {
                // may be better to use std::slice::from_raw_parts to convert into [u8].
                let c_str = unsafe {
                    CStr::from_ptr(val_char_p)
                        .to_str()
                        .expect("failed to convert to string")
                };
                Some(String::from(c_str))
            }
        } else {
            None
        }
    }

    pub fn real_value(&self) -> Option<f64> {
        if let Plist::Real(plist) = self {
            let node = plist.borrow();
            let mut value: f64 = 0.0;
            unsafe { ffi::plist_get_real_val(*node, &mut value) };
            return Some(value);
        }
        None
    }

    pub fn uint_value(&self) -> Option<u64> {
        if let Plist::Uint(plist) = self {
            let node = plist.borrow();
            let mut value: u64 = 0;
            unsafe { ffi::plist_get_uint_val(*node, &mut value) };
            return Some(value);
        }
        None
    }

    pub fn date_value(&self) -> Option<DateTime<Utc>> {
        if let Plist::Date(plist) = self {
            let node = plist.borrow();
            let mut secs: i32 = 0;
            let mut usecs: i32 = 0;

            unsafe { ffi::plist_get_date_val(*node, &mut secs, &mut usecs) };

            let secs = secs as i64 + SECONDS_FROM_2001_01_01;
            let datetime = Utc.timestamp(secs as i64, (usecs as u32) * 1000);

            Some(datetime)
        } else {
            None
        }
    }

    pub fn dict_get_size(&self) -> u32 {
        if let Plist::Dict(node) = self {
            let node = node.borrow();
            unsafe { ffi::plist_dict_get_size(*node) }
        } else {
            0
        }
    }

    pub fn dict_set_item(&mut self, key: &str, value: Plist) {
        if let Plist::Dict(node) = self {
            let node = node.borrow();
            let value_node = Plist::into_raw(value);
            let key = CString::new(key).expect(format!("failed to convert key {}", key).as_str());
            unsafe { ffi::plist_dict_set_item(*node, key.as_ptr(), value_node) };
        }
    }

    pub fn dict_get_item(&self, key: &str) -> Option<Plist> {
        if let Plist::Dict(node) = self {
            let node = node.borrow();
            let key = CString::new(key).expect(format!("failed to convert key {}", key).as_str());
            let item = unsafe { ffi::plist_dict_get_item(*node, key.as_ptr()) };
            let ty = unsafe { ffi::plist_get_node_type(item) };
            if ty != ffi::plist_type::PLIST_NONE {
                let item = unsafe { ffi::plist_copy(item) };
                return Plist::from_raw(item);
            } else {
                return Some(Plist::None);
            }
        }

        None
    }

    pub fn dict_iter(&self) -> Option<IterDict> {
        if let Plist::Dict(node) = self {
            let node = node.borrow();
            let mut iter: ffi::plist_dict_iter = null_mut();
            unsafe {
                ffi::plist_dict_new_iter(*node, &mut iter);
            }

            if !iter.is_null() {
                Some(IterDict { iter, node: &self })
            } else {
                None
            }
        } else {
            None
        }
    }

    pub fn array_append_item(&mut self, item: Plist) {
        if let Plist::Array(node) = self {
            let node = node.borrow();
            let item_node = Plist::into_raw(item);
            unsafe { ffi::plist_array_append_item(*node, item_node) };
        }
    }

    pub fn array_get_size(&self) -> u32 {
        if let Plist::Array(node) = self {
            let node = node.borrow();
            return unsafe { ffi::plist_array_get_size(*node) };
        }

        0
    }

    pub fn array_get_item(&self, pos: u32) -> Option<Plist> {
        if let Plist::Array(node) = self {
            let node = node.borrow();
            let item = unsafe { ffi::plist_array_get_item(*node, pos) };
            let ty = unsafe { ffi::plist_get_node_type(item) };
            if ty != ffi::plist_type::PLIST_NONE {
                let item = unsafe { ffi::plist_copy(item) };
                return Plist::from_raw(item);
            } else {
                return Some(Plist::None);
            }
        }

        None
    }

    pub fn to_xml(&self) -> Option<Vec<u8>> {
        if let Some(plist) = self.node() {
            let node = plist.borrow();
            let mut buffer: *mut c_char = null_mut();
            let mut length: u32 = 0;
            unsafe { ffi::plist_to_xml(*node, &mut buffer, &mut length) };

            if !buffer.is_null() && length > 0 {
                let length = length as usize;
                let mut out_vec = Vec::<u8>::with_capacity(length);
                unsafe {
                    out_vec.set_len(length);
                    std::ptr::copy_nonoverlapping(
                        buffer as *const u8,
                        out_vec.as_mut_ptr(),
                        length,
                    );
                    ffi::plist_mem_free(buffer as *mut c_void);
                }
                return Some(out_vec);
            }
        }

        None
    }

    pub fn to_bin(&self) -> Option<Vec<u8>> {
        if let Some(plist) = self.node() {
            let node = plist.borrow();
            let mut buffer: *mut c_char = null_mut();
            let mut length: u32 = 0;
            unsafe { ffi::plist_to_bin(*node, &mut buffer, &mut length) };

            if !buffer.is_null() && length > 0 {
                let length = length as usize;
                let mut out_vec = Vec::<u8>::with_capacity(length);
                unsafe {
                    out_vec.set_len(length);
                    std::ptr::copy_nonoverlapping(
                        buffer as *const u8,
                        out_vec.as_mut_ptr(),
                        length,
                    );
                    ffi::plist_mem_free(buffer as *mut c_void);
                }
            }
        }

        None
    }
}

impl Clone for Plist {
    fn clone(&self) -> Self {
        let plist = self.node().expect("failed to get node");
        let plist = *plist.borrow();
        let out_plist = unsafe { ffi::plist_copy(plist) };
        return Self::from_raw(out_plist).expect("failed to clone plist");
    }
}

pub struct IterDict<'a> {
    iter: ffi::plist_dict_iter,
    node: &'a Plist,
}

impl<'a> Iterator for IterDict<'a> {
    type Item = (String, Plist);

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(node) = self.node.node() {
            let node = node.borrow();
            let mut key: *mut c_char = null_mut();
            let mut value: ffi::plist_t = null_mut();

            unsafe {
                ffi::plist_dict_next_item(*node, self.iter, &mut key, &mut value);
            }

            if !value.is_null() {
                let key_str;
                let item;
                unsafe {
                    key_str = CStr::from_ptr(key).to_string_lossy().into_owned();
                    item = ffi::plist_copy(value);
                    // according to comments for next_item, key is needed to be freed
                    libc::free(key as *mut c_void);
                }

                if let Some(item) = Plist::from_raw(item) {
                    return Some((key_str, item));
                }
            }
        }

        None
    }
}

impl<'a> Drop for IterDict<'a> {
    fn drop(&mut self) {
        if !self.iter.is_null() {
            unsafe {
                libc::free(self.iter);
            }
        }
    }
}

impl fmt::Debug for Plist {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Plist::None => write!(f, "Plist::None"),
            Plist::Boolean(plist) => {
                let output = string_for_plist(*plist.borrow(), 0);
                write!(f, "Plist::Boolean({})", output)
            }
            Plist::Uint(plist) => {
                let output = string_for_plist(*plist.borrow(), 0);
                write!(f, "Plist::Uint({})", output)
            }
            Plist::Real(plist) => {
                let output = string_for_plist(*plist.borrow(), 0);
                write!(f, "Plist::Real({})", output)
            }
            Plist::String(plist) => {
                let output = string_for_plist(*plist.borrow(), 0);
                write!(f, "Plist::String({})", output)
            }
            Plist::Array(plist) => {
                let output = string_for_plist(*plist.borrow(), 0);
                write!(f, "Plist::Array({})", output)
            }
            Plist::Dict(plist) => {
                let output = string_for_plist(*plist.borrow(), 0);
                write!(f, "Plist::Dict({})", output)
            }
            Plist::Date(plist) => {
                let output = string_for_plist(*plist.borrow(), 0);
                write!(f, "Plist::Date({})", output)
            }
            Plist::Data(plist) => {
                let output = string_for_plist(*plist.borrow(), 0);
                write!(f, "Plist::Data({})", output)
            }
            Plist::Key(plist) => {
                let output = string_for_plist(*plist.borrow(), 0);
                write!(f, "Plist::Key({})", output)
            }
            Plist::Uid(plist) => {
                let output = string_for_plist(*plist.borrow(), 0);
                write!(f, "Plist::Uid({})", output)
            }
        }
    }
}

pub fn string_for_plist(node: plist_t, depth: u8) -> String {
    let ty = unsafe { ffi::plist_get_node_type(node) };
    match ty {
        plist_type::PLIST_BOOLEAN => {
            let mut val: u8 = 0;
            unsafe { ffi::plist_get_bool_val(node, &mut val) };
            format!("Bool({})", if val != 0 { "true" } else { "false" })
        }
        plist_type::PLIST_UINT => {
            let mut val: u64 = 0;
            unsafe { ffi::plist_get_uint_val(node, &mut val) };
            format!("Uint({})", val)
        }
        plist_type::PLIST_REAL => {
            let mut val: std::os::raw::c_double = 0.0;
            unsafe { ffi::plist_get_real_val(node, &mut val) };
            format!("Real({})", val)
        }
        plist_type::PLIST_STRING => {
            let mut len_str: u64 = 0;
            let val_char_p: *const c_char;
            val_char_p = unsafe { ffi::plist_get_string_ptr(node, &mut len_str) };
            if val_char_p.is_null() {
                format!("String(null)")
            } else {
                // may be better to use std::slice::from_raw_parts to convert into [u8].
                let c_str = unsafe {
                    CStr::from_ptr(val_char_p)
                        .to_str()
                        .expect("failed to convert to string")
                };
                format!("String(\"{}\")", c_str)
            }
        }
        plist_type::PLIST_ARRAY => {
            let mut array = Vec::<String>::new();
            let size = unsafe { ffi::plist_array_get_size(node) };
            for i in 0..size {
                let item = unsafe { ffi::plist_array_get_item(node, i) };
                if !item.is_null() {
                    let val = string_for_plist(item, depth + 1);
                    let f = format!("{}:{}", i, val);
                    array.push(f);
                }
            }
            format!("Array[{}]", array.join(", ").as_str())
        }
        plist_type::PLIST_DICT => unsafe {
            let mut iter: ffi::plist_dict_iter = null_mut();
            ffi::plist_dict_new_iter(node, &mut iter);
            if !iter.is_null() {
                let mut dict_array = Vec::<String>::new();
                loop {
                    let mut c_str_p: *mut c_char = null_mut();
                    let mut val_p: plist_t = null_mut();
                    ffi::plist_dict_next_item(node, iter, &mut c_str_p, &mut val_p);
                    if val_p.is_null() {
                        break;
                    }

                    let key = CStr::from_ptr(c_str_p).to_string_lossy().into_owned();
                    if !c_str_p.is_null() {
                        libc::free(c_str_p as *mut c_void);
                    }
                    let value_str = string_for_plist(val_p, depth + 1);
                    let pair = format!("{} : {}", key, value_str);
                    dict_array.push(pair);
                }
                format!("Dict\n{{\n{}\n}}", dict_array.join("\n").as_str())
            } else {
                format!("Dict(None)")
            }
        },
        plist_type::PLIST_DATE => {
            let mut sec: i32 = 0;
            let mut usec: i32 = 0;
            unsafe { ffi::plist_get_date_val(node, &mut sec, &mut usec) };
            // let dt_20010101 = Utc.ymd(2001, 1, 1).and_hms(0, 0, 0);
            // let secs = sec as i64 + dt_20010101.timestamp();
            let secs = sec as i64 + SECONDS_FROM_2001_01_01;
            let datetime = Utc.timestamp(secs, (usec * 1000) as u32);
            format!("Date({})", datetime.to_rfc2822())
        }
        plist_type::PLIST_DATA => format!("Data"),
        plist_type::PLIST_KEY => format!("Key"),
        plist_type::PLIST_UID => {
            let mut val: u64 = 0;
            unsafe { ffi::plist_get_uid_val(node, &mut val) };
            format!("Uid({})", val)
        }
        other => format!("None({:?})", other),
    }
}
