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

extern crate bindgen;
extern crate pkg_config;

use std::env;
use std::path::PathBuf;

fn main() {
    libimobiledevice();
}

fn libimobiledevice() {
    let libname = "libimobiledevice";
    let wrapper_file = format!("{}_wrapper.h", libname);

    let library = pkg_config::Config::new()
        .print_system_cflags(true)
        .atleast_version("1.2.1")
        .probe("libimobiledevice-1.0")
        .unwrap();
    println!("cargo:rerun-if-changed={}", wrapper_file);

    let mut args = Vec::new();
    for i in library.include_paths.iter() {
        let mut arg = String::from("-I");
        arg.push_str(i.to_str().unwrap());
        args.push(arg);
    }

    let bindings_builder = bindgen::Builder::default()
        .clang_args(args)
        .header(wrapper_file);
    let bindings = bindings_builder
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .whitelist_function("idevice_.+")
        .whitelist_type("idevice_.+")
        .whitelist_function("lockdownd_.+")
        .whitelist_type("lockdownd_.+")
        .whitelist_function("mobilebackup2_.+")
        .whitelist_type("mobilebackup2_.+")
        .whitelist_var("MOBILEBACKUP2_.+")
        .whitelist_function("afc_.+")
        .whitelist_type("afc_.+")
        .whitelist_var("AFC_.+")
        .whitelist_function("np_.+")
        .whitelist_type("np_.+")
        .whitelist_var("NP_.+")
        .whitelist_function("instproxy_.+")
        .whitelist_type("instproxy_.+")
        .whitelist_var("INSTPROXY_.+")
        .default_enum_style(bindgen::EnumVariation::Rust {
            non_exhaustive: true,
        })
        .bitfield_enum("idevice_options")
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    let binding_filename = format!("{}_bindings.rs", libname);
    bindings
        .write_to_file(out_path.join(binding_filename.as_str()))
        .expect(format!("Couldn't write {}", binding_filename.as_str()).as_ref());
}
