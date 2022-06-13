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

extern crate bindgen;
extern crate pkg_config;

use std::env;
use std::path::PathBuf;

fn main() {
    libplist();
}

fn libplist() {
    let libname = "libplist";
    let pkgname = format!("{}-2.0", libname);
    let wrapper_file = format!("{}_wrapper.h", libname);
    let library = pkg_config::Config::new()
        .print_system_cflags(true)
        .atleast_version("2.1")
        .probe(&pkgname)
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
        .whitelist_function("plist_.+")
        .whitelist_type("plist_.+")
        .default_enum_style(bindgen::EnumVariation::Rust {
            non_exhaustive: true,
        })
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    let binding_filename = format!("{}_bindings.rs", libname);
    bindings
        .write_to_file(out_path.join(binding_filename.as_str()))
        .expect(format!("Couldn't write {}", binding_filename.as_str()).as_ref());
}
