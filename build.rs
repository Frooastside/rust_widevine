use std::io::Result;

use prost_build::Config;

extern crate prost_build;

fn main() -> Result<()> {
    println!("cargo:rerun-if-changed=src/license_protocol.proto");
    Config::new().out_dir("src").compile_protos(&["src/license_protocol.proto"], &["src/"])?;
    Ok(())
}
