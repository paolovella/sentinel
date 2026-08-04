// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

fn main() {
    #[cfg(feature = "grpc")]
    {
        // Paths must stay inside the crate directory. crates.io packages only
        // files under the crate root, so a `../proto/...` reference is absent
        // from the published tarball and every published version fails to
        // build for consumers with:
        //
        //   Could not make proto path relative: ../proto/mcp/v1/mcp.proto:
        //   No such file or directory
        //
        // Verify with `cargo package -p vellaveto-http-proxy --list` -- the
        // .proto must appear there.
        let proto_file = "proto/mcp/v1/mcp.proto";
        println!("cargo:rerun-if-changed={proto_file}");
        if let Err(error) = tonic_prost_build::configure()
            .build_server(true)
            .build_client(true)
            .compile_protos(&[proto_file], &["proto"])
        {
            eprintln!("Failed to compile MCP protobuf schema: {error}");
            std::process::exit(1);
        }
    }
}
