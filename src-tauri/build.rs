fn main() {
    // /DELAYLOAD:WinDivert.dll is wired in `.cargo/config.toml` via the
    // `[target.x86_64-pc-windows-msvc].rustflags` table — that's the most
    // reliable injection point. windivert-sys's `cargo:rustc-link-lib`
    // creates a regular Windows DLL import; without delay-load Windows
    // refuses to start the cdylib at app launch. The flag tells the
    // linker to defer the import resolution to first symbol use, by which
    // time our `portscan_driver_install` has copied WinDivert.dll next to
    // the exe.
    tauri_build::build()
}
