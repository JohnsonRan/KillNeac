fn main() {
    if cfg!(target_os = "windows") {
        let mut res = winres::WindowsResource::new();
        res.set_manifest_file("app.manifest");
        res.set("FileDescription", "KillNeac");
        res.set("ProductName", "KillNeac");
        res.set_icon("icon.ico");
        res.compile().unwrap();
    }
}
