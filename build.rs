use cc;

fn main() {
    cc::Build::new()
        .file("src/checksum.c")
        .compile("checksum");
}
