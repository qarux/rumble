fn main() {
    protoc_rust::Codegen::new()
        .out_dir("src/proto")
        .input("src/proto/mumble.proto")
        .include("src/proto")
        .run()
        .expect("protoc");
}