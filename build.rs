use protobuf_codegen_pure::Customize;

fn main() {
    let customize = Customize {
        expose_fields: Some(true),
        generate_accessors: Some(false),
        ..Default::default()
    };
    protobuf_codegen_pure::Codegen::new()
        .out_dir("src/protocol")
        .inputs(&["src/protocol/mumble.proto"])
        .include("src/protocol")
        .customize(customize)
        .run()
        .expect("Codegen failed.");
}
