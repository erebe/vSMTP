// Rhai modules in the `rhai-fs` package.
mod pkg {
    include!("src/api.rs");
}

fn main() {
    if let Ok(docs_path) = std::env::var("DOCS_DIR") {
        let mut engine = rhai::Engine::new();

        engine.register_static_module("memcached", rhai::exported_module!(pkg::memcached).into());

        let docs = rhai_autodocs::generate_documentation(&engine, false)
            .expect("failed to generate documentation");

        write_docs(&docs_path, &docs);
    }
}

fn write_docs(path: &str, docs: &rhai_autodocs::ModuleDocumentation) {
    std::fs::write(
        std::path::PathBuf::from_iter([path, &format!("fn::{}.md", &docs.name)]),
        &docs.documentation,
    )
    .expect("failed to write documentation");

    for doc in &docs.sub_modules {
        write_docs(path, doc);
    }
}
