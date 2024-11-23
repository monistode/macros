mod assembler;
use proc_macro::TokenStream;
use syn::{parse_macro_input, LitStr};

#[proc_macro]
pub fn assembler(input: TokenStream) -> TokenStream {
    let filename = parse_macro_input!(input as LitStr).value();

    let raw_definition = monistode_binutils::definition::RawDefinition::from_str(
        match std::fs::read_to_string(&filename) {
            Ok(x) => x,
            Err(e) => panic!("Error reading {}: {}", filename, e),
        }
        .as_str(),
    )
    .unwrap();
    let definition = monistode_binutils::definition::Definition::try_from(raw_definition).unwrap();
    assembler::generate_parser(&definition).into()
}
