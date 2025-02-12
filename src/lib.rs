mod assembler;
use proc_macro::TokenStream;
use syn::parse_macro_input;

#[proc_macro]
pub fn assembler(input: TokenStream) -> TokenStream {
    // Parse an identifier and a string literal
    let input = parse_macro_input!(input with syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated)
        .into_iter()
        .collect::<Vec<_>>();

    if input.len() != 2 {
        panic!("Expected two arguments: architecture name and definition file path");
    }

    // Extract architecture from identifier
    let architecture = if let syn::Expr::Path(path) = &input[0] {
        if let Some(ident) = path.path.get_ident() {
            ident.to_string()
        } else {
            panic!("Expected architecture identifier");
        }
    } else {
        panic!("Expected architecture identifier");
    };

    // Extract filename from string literal
    let filename = if let syn::Expr::Lit(syn::ExprLit {
        lit: syn::Lit::Str(s),
        ..
    }) = &input[1]
    {
        s.value()
    } else {
        panic!("Expected string literal for filename");
    };

    let raw_definition = monistode_binutils::definition::RawDefinition::from_str(
        match std::fs::read_to_string(&filename) {
            Ok(x) => x,
            Err(e) => panic!("Error reading {}: {}", filename, e),
        }
        .as_str(),
    )
    .unwrap();
    let definition = monistode_binutils::definition::Definition::try_from(raw_definition).unwrap();
    assembler::generate_parser(&definition, &architecture).into()
}
