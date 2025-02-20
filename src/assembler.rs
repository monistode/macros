use monistode_binutils::definition::Definition;
use quote::quote;

pub fn generate_parser(definition: &Definition, architecture: &str) -> proc_macro2::TokenStream {
    let text_parser = crate::text_section::generate_text_parser(definition);
    let arch = format!("{}", architecture);
    let arch_ident = syn::Ident::new(&arch, proc_macro2::Span::call_site());

    return quote! {
        #text_parser

        fn all_sections_parser<Input>() -> impl combine::Parser<Input, Output = Vec<monistode_binutils::object_file::Section>>
        where
            Input: combine::Stream<Token = char>,
            Input::Error: combine::ParseError<Input::Token, Input::Range, Input::Position>,
        {
            combine::parser::repeat::many(
                combine::parser::choice::choice((
                    combine::attempt(parse_text().map(|parsed| monistode_binutils::object_file::Section::Text(monistode_binutils::object_file::TextSection { data: parsed.data, symbols: parsed.symbols, relocations: parsed.relocations })),),
                ))
            )
        }

        pub fn parse(input: &str) -> Result<monistode_binutils::object_file::ObjectFile, String> {
            let mut input = input.to_string();
            if !input.ends_with("\n") {
                input.push('\n');
            }
            let result = all_sections_parser()
                .parse(combine::easy::Stream(input.as_str()))
                .map_err(|e| e.map_position(|p| p.translate_position(input.as_str())));

            match result {
                Ok((sections, remaining)) => {
                    if !remaining.0.is_empty() {
                        let position = input.len() - remaining.0.len();
                        let line = input[..position].chars().filter(|c| *c == '\n').count() + 1;
                        let column = input[..position]
                            .chars()
                            .rev()
                            .take_while(|c| *c != '\n')
                            .count();
                        let line_with_error = input[position..]
                            .chars()
                            .take_while(|c| *c != '\n')
                            .collect::<String>();
                        Err(format!(
                            "Unexpected input at line {}, column {}\n{}\n{}^",
                            line, column + 1, line_with_error, " ".repeat(column)
                        ))
                    } else {
                        Ok(monistode_binutils::object_file::ObjectFile::with_sections(
                            monistode_binutils::Architecture::#arch_ident,
                            sections
                        ))
                    }
                }
                Err(e) => Err(format!("{}", e)),
            }
        }
    };
}
