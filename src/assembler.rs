use quote::quote;

use monistode_binutils::definition::{
    ArgumentDefinition, CommandDefinition, Definition, RegisterGroup,
};

fn generate_register_group_parser(register_group: &RegisterGroup) -> proc_macro2::TokenStream {
    // Example:
    // fn parse_register_group_general_purpose<Input>() -> impl combine::Parser<Input, Output = Parsed>
    // where
    //    Input: combine::Stream<Token = char>,
    //    Input::Error: combine::ParseError<Input::Token, Input::Range, Input::Position>,
    //  {
    //    combine::choice!(
    //      combine::parser::char::string("%R00").map(|_|
    //      Parsed::from_data(bits![0, 0])) |
    //      combine::parser::char::string("%R01").map(|_|
    //      Parsed::from_data(bits![0, 1])) |
    //      combine::parser::char::string("%R02").map(|_|
    //      Parsed::from_data(bits![1, 0])) |
    //      combine::parser::char::string("%R03").map(|_|
    //      Parsed::from_data(bits![1, 1]))
    //    )
    //  }
    let mut arms = vec![];
    for (i, register) in register_group.registers.iter().enumerate() {
        let register = format!("%{}", register);

        if register_group.length == 0 {
            return quote! {
                combine::parser::char::string(#register).map(|_| Parsed::from_data(bitvec::prelude::BitVec::new()))
            };
        }

        let mut data = Vec::new();
        data.extend((0..register_group.length).map(|j| (i >> j) & 1).rev());
        let data = data
            .into_iter()
            .map(|b| b == 1usize)
            .map(|b| quote!(bv.push(#b)));

        arms.push(quote! {
            combine::parser::char::string(#register).map(|_| {
                let mut bv = bitvec::prelude::BitVec::new();
                #(#data);*;
                Parsed::from_data(bv)
            })
        });
    }

    quote! {
        combine::parser::choice::choice((
            #(#arms),*
                ,
        ))
    }
}

fn generate_argument_parser(definition: &ArgumentDefinition) -> proc_macro2::TokenStream {
    match definition {
        ArgumentDefinition::Immediate { bits } => {
            return quote! {
                parse_value::<Input>(#bits)
            };
        }
        ArgumentDefinition::DataAddress { bits } => {
            return quote! {
                parse_value::<Input>(#bits)
            };
        }
        ArgumentDefinition::TextAddress { bits } => {
            return quote! {
                parse_value::<Input>(#bits)
            };
        }
        ArgumentDefinition::Register { group } => {
            return generate_register_group_parser(group);
        }
        ArgumentDefinition::RegisterAddress { group } => {
            let register_parser = generate_register_group_parser(group);
            return quote! {
                (
                    combine::parser::char::char('['),
                    combine::skip_many(combine::parser::char::space()),
                    #register_parser,
                    combine::skip_many(combine::parser::char::space()),
                    combine::parser::char::char(']')
                ).map(|(_, _, parsed, _, _)| parsed)
            };
        }
        ArgumentDefinition::Padding { bits } => {
            let bits = bits.clone() as usize;
            return quote! {
                parse_padding::<Input>(#bits)
            };
        }
    }
}

fn generate_command_parser(
    definition: &CommandDefinition,
    opcode_length: u8,
    byte_size: u8,
    address_size: u8,
) -> proc_macro2::TokenStream {
    let mut data = Vec::new();
    data.extend(
        (0..opcode_length)
            .map(|j| (definition.opcode >> j) & 1 == 1)
            .rev(),
    );

    let mut meaningful_args_exist = false;
    // Add an optional comma and optional whitespace after each argument (comma -> optional, or
    // just whitespace)
    let mut argument_parsers = Vec::new();
    let mut argument_names_with_commas = Vec::new();
    for (i, argument) in definition.arguments.iter().enumerate() {
        match argument {
            ArgumentDefinition::Padding { .. } => {}
            _ => {
                if meaningful_args_exist {
                    argument_parsers.push(quote! {
                        (
                            combine::parser::choice::choice((
                                combine::parser::char::char(',').map(|_| ()),
                                combine::parser::char::space().map(|_| ()),
                            )),
                            combine::skip_many(combine::parser::char::space())
                        ).map(|_| ())
                    });
                    argument_names_with_commas
                        .push(syn::Ident::new("_", proc_macro2::Span::call_site()));
                }
                meaningful_args_exist = true;
            }
        }
        argument_parsers.push(generate_argument_parser(argument));
        argument_names_with_commas.push(syn::Ident::new(
            format!("arg{}", i).as_str(),
            proc_macro2::Span::call_site(),
        ));
    }

    let argument_extenders = definition.arguments.iter().enumerate().map(|(i, _)| {
        let name = format!("arg{}", i);
        let name = syn::Ident::new(name.as_str(), proc_macro2::Span::call_site());
        quote! {
            parsed.extend(#name);
        }
    });

    let post_opcode_space = if meaningful_args_exist {
        quote! {
            combine::skip_many1(combine::parser::char::space())
        }
    } else {
        quote! {
            combine::parser::char::string("").map(|_| ())
        }
    };

    let mnemonic = definition.mnemonic.as_str();
    let mnemonic_upper = definition.mnemonic.to_uppercase();
    let mnemonic_upper = mnemonic_upper.as_str();
    let byte_size = byte_size as usize;
    let address_size = address_size as usize;

    let map = quote! {{
        let mut bv = bitvec::prelude::BitVec::new();
        bv.extend(vec![#(#data),*]);

        let mut parsed = Parsed::from_data(bv);
        #(#argument_extenders);*;

        parsed.ground_relocations(#byte_size, #address_size);

        parsed
    }};

    return quote! {
        (
            combine::parser::choice::choice((
                combine::parser::char::string(#mnemonic).map(|_| ()),
                combine::parser::char::string(#mnemonic_upper).map(|_| ()),
            )),
            #post_opcode_space,
            #(#argument_parsers),*
        ).map(|(_, _, #(#argument_names_with_commas),*)| #map)
    };
}

fn generate_text_parser(definition: &Definition) -> proc_macro2::TokenStream {
    let mut command_parsers = definition
        .commands
        .iter()
        .map(|c| {
            generate_command_parser(
                c,
                definition.opcode_length,
                definition.text_byte_length,
                definition.address_size,
            )
        })
        .map(|c| {
            quote! { (
                                #c,
                                combine::skip_many(combine::parser::char::char(' ')),
                                combine::parser::choice::choice((
                                    parse_comment(),
                                    combine::parser::char::char('\n').map(|_| ()),
                                )),
            ).map(|(parsed, _, _)| parsed)

            }
        })
        .collect::<Vec<_>>();

    while command_parsers.len() > 1 {
        // Group it into 25-item blocks, each of them will be a choice
        let mut new_parsers = Vec::new();
        for chunk in command_parsers.chunks(25) {
            let chunk = chunk.iter().map(|c| quote! { combine::attempt(#c) });
            new_parsers.push(quote! {
                combine::parser::choice::choice((
                    #(#chunk),*
                        ,
                ))
            });
        }
        command_parsers = new_parsers;
    }
    let command_parser = command_parsers.pop().unwrap();

    return quote! {
        use combine::Parser;
        pub use monistode_binutils::{Address, Symbol};
        pub use monistode_binutils::object_file::Relocation;

        trait HelpfulSymbol {
            fn after(self, n_bits: usize) -> Self;
            fn as_parsed(self) -> Parsed;
        }

        impl HelpfulSymbol for Symbol {
            fn after(self, n_bits: usize) -> Symbol {
                Symbol {
                    name: self.name,
                    address: self.address + n_bits,
                }
            }

            fn as_parsed(self) -> Parsed {
                Parsed {
                    data: bitvec::prelude::BitVec::new(),
                    symbols: vec![self],
                    relocations: Vec::new(),
                }
            }
        }

        trait HelpfulRelocation {
            fn after(self, n_bits: usize) -> Self;
        }

        impl HelpfulRelocation for Relocation {
            fn after(self, n_bits: usize) -> Relocation {
                Relocation {
                    symbol: self.symbol,
                    address: self.address + n_bits,
                    relative: self.relative,
                }
            }
        }

        #[derive(Debug)]
        pub struct Parsed {
            data: bitvec::prelude::BitVec,
            symbols: Vec<Symbol>,
            relocations: Vec<Relocation>,
        }

        impl Parsed {
            fn from_data(data: bitvec::prelude::BitVec) -> Self {
                Parsed { data, symbols: Vec::new(), relocations: Vec::new() }
            }

            fn after(self, n_bits: usize) -> Parsed {
                Parsed {
                    data: self.data,
                    symbols: self.symbols.into_iter().map(|s| s.after(n_bits)).collect(),
                    relocations: self.relocations.into_iter().map(|r| r.after(n_bits)).collect(),
                }
            }

            fn ground_relocations(&mut self, byte_size: usize, address_size: usize) {
                for relocation in &self.relocations {
                    if !relocation.relative {
                        continue;
                    };
                    let offset = self.data.len() - relocation.address.0;
                    let offset_bytes = (offset + byte_size - 1) / byte_size;

                    let mut target: usize = 0;
                    for i in 0..address_size {
                        target |= (self.data[relocation.address.0 + i] as usize) << (address_size - i - 1);
                    }
                    let target = target.wrapping_sub(offset_bytes);
                    for i in 0..address_size {
                        self.data.set(
                            relocation.address.0 + i,
                            (target >> (address_size - i - 1)) & 1 != 0,
                        );
                    }
                }
            }

            fn extend(&mut self, other: Parsed) {
                let other = other.after(self.data.len());
                self.data.extend(other.data.iter().map(|b| *b));
                self.symbols.extend(other.symbols);
                self.relocations.extend(other.relocations);
            }
        }

        fn parse_symbol_name<Input>() -> impl combine::Parser<Input, Output = String>
        where
            Input: combine::Stream<Token = char>,
            Input::Error: combine::ParseError<Input::Token, Input::Range, Input::Position>,
        {
            (
                // Allow underscore or letter as first character
                combine::parser::choice::choice((
                    combine::parser::char::letter(),
                    combine::parser::char::char('_'),
                )),
                // Allow underscores in the rest of the name
                combine::parser::repeat::many(combine::parser::choice::choice((
                    combine::parser::char::alpha_num(),
                    combine::parser::char::char('_'),
                ))),
            ).map(|(first, rest): (char, Vec<char>)| {
                let mut name = String::new();
                name.push(first);
                for c in rest {
                    name.push(c);
                }
                name
            })
        }

        fn parse_padding<Input>(bits: usize) -> impl combine::Parser<Input, Output = Parsed>
        where
            Input: combine::Stream<Token = char>,
            Input::Error: combine::ParseError<Input::Token, Input::Range, Input::Position>,
        {
            combine::parser::char::string("").map(move |_| {
                let mut bv = bitvec::prelude::BitVec::new();
                bv.resize(bits, false);
                Parsed::from_data(bv)
            })
        }

        fn parse_numeric<Input>() -> impl combine::Parser<Input, Output = usize>
        where
            Input: combine::Stream<Token = char>,
            Input::Error: combine::ParseError<Input::Token, Input::Range, Input::Position>,
        {
            combine::parser::repeat::many1(combine::parser::char::digit())
                .map(move |s: String| {
                    s.parse().unwrap()
                })
        }

        fn parse_comment<Input>() -> impl combine::Parser<Input, Output = ()>
        where
            Input: combine::Stream<Token = char>,
            Input::Error: combine::ParseError<Input::Token, Input::Range, Input::Position>,
        {
            (
                combine::parser::choice::choice((
                    combine::parser::char::char('#'),
                    combine::parser::char::char(';'),
                )),
                combine::parser::repeat::skip_many(combine::satisfy(|c| c != '\n')),
                combine::parser::char::char('\n'),
            ).map(|_| ())
        }

        fn parse_value<Input>(n_bits: u8) -> impl combine::Parser<Input, Output = Parsed>
        where
            Input: combine::Stream<Token = char>,
            Input::Error: combine::ParseError<Input::Token, Input::Range, Input::Position>,
        {
            combine::parser::choice::choice((
                combine::attempt(parse_numeric().map(move |immediate: usize| {
                    let mut data = bitvec::prelude::BitVec::new();
                    data.extend((0..n_bits).map(|i| (immediate >> i) & 1 == 1).rev());
                    Parsed::from_data(data)
                })),
                combine::attempt(parse_symbol_name().map(move |symbol: String| {
                    let mut data = bitvec::prelude::BitVec::new();
                    data.extend((0..n_bits).map(|_| false));
                    Parsed {
                        data,
                        symbols: Vec::new(),
                        relocations: vec![Relocation {
                            symbol,
                            address: Address(0),
                            relative: true,
                        }],
                    }
                })),
                combine::attempt((
                    combine::parser::char::char('\''),
                    combine::satisfy(|c| c != '\''),
                    combine::parser::char::char('\''),
                ).map(move |(_, c, _)| {
                    let immediate = c as usize;
                    let mut data = bitvec::prelude::BitVec::new();
                    data.extend((0..n_bits).map(|i| (immediate >> i) & 1 == 1).rev());
                    Parsed::from_data(data)
                })),
            ))
        }

        fn parse_command<Input>() -> impl combine::Parser<Input, Output = Parsed>
        where
            Input: combine::Stream<Token = char>,
            Input::Error: combine::ParseError<Input::Token, Input::Range, Input::Position>,
        {
            #command_parser
        }

        fn parse_label<Input>() -> impl combine::Parser<Input, Output = Parsed>
        where
            Input: combine::Stream<Token = char>,
            Input::Error: combine::ParseError<Input::Token, Input::Range, Input::Position>,
        {
            (
                parse_symbol_name(),
                combine::parser::char::char(':'),
                combine::skip_many(combine::parser::char::char(' ')),
                combine::parser::choice::choice((
                    parse_comment(),
                    combine::parser::char::char('\n').map(|_| ()),
                )),
            ).map(|(name, _, _, _)| {
                Symbol {
                    name,
                    address: Address(0),
                }.as_parsed()
            })
        }

        fn parse_blank_or_comment_line<Input>() -> impl combine::Parser<Input, Output = ()>
        where
            Input: combine::Stream<Token = char>,
            Input::Error: combine::ParseError<Input::Token, Input::Range, Input::Position>,
        {
            (
                combine::parser::choice::choice((
                    // Just a blank line
                    combine::parser::char::char('\n').map(|_| ()),
                    // Comment line
                    parse_comment().map(|_| ()),
                )),
            ).map(|_| ())
        }

        fn parse_commands<Input>() -> impl combine::Parser<Input, Output = Vec<Parsed>>
        where
            Input: combine::Stream<Token = char>,
            Input::Error: combine::ParseError<Input::Token, Input::Range, Input::Position>,
        {
            combine::parser::repeat::many((
                combine::skip_many(combine::parser::char::char(' ')),
                combine::parser::choice::choice((
                    combine::attempt(parse_label()),
                    combine::attempt(parse_command()),
                    combine::attempt(parse_blank_or_comment_line().map(|_| {
                        Parsed {
                            data: bitvec::prelude::BitVec::new(),
                            symbols: Vec::new(),
                            relocations: Vec::new(),
                        }
                    })),
                ))
            ).map(|(_, parsed)| parsed))
        }

        fn parse_text<Input>() -> impl combine::Parser<Input, Output = Parsed>
        where
            Input: combine::Stream<Token = char>,
            Input::Error: combine::ParseError<Input::Token, Input::Range, Input::Position>,
        {
            (
                combine::parser::char::string(".text\n"),
                parse_commands()
            ).map(|(_, commands)| {
                let mut bv = bitvec::prelude::BitVec::new();
                let mut symbols = Vec::new();
                let mut relocations = Vec::new();
                for command in commands {
                    let command = command.after(bv.len());
                    bv.extend(command.data.iter().map(|b| *b));
                    symbols.extend(command.symbols);
                    relocations.extend(command.relocations);
                }
                Parsed {
                    data: bv,
                    symbols,
                    relocations,
                }
            })
        }
    };
}

pub fn generate_parser(definition: &Definition, architecture: &str) -> proc_macro2::TokenStream {
    let text_parser = generate_text_parser(definition);
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
