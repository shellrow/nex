#![deny(warnings)]

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput, Visibility};

mod decorator;
mod util;

/// The entry point for the `derive(Packet)` custom derive
#[proc_macro_derive(Packet, attributes(construct_with, length, length_fn, payload))]
pub fn derive_packet(input: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(input as DeriveInput);
    // ensure struct is public
    match ast.vis {
        Visibility::Public(_) => (),
        _ => {
            let ts = syn::Error::new(ast.ident.span(), "#[packet] structs must be public")
                .to_compile_error();
            return ts.into();
        }
    }
    let name = &ast.ident;
    let s = match &ast.data {
        syn::Data::Struct(ref s) => decorator::generate_packet(s, name.to_string()),
        _ => panic!("Only structs are supported"),
    };
    match s {
        Ok(ts) => ts.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

/// The entry point for the `packet` proc_macro_attribute
#[proc_macro_attribute]
pub fn packet(_attrs: TokenStream, code: TokenStream) -> TokenStream {
    // let _attrs = parse_macro_input!(attrs as AttributeArgs);
    let input = parse_macro_input!(code as DeriveInput);
    // enhancement: if input already has Clone and/or Debug, do not add them
    let s = quote! {
        #[derive(::nex_macro::Packet, Clone, Debug)]
        #[allow(unused_attributes)]
        #input
    };
    s.into()
}
