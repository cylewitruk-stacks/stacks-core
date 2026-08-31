// Copyright (C) 2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! Locates test-only regions and module declarations in a parsed Rust file.

use syn::spanned::Spanned;
use syn::visit::{self, Visit};

use crate::gate;

/// A span of lines that exists only in test builds and so must not be counted
/// toward coverage. Line numbers are 1-based and inclusive.
#[derive(Debug)]
pub struct Region {
    pub start: usize,
    pub end: usize,
    pub kind: &'static str,
    pub gate: String,
}

/// A `mod name;` declaration, i.e. one whose body is another file.
#[derive(Debug)]
pub struct ModDecl {
    pub name: String,
    /// Value of a `#[path = ".."]` attribute, if present.
    pub path: Option<String>,
    pub test_only: bool,
}

#[derive(Default)]
pub struct Scan {
    pub regions: Vec<Region>,
    pub mod_decls: Vec<ModDecl>,
    /// Line of the first top-level item, where a whole-file marker belongs.
    pub first_item_line: Option<usize>,
}

/// `use` and `mod name;` are declarations that llvm-cov never attributes a
/// counter to, so marking them would be pure churn. Everything else can carry
/// instrumentation — including `static`s with closure initializers and types
/// whose `derive`s expand to real code — so it gets marked.
fn is_markable(kind: &str) -> bool {
    !matches!(kind, "use" | "mod-decl")
}

pub fn scan(file: &syn::File) -> Scan {
    let mut visitor = Visitor::default();
    visitor.visit_file(file);
    let mut scan = visitor.scan;
    scan.regions.sort_by_key(|r| (r.start, r.end));
    scan.first_item_line = file.items.first().map(|i| i.span().start().line);
    scan
}

#[derive(Default)]
struct Visitor {
    scan: Scan,
}

impl Visitor {
    /// Record a test-only region, unless it sits inside one already recorded —
    /// grcov's regions do not nest, so the inner markers would close the outer
    /// region early.
    fn record(&mut self, attrs: &[syn::Attribute], span: proc_macro2::Span, kind: &'static str) {
        if !is_markable(kind) {
            return;
        }
        let Some(gate) = gate::test_only(attrs) else {
            return;
        };
        let (start, end) = (span.start().line, span.end().line);
        if self
            .scan
            .regions
            .iter()
            .any(|r| r.start <= start && end <= r.end)
        {
            return;
        }
        self.scan.regions.push(Region {
            start,
            end,
            kind,
            gate,
        });
    }
}

impl<'ast> Visit<'ast> for Visitor {
    fn visit_item(&mut self, item: &'ast syn::Item) {
        let (kind, attrs) = item_parts(item);
        if let syn::Item::Mod(m) = item {
            if m.content.is_none() {
                self.scan.mod_decls.push(ModDecl {
                    name: m.ident.to_string(),
                    path: path_attr(&m.attrs),
                    test_only: gate::test_only(&m.attrs).is_some(),
                });
            }
        }
        self.record(attrs, item.span(), kind);
        visit::visit_item(self, item);
    }

    fn visit_impl_item(&mut self, item: &'ast syn::ImplItem) {
        let attrs: &[syn::Attribute] = match item {
            syn::ImplItem::Fn(x) => &x.attrs,
            syn::ImplItem::Const(x) => &x.attrs,
            syn::ImplItem::Type(x) => &x.attrs,
            syn::ImplItem::Macro(x) => &x.attrs,
            _ => &[],
        };
        self.record(attrs, item.span(), "impl-item");
        visit::visit_impl_item(self, item);
    }

    fn visit_trait_item(&mut self, item: &'ast syn::TraitItem) {
        let attrs: &[syn::Attribute] = match item {
            syn::TraitItem::Fn(x) => &x.attrs,
            syn::TraitItem::Const(x) => &x.attrs,
            syn::TraitItem::Type(x) => &x.attrs,
            syn::TraitItem::Macro(x) => &x.attrs,
            _ => &[],
        };
        self.record(attrs, item.span(), "trait-item");
        visit::visit_trait_item(self, item);
    }

    fn visit_stmt(&mut self, stmt: &'ast syn::Stmt) {
        let attrs: &[syn::Attribute] = match stmt {
            syn::Stmt::Local(l) => &l.attrs,
            syn::Stmt::Expr(e, _) => expr_attrs(e),
            syn::Stmt::Macro(m) => &m.attrs,
            // Handled by `visit_item`, which knows the item's kind.
            syn::Stmt::Item(_) => &[],
        };
        self.record(attrs, stmt.span(), "stmt");
        visit::visit_stmt(self, stmt);
    }

    fn visit_arm(&mut self, arm: &'ast syn::Arm) {
        self.record(&arm.attrs, arm.span(), "match-arm");
        visit::visit_arm(self, arm);
    }

    fn visit_field(&mut self, field: &'ast syn::Field) {
        self.record(&field.attrs, field.span(), "field");
        visit::visit_field(self, field);
    }

    fn visit_variant(&mut self, variant: &'ast syn::Variant) {
        self.record(&variant.attrs, variant.span(), "variant");
        visit::visit_variant(self, variant);
    }

    fn visit_field_value(&mut self, field: &'ast syn::FieldValue) {
        self.record(&field.attrs, field.span(), "field-value");
        visit::visit_field_value(self, field);
    }
}

fn item_parts(item: &syn::Item) -> (&'static str, &[syn::Attribute]) {
    match item {
        syn::Item::Mod(x) => (
            if x.content.is_some() {
                "mod-inline"
            } else {
                "mod-decl"
            },
            &x.attrs,
        ),
        syn::Item::Use(x) => ("use", &x.attrs),
        syn::Item::Fn(x) => ("fn", &x.attrs),
        syn::Item::Impl(x) => ("impl", &x.attrs),
        syn::Item::Macro(x) => ("macro", &x.attrs),
        syn::Item::Const(x) => ("const", &x.attrs),
        syn::Item::Static(x) => ("static", &x.attrs),
        syn::Item::Struct(x) => ("struct", &x.attrs),
        syn::Item::Enum(x) => ("enum", &x.attrs),
        syn::Item::Union(x) => ("union", &x.attrs),
        syn::Item::Trait(x) => ("trait", &x.attrs),
        syn::Item::TraitAlias(x) => ("trait-alias", &x.attrs),
        syn::Item::Type(x) => ("type", &x.attrs),
        syn::Item::ExternCrate(x) => ("extern-crate", &x.attrs),
        syn::Item::ForeignMod(x) => ("extern-block", &x.attrs),
        _ => ("item", &[]),
    }
}

fn path_attr(attrs: &[syn::Attribute]) -> Option<String> {
    attrs.iter().find_map(|attr| {
        let syn::Meta::NameValue(nv) = &attr.meta else {
            return None;
        };
        if !nv.path.is_ident("path") {
            return None;
        }
        match &nv.value {
            syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(s),
                ..
            }) => Some(s.value()),
            _ => None,
        }
    })
}

fn expr_attrs(expr: &syn::Expr) -> &[syn::Attribute] {
    macro_rules! attrs_of {
        ($($variant:ident),* $(,)?) => {
            match expr { $(syn::Expr::$variant(x) => &x.attrs,)* _ => &[] }
        };
    }
    attrs_of!(
        Array, Assign, Async, Await, Binary, Block, Break, Call, Cast, Closure, Const, Continue,
        Field, ForLoop, Group, If, Index, Infer, Let, Lit, Loop, Macro, Match, MethodCall, Paren,
        Path, Range, Reference, Repeat, Return, Struct, Try, TryBlock, Tuple, Unary, Unsafe, While,
        Yield,
    )
}
