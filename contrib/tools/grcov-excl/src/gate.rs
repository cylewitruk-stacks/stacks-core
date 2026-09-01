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

//! Decides whether a `#[cfg(..)]` predicate makes an item test-only.

/// Three-valued logic, used to evaluate a `cfg` predicate in a hypothetical
/// "not a test build" configuration where every flag other than `test` and
/// `feature = "testing"` is unknown.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Tri {
    True,
    False,
    Unknown,
}

impl Tri {
    fn not(self) -> Self {
        match self {
            Tri::True => Tri::False,
            Tri::False => Tri::True,
            Tri::Unknown => Tri::Unknown,
        }
    }
}

/// Which build configuration a predicate is being evaluated against.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Build {
    /// A normal build: `test` is off, and so is `feature = "testing"`.
    NonTest,
    /// The instrumented test build coverage is collected from: `test` is on,
    /// but whether any given feature is enabled is not known here.
    Test,
}

/// Evaluate `meta` against `build`, leaving every flag the configuration does
/// not pin down as unknown.
fn eval(meta: &syn::Meta, build: Build) -> Tri {
    match meta {
        syn::Meta::Path(path) => {
            if path.is_ident("test") {
                match build {
                    Build::NonTest => Tri::False,
                    Build::Test => Tri::True,
                }
            } else {
                Tri::Unknown
            }
        }
        syn::Meta::NameValue(nv) => {
            let is_testing_feature = nv.path.is_ident("feature")
                && matches!(
                    &nv.value,
                    syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(s), .. })
                        if s.value() == "testing"
                );
            match (is_testing_feature, build) {
                (true, Build::NonTest) => Tri::False,
                // The coverage build may or may not turn `testing` on, so in a
                // test build it stays unknown.
                _ => Tri::Unknown,
            }
        }
        syn::Meta::List(list) => {
            let Ok(inner) = list.parse_args_with(
                syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
            ) else {
                return Tri::Unknown;
            };
            let vals: Vec<Tri> = inner.iter().map(|m| eval(m, build)).collect();

            if list.path.is_ident("all") {
                if vals.contains(&Tri::False) {
                    Tri::False
                } else if vals.iter().all(|v| *v == Tri::True) {
                    Tri::True
                } else {
                    Tri::Unknown
                }
            } else if list.path.is_ident("any") {
                if vals.contains(&Tri::True) {
                    Tri::True
                } else if vals.iter().all(|v| *v == Tri::False) {
                    Tri::False
                } else {
                    Tri::Unknown
                }
            } else if list.path.is_ident("not") {
                vals.first().copied().unwrap_or(Tri::Unknown).not()
            } else {
                Tri::Unknown
            }
        }
    }
}

/// Whether the item is certain to be compiled into the instrumented test build.
///
/// A `mod name;` is only guaranteed to have a backing file when it is; Rust is
/// happy for `#[cfg(all(test, feature = "extra"))] mod extra_tests;` to point at
/// nothing when that feature is off, because `cfg` stripping happens before
/// modules are loaded. Anything less than certain must not be treated as a
/// missing file.
pub fn always_present_in_test_build(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().all(|attr| {
        // `cfg_attr` can expand to a further `cfg`, as in
        // `#[cfg_attr(test, cfg(feature = "extra"))]`. Reading through the
        // expansion is more than this needs, so any `cfg_attr` carrying a
        // nested `cfg` is treated as leaving presence undecided.
        if attr.path().is_ident("cfg_attr") {
            let syn::Meta::List(list) = &attr.meta else {
                return true;
            };
            return !list
                .tokens
                .clone()
                .into_iter()
                .any(|token| matches!(&token, proc_macro2::TokenTree::Ident(i) if i == "cfg"));
        }
        if !attr.path().is_ident("cfg") {
            return true;
        }
        let syn::Meta::List(list) = &attr.meta else {
            return true;
        };
        match list.parse_args::<syn::Meta>() {
            Ok(inner) => eval(&inner, Build::Test) == Tri::True,
            Err(_) => false,
        }
    })
}

/// Why an item exists only in test builds, if it does.
pub fn test_only(attrs: &[syn::Attribute]) -> Option<String> {
    test_only_cfg(attrs).or_else(|| test_harness_attribute(attrs))
}

/// An attribute that hands the item to a test harness.
///
/// These need no `cfg` to be test-only: rustc only builds `#[test]` functions
/// under `--test`, so they exist solely in the instrumented test binaries. A
/// bare `#[test] fn` outside any `#[cfg(test)] mod` would otherwise be counted
/// as fully-covered production code.
fn test_harness_attribute(attrs: &[syn::Attribute]) -> Option<String> {
    attrs.iter().find_map(|attr| {
        let path = attr.path();
        // Matched on the last segment so that `tokio::test`, `rstest::rstest`
        // and friends are covered alongside their bare forms.
        let last = path.segments.last()?.ident.to_string();
        let is_harness = matches!(last.as_str(), "test" | "rstest" | "bench")
            // rstest_reuse: `#[template]` defines a test shape and
            // `#[apply(..)]` stamps it out as a test function.
            || (path.segments.len() == 1 && matches!(last.as_str(), "apply" | "template"));

        is_harness.then(|| format!("#[{}]", quote::quote!(#path).to_string().replace(' ', "")))
    })
}

/// The rendered predicate of the first test-only `#[cfg(..)]` in `attrs`, if any.
fn test_only_cfg(attrs: &[syn::Attribute]) -> Option<String> {
    attrs.iter().find_map(|attr| {
        if !attr.path().is_ident("cfg") {
            return None;
        }
        let syn::Meta::List(list) = &attr.meta else {
            return None;
        };
        let inner = list.parse_args::<syn::Meta>().ok()?;
        (eval(&inner, Build::NonTest) == Tri::False).then(|| {
            format!(
                "cfg({})",
                quote::quote!(#inner).to_string().replace(' ', "")
            )
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attrs_of(src: &str) -> Vec<syn::Attribute> {
        syn::parse_str::<syn::ItemFn>(src)
            .expect("parses as a function")
            .attrs
    }

    fn gate_of(src: &str) -> Option<String> {
        test_only(&attrs_of(src))
    }

    #[test]
    fn cfg_predicates_that_cannot_exist_outside_a_test_build() {
        for src in [
            "#[cfg(test)] fn f() {}",
            r#"#[cfg(any(test, feature = "testing"))] fn f() {}"#,
            r#"#[cfg(all(any(test, feature = "testing"), not(feature = "wasm-deterministic")))] fn f() {}"#,
            r#"#[cfg(all(feature = "wasm-deterministic", any(test, feature = "testing")))] fn f() {}"#,
            "#[cfg(all(test, not(feature = \"prod-genesis-chainstate\")))] fn f() {}",
        ] {
            assert!(gate_of(src).is_some(), "should be test-only: {src}");
        }
    }

    #[test]
    fn cfg_predicates_that_survive_a_non_test_build() {
        for src in [
            "fn f() {}",
            "#[cfg(not(test))] fn f() {}",
            "#[cfg(not(any(test, feature = \"testing\")))] fn f() {}",
            r#"#[cfg(any(feature = "bech32_std", test))] fn f() {}"#,
            r#"#[cfg(feature = "monitoring_prom")] fn f() {}"#,
            "#[cfg(unix)] fn f() {}",
            "#[derive(Debug)] fn f() {}",
        ] {
            assert_eq!(gate_of(src), None, "should not be test-only: {src}");
        }
    }

    #[test]
    fn harness_attributes_are_test_only_without_any_cfg() {
        // A bare `#[test] fn` outside a `#[cfg(test)] mod` is compiled only
        // under --test, so it lands in the instrumented binary and would
        // otherwise be counted as fully-covered production code.
        for src in [
            "#[test] fn f() {}",
            "#[tokio::test] fn f() {}",
            "#[rstest] fn f() {}",
            "#[rstest::rstest] fn f() {}",
            "#[apply(some_template)] fn f() {}",
            "#[template] fn f() {}",
            "#[bench] fn f() {}",
            "#[ignore] #[test] fn f() {}",
        ] {
            assert!(gate_of(src).is_some(), "should be test-only: {src}");
        }
    }

    #[test]
    fn harness_matching_does_not_swallow_unrelated_attributes() {
        for src in [
            "#[inline] fn f() {}",
            "#[serial] fn f() {}",
            "#[allow(dead_code)] fn f() {}",
            // `apply`/`template` are rstest_reuse and only match unqualified.
            "#[other::apply(x)] fn f() {}",
            "#[other::template] fn f() {}",
        ] {
            assert_eq!(gate_of(src), None, "should not be test-only: {src}");
        }
    }

    #[test]
    fn presence_in_a_test_build_is_only_claimed_when_it_is_certain() {
        // An unconditional test gate means the module must exist ..
        assert!(always_present_in_test_build(&attrs_of(
            "#[cfg(test)] fn f() {}"
        )));
        assert!(always_present_in_test_build(&attrs_of(
            r#"#[cfg(any(test, feature = "testing"))] fn f() {}"#
        )));
        assert!(always_present_in_test_build(&attrs_of("fn f() {}")));

        // .. while an optional feature means it need not, because `cfg`
        // stripping happens before modules are loaded.
        assert!(!always_present_in_test_build(&attrs_of(
            r#"#[cfg(all(test, feature = "extra"))] fn f() {}"#
        )));
        assert!(!always_present_in_test_build(&attrs_of(
            r#"#[cfg(target_os = "linux")] fn f() {}"#
        )));
    }

    #[test]
    fn a_cfg_attr_that_can_introduce_a_cfg_leaves_presence_undecided() {
        assert!(!always_present_in_test_build(&attrs_of(
            "#[cfg(test)]\n#[cfg_attr(test, cfg(feature = \"extra\"))]\nfn f() {}"
        )));
        // The forms actually used in this repository expand to lint and test
        // attributes, never to a `cfg`, so they must not be penalised.
        for src in [
            "#[cfg(test)]\n#[cfg_attr(test, mutants::skip)]\nfn f() {}",
            "#[cfg(test)]\n#[cfg_attr(test, allow(dead_code))]\nfn f() {}",
            "#[cfg(test)]\n#[cfg_attr(test, pinny::tag(slow))]\nfn f() {}",
        ] {
            assert!(always_present_in_test_build(&attrs_of(src)), "{src}");
        }
    }

    #[test]
    fn reported_reason_identifies_the_gate() {
        assert_eq!(
            gate_of("#[cfg(test)] fn f() {}").as_deref(),
            Some("cfg(test)")
        );
        assert_eq!(gate_of("#[test] fn f() {}").as_deref(), Some("#[test]"));
    }
}
