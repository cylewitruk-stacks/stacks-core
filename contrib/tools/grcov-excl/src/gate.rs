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

/// Evaluate `meta` with `test` and `feature = "testing"` forced off and every
/// other flag left unknown. A `False` result proves the item cannot exist
/// outside a test build.
fn eval(meta: &syn::Meta) -> Tri {
    match meta {
        syn::Meta::Path(path) => {
            if path.is_ident("test") {
                Tri::False
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
            if is_testing_feature {
                Tri::False
            } else {
                Tri::Unknown
            }
        }
        syn::Meta::List(list) => {
            let Ok(inner) = list.parse_args_with(
                syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
            ) else {
                return Tri::Unknown;
            };
            let vals: Vec<Tri> = inner.iter().map(eval).collect();

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
        (eval(&inner) == Tri::False).then(|| {
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
    fn reported_reason_identifies_the_gate() {
        assert_eq!(
            gate_of("#[cfg(test)] fn f() {}").as_deref(),
            Some("cfg(test)")
        );
        assert_eq!(gate_of("#[test] fn f() {}").as_deref(), Some("#[test]"));
    }
}
