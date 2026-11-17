//! In-house UI kit.
//!
//! These components replace the Cloudscape React components the app used to
//! be built on. They keep the same vocabulary (variants, sizes, colour names)
//! and — importantly for the Playwright suite — the same accessibility tree:
//! roles, accessible names, and where `data-testid` lands.

#![allow(dead_code)] // kit API: not every builder/prop is used by a page yet

mod charts;
mod form;
mod icons;
mod layout;
mod overlay;
mod table;

pub use charts::*;
pub use form::*;
pub use icons::icon;
pub use layout::*;
pub use overlay::*;
pub use table::*;

use std::cell::Cell;
use yew::prelude::*;

thread_local! {
    static NEXT_ID: Cell<u32> = const { Cell::new(0) };
}

/// A DOM id that is stable for the lifetime of the calling component.
#[hook]
pub fn use_id(prefix: &'static str) -> AttrValue {
    (*use_memo((), |_| {
        let n = NEXT_ID.with(|c| {
            c.set(c.get() + 1);
            c.get()
        });
        AttrValue::from(format!("{prefix}-{n}"))
    }))
    .clone()
}

/// Cloudscape spacing token → pixels.
pub(crate) fn space_px(token: &str) -> u32 {
    match token {
        "n" | "none" => 0,
        "xxxs" => 2,
        "xxs" => 4,
        "xs" => 8,
        "s" => 12,
        "m" => 16,
        "l" => 20,
        "xl" => 24,
        "xxl" => 32,
        "xxxl" => 40,
        _ => 0,
    }
}
