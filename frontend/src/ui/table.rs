//! Data table.

use super::{icon, use_id, Spinner};
use std::rc::Rc;
use yew::prelude::*;

/// One table column: an id, a header, and how to render a cell.
pub struct Column<T> {
    pub id: AttrValue,
    pub header: Html,
    pub cell: Rc<dyn Fn(&T) -> Html>,
    pub sortable: bool,
    pub width: Option<AttrValue>,
}

impl<T> Clone for Column<T> {
    fn clone(&self) -> Self {
        Self {
            id: self.id.clone(),
            header: self.header.clone(),
            cell: self.cell.clone(),
            sortable: self.sortable,
            width: self.width.clone(),
        }
    }
}

impl<T> PartialEq for Column<T> {
    fn eq(&self, o: &Self) -> bool {
        self.id == o.id && self.header == o.header && Rc::ptr_eq(&self.cell, &o.cell) && self.sortable == o.sortable
    }
}

impl<T> Column<T> {
    pub fn new(id: impl Into<AttrValue>, header: impl Into<AttrValue>, cell: impl Fn(&T) -> Html + 'static) -> Self {
        let header: AttrValue = header.into();
        Self { id: id.into(), header: html! { {header} }, cell: Rc::new(cell), sortable: false, width: None }
    }
    /// Replace the plain-text header with arbitrary markup.
    pub fn header_html(mut self, h: Html) -> Self {
        self.header = h;
        self
    }
    /// Header becomes a sort button; the parent sorts `items` in `on_sort`.
    pub fn sortable(mut self) -> Self {
        self.sortable = true;
        self
    }
    pub fn width(mut self, w: impl Into<AttrValue>) -> Self {
        self.width = Some(w.into());
        self
    }
}

#[derive(Properties)]
pub struct TableProps<T: Clone + PartialEq + 'static> {
    pub items: Vec<T>,
    pub columns: Vec<Column<T>>,
    /// Usually a `<Header>`; also provides the table's accessible name.
    #[prop_or_default]
    pub header: Html,
    /// Explicit accessible name (wins over the header).
    #[prop_or_default]
    pub aria_label: Option<AttrValue>,
    #[prop_or_default]
    pub filter: Html,
    #[prop_or_default]
    pub pagination: Html,
    #[prop_or_default]
    pub footer: Html,
    /// Shown instead of rows when `items` is empty and not loading.
    #[prop_or_default]
    pub empty: Html,
    #[prop_or_default]
    pub loading: bool,
    #[prop_or_default]
    pub loading_text: Option<AttrValue>,
    /// "container" (default) | "embedded" | "borderless" | "full-page" | "stacked"
    #[prop_or(AttrValue::Static("container"))]
    pub variant: AttrValue,
    #[prop_or_default]
    pub striped_rows: bool,
    #[prop_or_default]
    pub sticky_header: bool,
    #[prop_or_default]
    pub wrap_lines: bool,
    /// Stable row key (Cloudscape `trackBy`). Required for selection.
    #[prop_or_default]
    pub track_by: Option<Callback<T, String>>,
    /// "single" | "multi"
    #[prop_or_default]
    pub selection_type: Option<AttrValue>,
    /// Keys (per `track_by`) of selected rows.
    #[prop_or_default]
    pub selected_keys: Vec<String>,
    /// Full new selection.
    #[prop_or_default]
    pub on_selection_change: Callback<Vec<T>>,
    #[prop_or_default]
    pub is_item_disabled: Option<Callback<T, bool>>,
    #[prop_or_default]
    pub on_row_click: Option<Callback<T>>,
    /// Id of the column currently sorted by.
    #[prop_or_default]
    pub sorting_column: Option<AttrValue>,
    #[prop_or_default]
    pub sorting_descending: bool,
    /// (column id, descending) when a sortable header is clicked.
    #[prop_or_default]
    pub on_sort: Callback<(AttrValue, bool)>,
    /// Extra per-row `data-testid`.
    #[prop_or_default]
    pub row_testid: Option<Callback<T, String>>,
    #[prop_or_default]
    pub testid: Option<AttrValue>,
}

impl<T: Clone + PartialEq + 'static> PartialEq for TableProps<T> {
    fn eq(&self, o: &Self) -> bool {
        self.items == o.items
            && self.columns == o.columns
            && self.header == o.header
            && self.aria_label == o.aria_label
            && self.filter == o.filter
            && self.pagination == o.pagination
            && self.footer == o.footer
            && self.empty == o.empty
            && self.loading == o.loading
            && self.loading_text == o.loading_text
            && self.variant == o.variant
            && self.selection_type == o.selection_type
            && self.selected_keys == o.selected_keys
            && self.on_selection_change == o.on_selection_change
            && self.on_row_click == o.on_row_click
            && self.sorting_column == o.sorting_column
            && self.sorting_descending == o.sorting_descending
            && self.on_sort == o.on_sort
            && self.track_by == o.track_by
            && self.testid == o.testid
    }
}

/// Table with optional header/filter/pagination slots, selection and
/// parent-driven sorting. Named by `aria_label`, else by its header.
#[function_component]
pub fn Table<T: Clone + PartialEq + 'static>(p: &TableProps<T>) -> Html {
    let header_id = use_id("ui-table");
    let has_header = p.header != Html::default();
    let key_of = |item: &T, idx: usize| -> String {
        p.track_by.as_ref().map(|f| f.emit(item.clone())).unwrap_or_else(|| idx.to_string())
    };
    let disabled = |item: &T| p.is_item_disabled.as_ref().map(|f| f.emit(item.clone())).unwrap_or(false);
    let selection = p.selection_type.as_deref();
    let ncols = p.columns.len() + usize::from(selection.is_some());

    let selectable: Vec<(usize, &T)> = p.items.iter().enumerate().filter(|(_, it)| !disabled(it)).collect();
    let all_selected = !selectable.is_empty()
        && selectable.iter().all(|(i, it)| p.selected_keys.contains(&key_of(it, *i)));

    let select_all = {
        let cb = p.on_selection_change.clone();
        let items: Vec<T> = selectable.iter().map(|(_, it)| (*it).clone()).collect();
        Callback::from(move |_: Event| cb.emit(if all_selected { vec![] } else { items.clone() }))
    };

    let head = html! {
        <thead>
            <tr>
                if selection.is_some() {
                    <th class="ui-th ui-th-select" scope="col">
                        if selection == Some("multi") {
                            <input type="checkbox" aria-label="Select all" checked={all_selected} onchange={select_all} />
                        }
                    </th>
                }
                { for p.columns.iter().map(|c| {
                    let sorted = p.sorting_column.as_ref() == Some(&c.id);
                    let aria_sort = sorted.then_some(if p.sorting_descending { "descending" } else { "ascending" });
                    let style = c.width.as_ref().map(|w| format!("width:{w};"));
                    let inner = if c.sortable {
                        let cb = p.on_sort.clone();
                        let id = c.id.clone();
                        let next_desc = sorted && !p.sorting_descending;
                        html! {
                            <button type="button" class="ui-th-sort" onclick={move |_| cb.emit((id.clone(), next_desc))}>
                                {c.header.clone()}
                                <span class={classes!("ui-sort-caret", sorted.then_some("ui-sort-active"), (sorted && !p.sorting_descending).then_some("ui-sort-asc"))}>
                                    {icon("caret-down")}
                                </span>
                            </button>
                        }
                    } else {
                        c.header.clone()
                    };
                    html! { <th class="ui-th" scope="col" key={c.id.to_string()} aria-sort={aria_sort} {style}>{inner}</th> }
                }) }
            </tr>
        </thead>
    };

    let body = if p.loading {
        html! {
            <tr><td class="ui-td ui-table-status" colspan={ncols.to_string()}>
                <Spinner />{" "}{p.loading_text.clone().unwrap_or(AttrValue::Static("Loading"))}
            </td></tr>
        }
    } else if p.items.is_empty() {
        html! { <tr><td class="ui-td ui-table-status" colspan={ncols.to_string()}>{p.empty.clone()}</td></tr> }
    } else {
        p.items.iter().enumerate().map(|(idx, item)| {
            let key = key_of(item, idx);
            let is_selected = selection.is_some() && p.selected_keys.contains(&key);
            let is_disabled = disabled(item);
            let onclick = p.on_row_click.as_ref().map(|cb| {
                let cb = cb.clone();
                let item = item.clone();
                Callback::from(move |_: MouseEvent| cb.emit(item.clone()))
            });
            let select_cell = selection.map(|kind| {
                let cb = p.on_selection_change.clone();
                let item = item.clone();
                let single = kind == "single";
                let current: Vec<T> = p.items.iter().enumerate()
                    .filter(|(i, it)| p.selected_keys.contains(&key_of(it, *i)))
                    .map(|(_, it)| it.clone())
                    .collect();
                let onchange = Callback::from(move |_: Event| {
                    if single {
                        cb.emit(vec![item.clone()]);
                    } else if is_selected {
                        cb.emit(current.iter().filter(|c| **c != item).cloned().collect());
                    } else {
                        let mut next = current.clone();
                        next.push(item.clone());
                        cb.emit(next);
                    }
                });
                html! {
                    <td class="ui-td ui-td-select" onclick={|e: MouseEvent| e.stop_propagation()}>
                        <input type={if single { "radio" } else { "checkbox" }} aria-label="Select row"
                               checked={is_selected} disabled={is_disabled} {onchange} />
                    </td>
                }
            });
            html! {
                <tr key={key} class={classes!("ui-tr", is_selected.then_some("ui-tr-selected"), onclick.is_some().then_some("ui-tr-clickable"))}
                    aria-selected={selection.map(|_| is_selected.to_string())}
                    data-testid={p.row_testid.as_ref().map(|f| f.emit(item.clone()))} {onclick}>
                    {select_cell}
                    { for p.columns.iter().map(|c| html! { <td class="ui-td" key={c.id.to_string()}>{(c.cell)(item)}</td> }) }
                </tr>
            }
        }).collect::<Html>()
    };

    let labelledby = (p.aria_label.is_none() && has_header).then(|| header_id.clone());
    html! {
        <div class={classes!("ui-table", format!("ui-table-{}", p.variant), p.striped_rows.then_some("ui-table-striped"),
                             p.sticky_header.then_some("ui-table-sticky"), p.wrap_lines.then_some("ui-table-wrap"))}
             data-testid={p.testid.clone()}>
            if has_header || p.filter != Html::default() || p.pagination != Html::default() {
                <div class="ui-table-tools">
                    if has_header { <div class="ui-table-header" id={header_id}>{p.header.clone()}</div> }
                    if p.filter != Html::default() || p.pagination != Html::default() {
                        <div class="ui-table-controls">
                            <div class="ui-table-filter">{p.filter.clone()}</div>
                            <div class="ui-table-pagination">{p.pagination.clone()}</div>
                        </div>
                    }
                </div>
            }
            <div class="ui-table-scroll">
                <table role="table" aria-label={p.aria_label.clone()} aria-labelledby={labelledby}>
                    {head}
                    <tbody>{body}</tbody>
                </table>
            </div>
            if p.footer != Html::default() { <div class="ui-table-footer">{p.footer.clone()}</div> }
        </div>
    }
}
