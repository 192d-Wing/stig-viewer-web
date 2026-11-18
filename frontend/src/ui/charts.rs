//! SVG charts: line/threshold series and a pie/donut.

use yew::prelude::*;

#[derive(Clone, PartialEq)]
pub struct ChartSeries {
    pub title: AttrValue,
    /// CSS colour; falls back to the built-in palette by index.
    pub color: Option<AttrValue>,
    /// (x, y). For time scales x is epoch milliseconds.
    pub data: Vec<(f64, f64)>,
    /// Horizontal threshold line at this y (ignores `data`).
    pub threshold: Option<f64>,
}

impl ChartSeries {
    pub fn line(title: impl Into<AttrValue>, data: Vec<(f64, f64)>) -> Self {
        Self {
            title: title.into(),
            color: None,
            data,
            threshold: None,
        }
    }
    pub fn threshold(title: impl Into<AttrValue>, y: f64) -> Self {
        Self {
            title: title.into(),
            color: None,
            data: vec![],
            threshold: Some(y),
        }
    }
    pub fn color(mut self, c: impl Into<AttrValue>) -> Self {
        self.color = Some(c.into());
        self
    }
}

pub const CHART_PALETTE: [&str; 8] = [
    "#3ec6b3", "#ff7a7a", "#62c26a", "#b39bf5", "#e8bd45", "#f59b4c", "#82aee8", "#e58fb1",
];

pub const CHART_NEGATIVE: &str = "#ff7a7a";
pub const CHART_POSITIVE: &str = "#62c26a";

#[derive(Properties, PartialEq)]
pub struct LineChartProps {
    pub series: Vec<ChartSeries>,
    /// "time" (x is epoch ms; ticks render as local dates) | "linear"
    #[prop_or(AttrValue::Static("linear"))]
    pub x_scale_type: AttrValue,
    #[prop_or_default]
    pub x_title: Option<AttrValue>,
    #[prop_or_default]
    pub y_title: Option<AttrValue>,
    /// Fixed y range; defaults to 0..max.
    #[prop_or_default]
    pub y_domain: Option<(f64, f64)>,
    #[prop_or(300)]
    pub height: u32,
    #[prop_or_default]
    pub aria_label: Option<AttrValue>,
    /// Shown when no series has data.
    #[prop_or_default]
    pub empty: Html,
    /// Custom x tick label.
    #[prop_or_default]
    pub x_tick_formatter: Option<Callback<f64, String>>,
    /// Custom y tick label.
    #[prop_or_default]
    pub y_tick_formatter: Option<Callback<f64, String>>,
    #[prop_or_default]
    pub testid: Option<AttrValue>,
}

fn nice(v: f64) -> String {
    if (v - v.round()).abs() < 1e-9 {
        format!("{}", v.round() as i64)
    } else {
        format!("{v:.1}")
    }
}

#[function_component]
pub fn LineChart(p: &LineChartProps) -> Html {
    let has_data = p.series.iter().any(|s| !s.data.is_empty());
    if !has_data {
        return html! {
            <div class="ui-chart ui-chart-empty" data-testid={p.testid.clone()} style={format!("min-height:{}px", p.height.min(160))}>
                {p.empty.clone()}
            </div>
        };
    }
    let (w, h) = (720.0_f64, p.height as f64);
    let (ml, mr, mt, mb) = (56.0, 16.0, 12.0, 44.0);
    let xs = p.series.iter().flat_map(|s| s.data.iter().map(|d| d.0));
    let (mut x0, mut x1) = xs.fold((f64::INFINITY, f64::NEG_INFINITY), |(a, b), x| {
        (a.min(x), b.max(x))
    });
    if (x1 - x0).abs() < f64::EPSILON {
        x0 -= 1.0;
        x1 += 1.0;
    }
    let (y0, y1) = p.y_domain.unwrap_or_else(|| {
        let max = p
            .series
            .iter()
            .flat_map(|s| s.data.iter().map(|d| d.1).chain(s.threshold))
            .fold(0.0_f64, f64::max);
        (0.0, if max <= 0.0 { 1.0 } else { max * 1.1 })
    });
    let sx = |x: f64| ml + (x - x0) / (x1 - x0) * (w - ml - mr);
    let sy = |y: f64| h - mb - (y - y0) / (y1 - y0).max(f64::EPSILON) * (h - mt - mb);
    let fmt_x = |x: f64| match &p.x_tick_formatter {
        Some(f) => f.emit(x),
        None if p.x_scale_type == "time" => crate::util::ms_to_locale_date_string(x),
        None => nice(x),
    };
    let fmt_y = |y: f64| match &p.y_tick_formatter {
        Some(f) => f.emit(y),
        None => nice(y),
    };
    let y_ticks: Vec<f64> = (0..=4)
        .map(|i| y0 + (y1 - y0) * f64::from(i) / 4.0)
        .collect();
    let x_ticks: Vec<f64> = (0..=4)
        .map(|i| x0 + (x1 - x0) * f64::from(i) / 4.0)
        .collect();
    let color = |i: usize, s: &ChartSeries| {
        s.color
            .clone()
            .unwrap_or(AttrValue::Static(CHART_PALETTE[i % CHART_PALETTE.len()]))
    };
    html! {
        <div class="ui-chart" data-testid={p.testid.clone()}>
            <svg viewBox={format!("0 0 {w} {h}")} role="img" aria-label={p.aria_label.clone()} class="ui-chart-svg">
                { for y_ticks.iter().map(|t| html! {
                    <g key={format!("y{t}")}>
                        <line class="ui-chart-grid" x1={ml.to_string()} x2={(w - mr).to_string()} y1={sy(*t).to_string()} y2={sy(*t).to_string()} />
                        <text class="ui-chart-tick" x={(ml - 8.0).to_string()} y={(sy(*t) + 4.0).to_string()} text-anchor="end">{fmt_y(*t)}</text>
                    </g>
                }) }
                { for x_ticks.iter().map(|t| html! {
                    <text key={format!("x{t}")} class="ui-chart-tick" x={sx(*t).to_string()} y={(h - mb + 18.0).to_string()} text-anchor="middle">{fmt_x(*t)}</text>
                }) }
                <line class="ui-chart-axis" x1={ml.to_string()} x2={(w - mr).to_string()} y1={(h - mb).to_string()} y2={(h - mb).to_string()} />
                { for p.series.iter().enumerate().map(|(i, s)| {
                    let c = color(i, s);
                    if let Some(t) = s.threshold {
                        html! { <line key={i} x1={ml.to_string()} x2={(w - mr).to_string()} y1={sy(t).to_string()} y2={sy(t).to_string()}
                                      stroke={c} stroke-width="2" stroke-dasharray="6 4" /> }
                    } else {
                        let pts = s.data.iter().map(|(x, y)| format!("{:.1},{:.1}", sx(*x), sy(*y))).collect::<Vec<_>>().join(" ");
                        html! {
                            <g key={i}>
                                <polyline points={pts} fill="none" stroke={c.clone()} stroke-width="2" />
                                { for s.data.iter().map(|(x, y)| html! {
                                    <circle cx={sx(*x).to_string()} cy={sy(*y).to_string()} r="3" fill={c.clone()}>
                                        <title>{format!("{}: {} — {}", s.title, fmt_x(*x), fmt_y(*y))}</title>
                                    </circle>
                                }) }
                            </g>
                        }
                    }
                }) }
                if let Some(t) = &p.x_title {
                    <text class="ui-chart-title" x={((ml + w - mr) / 2.0).to_string()} y={(h - 6.0).to_string()} text-anchor="middle">{t.clone()}</text>
                }
                if let Some(t) = &p.y_title {
                    <text class="ui-chart-title" x="14" y={((mt + h - mb) / 2.0).to_string()} text-anchor="middle"
                          transform={format!("rotate(-90 14 {})", (mt + h - mb) / 2.0)}>{t.clone()}</text>
                }
            </svg>
            <ul class="ui-chart-legend">
                { for p.series.iter().enumerate().map(|(i, s)| html! {
                    <li key={i}><span class="ui-chart-swatch" style={format!("background:{}", color(i, s))} />{s.title.clone()}</li>
                }) }
            </ul>
        </div>
    }
}

#[derive(Clone, PartialEq)]
pub struct PieDatum {
    pub title: AttrValue,
    pub value: f64,
    pub color: Option<AttrValue>,
}

impl PieDatum {
    pub fn new(title: impl Into<AttrValue>, value: f64) -> Self {
        Self {
            title: title.into(),
            value,
            color: None,
        }
    }
    pub fn color(mut self, c: impl Into<AttrValue>) -> Self {
        self.color = Some(c.into());
        self
    }
}

#[derive(Properties, PartialEq)]
pub struct PieChartProps {
    pub data: Vec<PieDatum>,
    /// "pie" (default) | "donut"
    #[prop_or(AttrValue::Static("pie"))]
    pub variant: AttrValue,
    /// "small" | "medium" (default) | "large"
    #[prop_or(AttrValue::Static("medium"))]
    pub size: AttrValue,
    #[prop_or_default]
    pub aria_label: Option<AttrValue>,
    #[prop_or_default]
    pub aria_description: Option<AttrValue>,
    /// Legend suffix per segment, e.g. "12 rules, 40%".
    #[prop_or_default]
    pub segment_description: Option<Callback<(PieDatum, f64), String>>,
    /// Centre label for donuts.
    #[prop_or_default]
    pub inner_metric_value: Option<AttrValue>,
    #[prop_or_default]
    pub empty: Html,
    #[prop_or_default]
    pub testid: Option<AttrValue>,
}

#[function_component]
pub fn PieChart(p: &PieChartProps) -> Html {
    let total: f64 = p.data.iter().map(|d| d.value.max(0.0)).sum();
    if total <= 0.0 {
        return html! { <div class="ui-chart ui-chart-empty" data-testid={p.testid.clone()}>{p.empty.clone()}</div> };
    }
    let px = match p.size.as_str() {
        "small" => 160.0,
        "large" => 320.0,
        _ => 240.0,
    };
    let r = 100.0_f64;
    let inner = if p.variant == "donut" { 60.0 } else { 0.0 };
    let mut angle = -std::f64::consts::FRAC_PI_2;
    let color = |i: usize, d: &PieDatum| {
        d.color
            .clone()
            .unwrap_or(AttrValue::Static(CHART_PALETTE[i % CHART_PALETTE.len()]))
    };
    let mut segments = Vec::new();
    for (i, d) in p.data.iter().enumerate() {
        let frac = d.value.max(0.0) / total;
        if frac <= 0.0 {
            continue;
        }
        let a0 = angle;
        let a1 = angle + frac * std::f64::consts::TAU;
        angle = a1;
        let c = color(i, d);
        let title = format!("{}: {}", d.title, nice(d.value));
        if frac >= 0.9999 {
            segments.push(html! { <circle key={i} cx="0" cy="0" r={r.to_string()} fill={c}><title>{title}</title></circle> });
            continue;
        }
        let large = i32::from(a1 - a0 > std::f64::consts::PI);
        let (x0, y0, x1, y1) = (r * a0.cos(), r * a0.sin(), r * a1.cos(), r * a1.sin());
        let path = if inner > 0.0 {
            let (ix0, iy0, ix1, iy1) = (
                inner * a0.cos(),
                inner * a0.sin(),
                inner * a1.cos(),
                inner * a1.sin(),
            );
            format!("M{x0:.2} {y0:.2}A{r} {r} 0 {large} 1 {x1:.2} {y1:.2}L{ix1:.2} {iy1:.2}A{inner} {inner} 0 {large} 0 {ix0:.2} {iy0:.2}Z")
        } else {
            format!("M0 0L{x0:.2} {y0:.2}A{r} {r} 0 {large} 1 {x1:.2} {y1:.2}Z")
        };
        segments.push(html! { <path key={i} d={path} fill={c}><title>{title}</title></path> });
    }
    html! {
        <div class="ui-chart ui-chart-pie" data-testid={p.testid.clone()}>
            <svg viewBox="-104 -104 208 208" width={px.to_string()} height={px.to_string()} role="img"
                 aria-label={p.aria_label.clone()}>
                if let Some(d) = &p.aria_description { <desc>{d.clone()}</desc> }
                { for segments }
                if inner > 0.0 {
                    <circle cx="0" cy="0" r={inner.to_string()} class="ui-chart-hole" />
                    if let Some(v) = &p.inner_metric_value {
                        <text class="ui-chart-metric" x="0" y="8" text-anchor="middle">{v.clone()}</text>
                    }
                }
            </svg>
            <ul class="ui-chart-legend">
                { for p.data.iter().enumerate().map(|(i, d)| {
                    let extra = p.segment_description.as_ref().map(|f| f.emit((d.clone(), total)));
                    html! {
                        <li key={i}>
                            <span class="ui-chart-swatch" style={format!("background:{}", color(i, d))} />
                            {d.title.clone()}
                            if let Some(e) = extra { <span class="ui-chart-legend-extra">{" — "}{e}</span> }
                        </li>
                    }
                }) }
            </ul>
        </div>
    }
}
