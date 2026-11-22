//! Minimal text-only PDF writer used by the two report generators.
//!
//! Write-only and text-only: no parsing, encryption or signing. Any future
//! PDF signing must go through crypto review and use the signing envelope
//! with an algorithm identifier (#32).
//!
//! Emits A-size pages containing positioned runs of text in the three
//! built-in Helvetica faces (WinAnsiEncoding). No images, no embedded
//! fonts, no compression. All user-controlled text goes through
//! `pdf_writer::Str`, which escapes string delimiters.

use pdf_writer::{Content, Finish, Name, Pdf, Rect, Ref, Str, TextStr};

/// Millimetres to PDF points.
const MM: f32 = 72.0 / 25.4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Face {
    Regular,
    Bold,
    Italic,
}

impl Face {
    fn index(self) -> usize {
        match self {
            Face::Regular => 0,
            Face::Bold => 1,
            Face::Italic => 2,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Run {
    pub text: String,
    pub size_pt: f32,
    pub x_mm: f32,
    pub y_mm: f32,
    pub face: Face,
}

pub(crate) struct TextDoc {
    title: String,
    w_mm: f32,
    h_mm: f32,
    pages: Vec<Vec<Run>>,
}

impl TextDoc {
    pub fn new(title: impl Into<String>, w_mm: f32, h_mm: f32) -> Self {
        Self {
            title: title.into(),
            w_mm,
            h_mm,
            pages: vec![Vec::new()],
        }
    }

    pub fn add_page(&mut self) {
        self.pages.push(Vec::new());
    }

    pub fn text(&mut self, s: impl AsRef<str>, size: f32, x_mm: f32, y_mm: f32, face: Face) {
        if let Some(page) = self.pages.last_mut() {
            page.push(Run {
                text: s.as_ref().to_string(),
                size_pt: size,
                x_mm,
                y_mm,
                face,
            });
        }
    }

    #[cfg(test)]
    pub fn page_count(&self) -> usize {
        self.pages.len()
    }

    #[cfg(test)]
    pub fn page_runs(&self, page: usize) -> &[Run] {
        &self.pages[page]
    }

    pub fn finish(self) -> Vec<u8> {
        let catalog_id = Ref::new(1);
        let tree_id = Ref::new(2);
        let info_id = Ref::new(3);
        let font_ids = [Ref::new(4), Ref::new(5), Ref::new(6)];
        let font_names: [&[u8]; 3] = [b"F0", b"F1", b"F2"];
        let base_fonts: [&[u8]; 3] = [b"Helvetica", b"Helvetica-Bold", b"Helvetica-Oblique"];

        let mut pdf = Pdf::new();
        pdf.catalog(catalog_id).pages(tree_id);
        pdf.document_info(info_id).title(TextStr(&self.title));

        let page_ids: Vec<(Ref, Ref)> = (0..self.pages.len())
            .map(|i| {
                let base = 7 + 2 * i32::try_from(i).expect("page count fits i32");
                (Ref::new(base), Ref::new(base + 1))
            })
            .collect();

        pdf.pages(tree_id)
            .kids(page_ids.iter().map(|(p, _)| *p))
            .count(i32::try_from(self.pages.len()).expect("page count fits i32"));

        for (id, base) in font_ids.iter().zip(base_fonts) {
            pdf.type1_font(*id)
                .base_font(Name(base))
                .encoding_predefined(Name(b"WinAnsiEncoding"));
        }

        for (runs, (page_id, content_id)) in self.pages.iter().zip(&page_ids) {
            let mut page = pdf.page(*page_id);
            page.media_box(Rect::new(0.0, 0.0, self.w_mm * MM, self.h_mm * MM));
            page.parent(tree_id);
            page.contents(*content_id);
            let mut resources = page.resources();
            let mut fonts = resources.fonts();
            for (name, id) in font_names.iter().zip(font_ids) {
                fonts.pair(Name(name), id);
            }
            fonts.finish();
            resources.finish();
            page.finish();

            let mut content = Content::new();
            for run in runs {
                content.begin_text();
                content.set_font(Name(font_names[run.face.index()]), run.size_pt);
                content.next_line(run.x_mm * MM, run.y_mm * MM);
                content.show(Str(&win_ansi(&run.text)));
                content.end_text();
            }
            pdf.stream(*content_id, &content.finish());
        }

        pdf.finish()
    }
}

/// Encode `s` as WinAnsi (cp1252) bytes. Control characters are dropped;
/// other unmappable characters become `?`.
fn win_ansi(s: &str) -> Vec<u8> {
    s.chars()
        .filter_map(|c| match c as u32 {
            0x20..=0x7E | 0xA0..=0xFF => Some(c as u32 as u8),
            _ => match c {
                '€' => Some(0x80),
                '‚' => Some(0x82),
                'ƒ' => Some(0x83),
                '„' => Some(0x84),
                '…' => Some(0x85),
                '†' => Some(0x86),
                '‡' => Some(0x87),
                'ˆ' => Some(0x88),
                '‰' => Some(0x89),
                'Š' => Some(0x8A),
                '‹' => Some(0x8B),
                'Œ' => Some(0x8C),
                'Ž' => Some(0x8E),
                '‘' => Some(0x91),
                '’' => Some(0x92),
                '“' => Some(0x93),
                '”' => Some(0x94),
                '•' => Some(0x95),
                '–' => Some(0x96),
                '—' => Some(0x97),
                '˜' => Some(0x98),
                '™' => Some(0x99),
                'š' => Some(0x9A),
                '›' => Some(0x9B),
                'œ' => Some(0x9C),
                'ž' => Some(0x9E),
                'Ÿ' => Some(0x9F),
                _ if c.is_control() => None,
                _ => Some(b'?'),
            },
        })
        .collect()
}

/// Test helper: the `Td` operator `finish()` emits for a run at the given
/// millimetre position. pdf-writer prints integral f32 values without a
/// fraction and everything else as the shortest round-trip decimal, which
/// matches `Display` for these magnitudes.
#[cfg(test)]
pub(crate) fn td_operator(x_mm: f32, y_mm: f32) -> String {
    fn num(v: f32) -> String {
        if (v as i32) as f32 == v {
            (v as i32).to_string()
        } else {
            v.to_string()
        }
    }
    format!("{} {} Td", num(x_mm * MM), num(y_mm * MM))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
        hay.windows(needle.len()).position(|w| w == needle)
    }

    fn count(hay: &[u8], needle: &[u8]) -> usize {
        hay.windows(needle.len()).filter(|w| *w == needle).count()
    }

    #[test]
    fn win_ansi_maps_and_drops() {
        assert_eq!(win_ansi("Abc 1"), b"Abc 1");
        assert_eq!(win_ansi("—·…é"), vec![0x97, 0xB7, 0x85, 0xE9]);
        assert_eq!(win_ansi("a😀b漢c"), b"a?b?c");
        assert_eq!(win_ansi("a\tb\nc"), b"abc");
    }

    const SECOND_Y: f32 = 277.0 - 4.8;
    const BOLD_X: f32 = 30.0;
    const BOLD_Y: f32 = 250.5;

    fn sample() -> Vec<u8> {
        let mut d = TextDoc::new("T", 210.0, 297.0);
        d.text("Hello", 10.0, 18.0, 277.0, Face::Regular);
        d.text("Second", 10.0, 18.0, SECOND_Y, Face::Regular);
        d.add_page();
        d.text("Bold", 10.0, BOLD_X, BOLD_Y, Face::Bold);
        d.add_page();
        d.text("Ital", 10.0, 18.0, 277.0, Face::Italic);
        d.finish()
    }

    #[test]
    fn finish_structure() {
        let b = sample();
        assert!(b.starts_with(b"%PDF-"));
        let s = String::from_utf8_lossy(&b).to_string();
        assert!(s.trim_end().ends_with("%%EOF"));

        let sx = s.rfind("startxref").expect("startxref");
        let off: usize = s[sx + "startxref".len()..]
            .split_whitespace()
            .next()
            .and_then(|n| n.parse().ok())
            .expect("offset");
        assert!(b[off..].starts_with(b"xref"));

        assert!(find(&b, b"/Count 3").is_some());
        assert_eq!(count(&b, b"/Type /Page\n"), 3);
        for f in ["/Helvetica", "/Helvetica-Bold", "/Helvetica-Oblique"] {
            assert!(s.contains(&format!("/BaseFont {f}")), "{f}");
        }
        assert!(s.contains("/Encoding /WinAnsiEncoding"));
        assert!(s.contains("(Hello) Tj"));
        assert!(s.contains("51.023624 785.1969 Td"));
        assert_eq!(td_operator(18.0, 277.0), "51.023624 785.1969 Td");
        let second = td_operator(18.0, SECOND_Y);
        assert!(s.contains(&format!("{second}\n(Second) Tj")), "{s}");
        assert!(s.contains(&td_operator(BOLD_X, BOLD_Y)));
        assert_eq!(count(&b, b" Td"), 4);
    }

    #[test]
    fn delimiters_are_escaped() {
        let mut d = TextDoc::new("T", 210.0, 297.0);
        d.text("a) Tj ET (b\\", 10.0, 10.0, 10.0, Face::Regular);
        let b = d.finish();
        assert!(find(&b, b"a) Tj ET (b\\)").is_none());
        let s = String::from_utf8_lossy(&b);
        assert!(s.contains("a\\) Tj ET \\(b\\\\"), "{s}");
    }

    #[test]
    fn em_dash_is_encoded() {
        let mut d = TextDoc::new("T", 210.0, 297.0);
        d.text("a—b", 10.0, 10.0, 10.0, Face::Regular);
        let b = d.finish();
        assert!(find(&b, b"<619762> Tj").is_some());
    }
}
