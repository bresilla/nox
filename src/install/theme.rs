//! Color palette and styling helpers for the installer TUI. One place to tune
//! the look. Palette is Catppuccin-Mocha-flavoured, on the terminal's own
//! background (matches the `nastty` tool's look).

use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, BorderType, Borders, Cell, Padding};

// ── palette ─────────────────────────────────────────────────────

pub const TEXT: Color = Color::Rgb(0xcd, 0xd6, 0xf4);
pub const SUBTEXT: Color = Color::Rgb(0xa6, 0xad, 0xc8);
pub const MUTED: Color = Color::Rgb(0x6c, 0x70, 0x86);
pub const SURFACE: Color = Color::Rgb(0x31, 0x32, 0x44);
pub const SURFACE_LO: Color = Color::Rgb(0x24, 0x25, 0x34);

pub const ACCENT: Color = Color::Indexed(1);
pub const MAUVE: Color = Color::Indexed(5);
pub const GREEN: Color = Color::Rgb(0xa6, 0xe3, 0xa1);
pub const RED: Color = Color::Rgb(0xf3, 0x8b, 0xa8);
pub const YELLOW: Color = Color::Rgb(0xf9, 0xe2, 0xaf);
pub const PEACH: Color = Color::Rgb(0xfa, 0xb3, 0x87);
pub const SKY: Color = Color::Rgb(0x89, 0xdc, 0xeb);
#[allow(dead_code)]
pub const BLUE: Color = Color::Rgb(0x89, 0xb4, 0xfa);

// ── styles ──────────────────────────────────────────────────────

pub fn text() -> Style {
    Style::default().fg(TEXT)
}

pub fn dim() -> Style {
    Style::default().fg(MUTED)
}

pub fn subtle() -> Style {
    Style::default().fg(SUBTEXT)
}

#[allow(dead_code)]
pub fn label() -> Style {
    Style::default().fg(ACCENT)
}

pub fn title() -> Style {
    Style::default().fg(MAUVE).add_modifier(Modifier::BOLD)
}

#[allow(dead_code)]
pub fn table_header() -> Style {
    Style::default()
        .fg(MAUVE)
        .add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
}

/// Whole-card selection: a background tint over every line of the row,
/// leaving each span's own foreground color intact.
pub fn selected_row() -> Style {
    Style::default().bg(SURFACE)
}

// ── blocks ──────────────────────────────────────────────────────

/// Bare rounded panel with no title.
pub fn panel_bare() -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(SURFACE))
        .padding(Padding::horizontal(1))
}

/// Standard rounded panel with a styled title. The title is copied into an
/// owned span, so the block is `'static` regardless of the input's lifetime.
pub fn panel(title: &str) -> Block<'static> {
    panel_bare().title(Span::styled(format!(" {title} "), self::title()))
}

// ── badges ──────────────────────────────────────────────────────

/// Colored status dot + word, e.g. "● enabled".
#[allow(dead_code)]
pub fn badge<'a>(on: bool, on_word: &'a str, off_word: &'a str) -> Span<'a> {
    if on {
        Span::styled(format!("● {on_word}"), Style::default().fg(GREEN))
    } else {
        Span::styled(format!("○ {off_word}"), Style::default().fg(MUTED))
    }
}

/// Key-hint chip for the footer: highlighted key + dim label. The key text is
/// plain black on the accent — bold turns "bright" grey in some terminals and
/// washes out against the background color.
pub fn chip<'a>(key: &'a str, label: &'a str) -> Vec<Span<'a>> {
    vec![
        Span::styled(
            format!(" {key} "),
            Style::default().fg(Color::Black).bg(ACCENT),
        ),
        Span::styled(format!(" {label}  "), dim()),
    ]
}

// ── two-line card cells ─────────────────────────────────────────

/// A cell with a primary line and a dim secondary line underneath. Both lines
/// get a leading space so card content never touches the selection edge.
/// Accepts spans or whole lines for either row.
pub fn cell2<'a>(primary: impl Into<Line<'a>>, secondary: impl Into<Line<'a>>) -> Cell<'a> {
    let mut top = primary.into();
    top.spans.insert(0, Span::raw(" "));
    let mut bottom = secondary.into();
    bottom.spans.insert(0, Span::raw(" "));
    Cell::from(Text::from(vec![top, bottom]))
}

/// A single-line cell, vertically padded to match `cell2` rows.
pub fn cell1<'a>(content: Span<'a>) -> Cell<'a> {
    Cell::from(Text::from(vec![Line::from(vec![Span::raw(" "), content])]))
}

pub fn primary(s: impl Into<String>) -> Span<'static> {
    Span::styled(s.into(), text().add_modifier(Modifier::BOLD))
}

#[allow(dead_code)]
pub fn secondary(s: impl Into<String>) -> Span<'static> {
    Span::styled(s.into(), dim())
}
