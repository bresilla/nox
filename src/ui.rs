use std::io;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph};
use ratatui::Terminal;

use crate::Result;

pub fn select(title: &str, items: &[&str]) -> Result<String> {
    if items.is_empty() {
        return Err("nothing to select".to_string());
    }
    if !std::io::IsTerminal::is_terminal(&io::stdin()) {
        return Err("interactive selector requires a terminal".to_string());
    }

    let mut terminal = SelectorTerminal::enter()?;
    let result = run_selector(&mut terminal.terminal, title, items);
    terminal.leave()?;
    result
}

struct SelectorTerminal {
    terminal: Terminal<CrosstermBackend<io::Stdout>>,
    left: bool,
}

impl SelectorTerminal {
    fn enter() -> Result<Self> {
        enable_raw_mode().map_err(|err| format!("failed to enable raw mode: {err}"))?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)
            .map_err(|err| format!("failed to enter alternate screen: {err}"))?;
        let terminal = Terminal::new(CrosstermBackend::new(stdout))
            .map_err(|err| format!("failed to create terminal: {err}"))?;
        Ok(Self {
            terminal,
            left: false,
        })
    }

    fn leave(&mut self) -> Result<()> {
        if self.left {
            return Ok(());
        }
        disable_raw_mode().map_err(|err| format!("failed to disable raw mode: {err}"))?;
        execute!(self.terminal.backend_mut(), LeaveAlternateScreen)
            .map_err(|err| format!("failed to leave alternate screen: {err}"))?;
        self.terminal
            .show_cursor()
            .map_err(|err| format!("failed to show cursor: {err}"))?;
        self.left = true;
        Ok(())
    }
}

impl Drop for SelectorTerminal {
    fn drop(&mut self) {
        if !self.left {
            let _ = disable_raw_mode();
            let _ = execute!(self.terminal.backend_mut(), LeaveAlternateScreen);
            let _ = self.terminal.show_cursor();
        }
    }
}

fn run_selector(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    title: &str,
    items: &[&str],
) -> Result<String> {
    let mut state = SelectorState::new(items);

    loop {
        terminal
            .draw(|frame| {
                let area = frame.area();
                frame.render_widget(Clear, area);
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Length(3),
                        Constraint::Min(3),
                        Constraint::Length(1),
                    ])
                    .split(area);

                let input = Paragraph::new(Line::from(vec![
                    Span::styled(format!("{title}  "), Style::default().fg(Color::Cyan)),
                    Span::raw("/"),
                    Span::raw(&state.filter),
                ]))
                .block(Block::default().borders(Borders::ALL));
                frame.render_widget(input, chunks[0]);

                let visible = state.visible_items(items);
                let list_items: Vec<ListItem> = visible
                    .iter()
                    .map(|(_, item)| ListItem::new(Line::from((*item).to_string())))
                    .collect();
                let list = List::new(list_items)
                    .block(Block::default().borders(Borders::ALL))
                    .highlight_style(
                        Style::default()
                            .fg(Color::Black)
                            .bg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    )
                    .highlight_symbol("› ");
                let mut list_state = ListState::default();
                if !visible.is_empty() {
                    list_state.select(Some(state.selected.min(visible.len() - 1)));
                }
                frame.render_stateful_widget(list, chunks[1], &mut list_state);

                let help = Paragraph::new("up/down j/k move  / filter  enter select  esc cancel");
                frame.render_widget(help, chunks[2]);
            })
            .map_err(|err| format!("failed to draw selector: {err}"))?;

        if !event::poll(Duration::from_millis(250))
            .map_err(|err| format!("failed to poll terminal input: {err}"))?
        {
            continue;
        }

        let Event::Key(key) =
            event::read().map_err(|err| format!("failed to read terminal input: {err}"))?
        else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }

        match key.code {
            KeyCode::Esc => {
                if state.filter.is_empty() {
                    return Err("cancelled".to_string());
                }
                state.filter.clear();
                state.selected = 0;
            }
            KeyCode::Enter => {
                let visible = state.visible_items(items);
                let Some((_, item)) = visible.get(state.selected) else {
                    continue;
                };
                return Ok((*item).to_string());
            }
            KeyCode::Up | KeyCode::Char('k') => state.previous(items),
            KeyCode::Down | KeyCode::Char('j') => state.next(items),
            KeyCode::Backspace => {
                state.filter.pop();
                state.selected = 0;
            }
            KeyCode::Char('/') => {
                state.filter.clear();
                state.selected = 0;
            }
            KeyCode::Char(ch) => {
                state.filter.push(ch);
                state.selected = 0;
            }
            _ => {}
        }
    }
}

#[derive(Debug, Clone)]
struct SelectorState {
    filter: String,
    selected: usize,
}

impl SelectorState {
    fn new(_items: &[&str]) -> Self {
        Self {
            filter: String::new(),
            selected: 0,
        }
    }

    fn visible_items<'a>(&self, items: &'a [&'a str]) -> Vec<(usize, &'a str)> {
        let filter = self.filter.to_lowercase();
        items
            .iter()
            .copied()
            .enumerate()
            .filter(|(_, item)| filter.is_empty() || item.to_lowercase().contains(&filter))
            .collect()
    }

    fn previous(&mut self, items: &[&str]) {
        let len = self.visible_items(items).len();
        if len == 0 {
            self.selected = 0;
        } else if self.selected == 0 {
            self.selected = len - 1;
        } else {
            self.selected -= 1;
        }
    }

    fn next(&mut self, items: &[&str]) {
        let len = self.visible_items(items).len();
        if len == 0 {
            self.selected = 0;
        } else {
            self.selected = (self.selected + 1) % len;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SelectorState;

    #[test]
    fn filter_keeps_matching_items() {
        let items = ["package", "service", "profile"];
        let mut state = SelectorState::new(&items);
        state.filter = "pro".to_string();
        let visible = state.visible_items(&items);
        assert_eq!(visible, vec![(2, "profile")]);
    }

    #[test]
    fn next_wraps_visible_items() {
        let items = ["package", "service"];
        let mut state = SelectorState::new(&items);
        state.next(&items);
        assert_eq!(state.selected, 1);
        state.next(&items);
        assert_eq!(state.selected, 0);
    }
}
