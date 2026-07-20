//! Guided installer TUI. One question per screen, walked linearly with a
//! prev/current/next breadcrumb — see [`crate::install::flow`] for the step
//! sequence and state transitions. Rendering here is pure over the flow, and
//! the live install progress screen is reused from [`crate::install::progress`].

use std::io;
use std::path::Path;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Margin, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{
    Block, BorderType, Borders, Clear, Gauge, Paragraph, Row, Table, TableState, Wrap,
};
use ratatui::{Frame, Terminal};
use tui_globe::{project_point, Camera, Globe, MapData};
use tui_popup::Popup;

use crate::install::flow::{Flow, Step, StepKind};
use crate::install::preflight::PreflightStatus;
use crate::install::state::InstallState;
use crate::install::theme;
use crate::Result;

pub fn run(repo: &Path, execute: bool) -> Result<u8> {
    // Resume previous answers: a LIS document from an earlier run restores
    // the wizard state (hostname, storage layout, users, …).
    let mut state = InstallState::draft();
    let mut resumed = false;
    let draft = crate::install::lis::document_path(repo);
    if draft.is_file() {
        if let Ok(doc) = crate::install::lis::read(&draft) {
            crate::install::lis::apply_to_state(&doc, &mut state);
            resumed = true;
        }
    }
    let mut flow = Flow::new(state);
    if resumed {
        flow.status = "resumed previous answers from generated/system.lis.json".to_string();
    }
    let mut terminal = PreviewTerminal::enter()?;

    loop {
        flow.poll_link();
        flow.poll_preflight();
        terminal
            .terminal
            .draw(|frame| render_flow(frame, &flow))
            .map_err(|err| format!("failed to draw installer: {err}"))?;

        if !event::poll(Duration::from_millis(200))
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

        handle_key(&mut flow, key, repo);

        if flow.quit {
            terminal.leave()?;
            return Ok(0);
        }
        if flow.done {
            if execute {
                if let Err(err) = flow.commit_password() {
                    flow.status = format!("password error: {err}");
                    flow.done = false;
                    continue;
                }
                let code = run_install_screen(&mut terminal, repo, &flow.state)?;
                terminal.leave()?;
                return Ok(code);
            }
            terminal.leave()?;
            crate::install::exec::prepare_generated(repo, &flow.state)?;
            return Ok(0);
        }
    }
}

fn handle_key(flow: &mut Flow, key: KeyEvent, repo: &Path) {
    if key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('c')) {
        flow.quit = true;
        return;
    }

    // The `?` shortcuts panel swallows everything until dismissed.
    if flow.help_open {
        match key.code {
            KeyCode::Esc | KeyCode::Enter | KeyCode::Char('?') | KeyCode::Char('q') => {
                flow.help_open = false;
            }
            _ => {}
        }
        return;
    }

    // Subiquity-style footer buttons: Tab moves focus onto [ next › ] /
    // [ ‹ prev ]; Enter activates the focused button. Any other page key
    // returns focus to the page and is handled normally.
    if !flow.capturing_text() && !flow.storage_popup {
        match key.code {
            KeyCode::Tab => {
                flow.footer_cycle(true);
                return;
            }
            KeyCode::BackTab => {
                flow.footer_cycle(false);
                return;
            }
            _ => {}
        }
        if let Some(focus) = flow.footer_focus {
            use crate::install::flow::FooterFocus;
            match key.code {
                KeyCode::Enter => {
                    match focus {
                        FooterFocus::Prev if flow.can_prev() => flow.back(),
                        FooterFocus::Next if flow.can_next() => flow.advance(),
                        _ => {}
                    }
                    flow.footer_focus = None;
                    return;
                }
                KeyCode::Left | KeyCode::Right => {
                    flow.footer_focus = Some(match focus {
                        FooterFocus::Prev => FooterFocus::Next,
                        FooterFocus::Next => FooterFocus::Prev,
                    });
                    return;
                }
                KeyCode::Esc => {
                    flow.footer_focus = None;
                    return;
                }
                // Anything else: focus falls back to the page and the key is
                // handled as usual below.
                _ => flow.footer_focus = None,
            }
        }
    }

    // ? opens the shortcut panel (kept away from text-capturing editors).
    if !flow.capturing_text() && key.code == KeyCode::Char('?') {
        flow.help_open = true;
        return;
    }

    let kind = flow.current().kind();

    // Multi-select disk picker: space toggles, ↑↓ navigate.
    if kind == StepKind::DiskSelect {
        let disks = flow.installable_disks();
        let last = disks.len().saturating_sub(1);
        match key.code {
            KeyCode::Esc => flow.back(),
            KeyCode::Enter => flow.advance(),
            KeyCode::Up | KeyCode::Char('k') => flow.cursor = flow.cursor.saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j') => flow.cursor = (flow.cursor + 1).min(last),
            KeyCode::Char(' ') => {
                if let Some(disk) = disks.get(flow.cursor) {
                    let path = disk.path.clone();
                    flow.disk_toggle(&path);
                }
            }
            KeyCode::Char('q') => flow.quit = true,
            _ => {}
        }
        return;
    }

    // Extra-disks: set a mount for each remaining disk, or skip.
    if kind == StepKind::ExtraDisks {
        if flow.extra_edit.is_some() {
            match key.code {
                KeyCode::Enter => flow.extra_apply_edit(),
                KeyCode::Esc => flow.extra_cancel_edit(),
                KeyCode::Backspace => flow.extra_edit_backspace(),
                KeyCode::Char(ch) => flow.extra_edit_insert(ch),
                _ => {}
            }
            return;
        }
        match key.code {
            KeyCode::Esc => flow.back(),
            KeyCode::Enter => flow.advance(),
            KeyCode::Up | KeyCode::Char('k') => flow.extra_sel_prev(),
            KeyCode::Down | KeyCode::Char('j') => flow.extra_sel_next(),
            KeyCode::Char('m') => flow.extra_begin_edit(),
            KeyCode::Char('s') | KeyCode::Char('d') => flow.extra_clear(),
            KeyCode::Char('q') => flow.quit = true,
            _ => {}
        }
        return;
    }

    // Multi-user editor: overview page + the modal users editor window.
    if kind == StepKind::Users {
        if !flow.users_popup {
            match key.code {
                KeyCode::Esc => flow.back(),
                KeyCode::Enter => flow.advance(),
                KeyCode::Char('e') => flow.users_popup_open(),
                KeyCode::Char('q') => flow.quit = true,
                _ => {}
            }
            return;
        }
        // Live field buffer: the cursor sits IN the field — typing edits it,
        // ↑↓/Enter save and move, Esc saves and climbs back to the list.
        if flow.user_field_edit.is_some() {
            match key.code {
                KeyCode::Enter | KeyCode::Down => flow.user_row_next(),
                KeyCode::Up => flow.user_row_prev(),
                KeyCode::Esc => flow.users_back(),
                KeyCode::Tab => flow.help_open = true,
                KeyCode::Backspace => flow.user_field_backspace(),
                KeyCode::Char(ch) => flow.user_field_insert(ch),
                _ => {}
            }
            return;
        }
        match flow.user_stage {
            crate::install::flow::UserStage::List => match key.code {
                KeyCode::Esc => flow.users_back(),
                KeyCode::Enter | KeyCode::Char('e') => flow.users_enter(),
                KeyCode::Tab => flow.help_open = true,
                KeyCode::Up | KeyCode::Char('k') => flow.users_sel_prev(),
                KeyCode::Down | KeyCode::Char('j') => flow.users_sel_next(),
                KeyCode::Char('a') => flow.users_add(),
                KeyCode::Char('d') | KeyCode::Char('x') => flow.users_delete(),
                KeyCode::Char('f') => flow.users_finish(),
                KeyCode::Char('q') => flow.quit = true,
                _ => {}
            },
            // Only the group rows land here — the field rows always hold a
            // live buffer (handled above).
            crate::install::flow::UserStage::Detail => match key.code {
                KeyCode::Esc => flow.users_back(),
                KeyCode::Enter | KeyCode::Char('e') | KeyCode::Char(' ') => {
                    flow.user_edit_row()
                }
                KeyCode::Tab => flow.help_open = true,
                KeyCode::Up | KeyCode::Char('k') => flow.user_row_prev(),
                KeyCode::Down | KeyCode::Char('j') => flow.user_row_next(),
                KeyCode::Char('q') => flow.quit = true,
                _ => {}
            },
        }
        return;
    }

    // The disk stage is a two-panel pools|volumes editor with direct resizing.
    if let StepKind::Editor(crate::install::flow::Editor::Disks) = kind {
        // Editor closed → a normal wizard page; e opens the modal editor.
        if !flow.storage_popup {
            match key.code {
                KeyCode::Esc => flow.back(),
                KeyCode::Enter => flow.advance(),
                KeyCode::Char('e') => flow.storage_popup_open(),
                KeyCode::Char('q') => flow.quit = true,
                _ => {}
            }
            return;
        }
        // The universal `e` edit popup captures everything while open.
        if flow.edit_popup.is_some() {
            match key.code {
                KeyCode::Enter => flow.edit_apply(),
                KeyCode::Esc => flow.edit_cancel(),
                KeyCode::Up | KeyCode::BackTab => flow.edit_field_prev(),
                KeyCode::Down | KeyCode::Tab => flow.edit_field_next(),
                KeyCode::Left => flow.edit_cycle(-1),
                KeyCode::Right => flow.edit_cycle(1),
                KeyCode::Backspace => flow.edit_backspace(),
                KeyCode::Char(ch) => flow.edit_input(ch),
                _ => {}
            }
            return;
        }
        // Live pool-field buffer: the cursor sits IN the field — typing edits,
        // ↑↓/Enter save and move, Esc saves and climbs a tier.
        if flow.pool_edit.is_some() {
            match key.code {
                KeyCode::Enter | KeyCode::Down => flow.part_zone_down(),
                KeyCode::Up => flow.part_zone_up(),
                KeyCode::Esc => flow.storage_back(),
                KeyCode::Tab => flow.help_open = true,
                KeyCode::Backspace => flow.pool_edit_backspace(),
                KeyCode::Char(ch) => flow.pool_edit_insert(ch),
                _ => {}
            }
            return;
        }
        // Live partition-detail buffer: same pattern as the pool fields.
        if flow.detail_edit.is_some() {
            match key.code {
                KeyCode::Enter | KeyCode::Down => flow.detail_sel_next(),
                KeyCode::Up => flow.detail_sel_prev(),
                KeyCode::Esc => flow.storage_back(),
                KeyCode::Tab => flow.help_open = true,
                KeyCode::Backspace => flow.detail_edit_backspace(),
                KeyCode::Char(ch) => flow.detail_edit_insert(ch),
                _ => {}
            }
            return;
        }
        // Inline text edit of a subvolume name/mount (subvolume tier).
        if flow.subvol_edit.is_some() {
            match key.code {
                KeyCode::Enter => {
                    if let Err(err) = flow.subvol_apply_edit() {
                        flow.status = err;
                    }
                }
                KeyCode::Esc => flow.subvol_cancel_edit(),
                KeyCode::Backspace => flow.subvol_edit_backspace(),
                KeyCode::Char(ch) => flow.subvol_edit_insert(ch),
                _ => {}
            }
            return;
        }
        // Rename mode captures typing until Enter/Esc.
        if flow.disk_rename.is_some() {
            match key.code {
                KeyCode::Enter => flow.disk_apply_rename(),
                KeyCode::Esc => flow.disk_cancel_rename(),
                KeyCode::Backspace => flow.disk_rename_backspace(),
                KeyCode::Char(ch) => flow.disk_rename_insert(ch),
                _ => {}
            }
            return;
        }
        // Size-typing mode: type an exact GiB number, Enter applies.
        if flow.size_editing() {
            match key.code {
                KeyCode::Enter => flow.size_apply(),
                KeyCode::Esc => flow.size_cancel(),
                KeyCode::Backspace => flow.size_backspace(),
                KeyCode::Char(ch) => flow.size_insert(ch),
                _ => {}
            }
            return;
        }
        use crate::install::flow::{DiskStage, PartField};
        match flow.disk_stage {
            // ── PAGE 1: DISKS — plain checkbox selection ─────────
            DiskStage::Disks => match key.code {
                KeyCode::Esc => flow.storage_back(),
                KeyCode::Enter => flow.storage_forward(),
                KeyCode::Tab => flow.help_open = true,
                KeyCode::Up | KeyCode::Char('k') => flow.disk_sel_prev(),
                KeyCode::Down | KeyCode::Char('j') => flow.disk_sel_next(),
                KeyCode::Char(' ') => flow.disk_row_toggle_selected(),
                KeyCode::Char('e') => flow.storage_forward(),
                KeyCode::Char('b') => flow.storage_back(),
                KeyCode::Char('f') => flow.storage_finish(),
                KeyCode::Char('q') => flow.quit = true,
                _ => {}
            },
            // ── PAGE 2: POOLS — the disk↔pool segment map ────────
            DiskStage::Pools => match key.code {
                KeyCode::Esc => flow.storage_back(),
                KeyCode::Enter => flow.storage_forward(),
                KeyCode::Tab => flow.help_open = true,
                KeyCode::Up | KeyCode::Char('k') => flow.disk_sel_prev(),
                KeyCode::Down | KeyCode::Char('j') => flow.disk_sel_next(),
                KeyCode::Left | KeyCode::Char('h') => flow.seg_prev(),
                KeyCode::Right | KeyCode::Char('l') => flow.seg_next(),
                KeyCode::Char(c) if c.is_ascii_digit() => flow.size_begin(Some(c)),
                KeyCode::Char('+') | KeyCode::Char('=') => flow.slice_resize(8),
                KeyCode::Char('-') | KeyCode::Char('_') => flow.slice_resize(-8),
                KeyCode::PageUp => flow.slice_resize(64),
                KeyCode::PageDown => flow.slice_resize(-64),
                KeyCode::Char('e') => flow.storage_forward(),
                KeyCode::Char('b') => flow.storage_back(),
                KeyCode::Char('a') | KeyCode::Char('n') => flow.pool_from_free(),
                KeyCode::Char('p') => flow.slice_cycle_pool(),
                KeyCode::Char('s') => flow.slice_split(),
                KeyCode::Char('d') | KeyCode::Char('x') => flow.slice_delete(),
                KeyCode::Char('r') => flow.pool_begin_rename(),
                KeyCode::Char('q') => flow.quit = true,
                _ => {}
            },
            // ── PAGE 3: PARTITIONS — the same band UI as the map ─
            DiskStage::Partitions => match key.code {
                KeyCode::Esc => flow.storage_back(),
                KeyCode::Enter => flow.storage_forward(),
                KeyCode::Tab => flow.help_open = true,
                // ↑↓ move between the pool fields on top and the band below.
                KeyCode::Up | KeyCode::Char('k') => flow.part_zone_up(),
                KeyCode::Down | KeyCode::Char('j') => flow.part_zone_down(),
                KeyCode::Left | KeyCode::Char('h') if flow.part_zone == 2 => {
                    flow.disk_sel_prev()
                }
                KeyCode::Right | KeyCode::Char('l') if flow.part_zone == 2 => {
                    flow.disk_sel_next()
                }
                // e: edit the pool field, or enter the selected partition.
                KeyCode::Char('e') if flow.part_zone < 2 => flow.pool_edit_row(),
                KeyCode::Char('e') => flow.storage_forward(),
                KeyCode::Char('b') => flow.storage_back(),
                KeyCode::Char('+') | KeyCode::Char('=') if flow.part_zone == 2 => {
                    flow.disk_resize(8)
                }
                KeyCode::Char('-') | KeyCode::Char('_') if flow.part_zone == 2 => {
                    flow.disk_resize(-8)
                }
                KeyCode::PageUp if flow.part_zone == 2 => flow.disk_resize(64),
                KeyCode::PageDown if flow.part_zone == 2 => flow.disk_resize(-64),
                KeyCode::Char(c) if c.is_ascii_digit() && flow.part_zone == 2 => {
                    flow.size_begin(Some(c))
                }
                KeyCode::Char('*') if flow.part_zone == 2 => flow.fill_toggle(),
                KeyCode::Char('a') => flow.disk_add(),
                KeyCode::Char('s') if flow.part_zone == 2 => flow.part_split(),
                KeyCode::Char('d') | KeyCode::Char('x') if flow.part_zone == 2 => {
                    flow.disk_delete()
                }
                KeyCode::Char('n') | KeyCode::Char('r') if flow.part_zone == 2 => {
                    flow.disk_begin_edit(PartField::Name)
                }
                KeyCode::Char('m') if flow.part_zone == 2 => {
                    flow.disk_begin_edit(PartField::Mount)
                }
                KeyCode::Char('f') if flow.part_zone == 2 => flow.disk_cycle_fs(),
                KeyCode::Char('q') => flow.quit = true,
                _ => {}
            },
            // ── PAGE 4: inside one partition — fields on top, subvols below ─
            // Only non-text rows land here (fs/rest/subvols); the text fields
            // always hold a live buffer, handled above.
            DiskStage::Subvols => match key.code {
                KeyCode::Esc => flow.storage_back(),
                KeyCode::Enter => flow.detail_edit_row(),
                KeyCode::Tab => flow.help_open = true,
                KeyCode::Up | KeyCode::Char('k') => flow.detail_sel_prev(),
                KeyCode::Down | KeyCode::Char('j') => flow.detail_sel_next(),
                KeyCode::Char('e') => flow.detail_edit_row(),
                KeyCode::Char('b') => flow.storage_back(),
                KeyCode::Char('a') => {
                    flow.subvol_add();
                    flow.part_cursor = 6 + flow.subvol_sel;
                }
                KeyCode::Char('d') | KeyCode::Char('x') => {
                    if flow.part_cursor >= 6 {
                        flow.subvol_delete();
                        flow.part_cursor = (6 + flow.subvol_sel).min(
                            flow.detail_row_count().saturating_sub(1),
                        );
                    } else {
                        flow.status =
                            "d deletes subvolume rows — move onto one".to_string();
                    }
                }
                KeyCode::Char('m') => {
                    if flow.part_cursor >= 6 {
                        flow.subvol_begin_edit(crate::install::flow::SubvolField::Mount)
                    }
                }
                KeyCode::Char('q') => flow.quit = true,
                _ => {}
            },
        }
        return;
    }

    // The remaining advanced editors (manual mode) use the generic editor.
    if let StepKind::Editor(editor) = kind {
        let text_field = editor.is_text(flow.field);
        match key.code {
            KeyCode::Esc => flow.back(),
            KeyCode::Enter => flow.advance(),
            KeyCode::Up => flow.item_prev(),
            KeyCode::Down => flow.item_next(),
            KeyCode::Left | KeyCode::BackTab => flow.field_prev(),
            KeyCode::Right | KeyCode::Tab => flow.field_next(),
            KeyCode::Char('n') if key.modifiers.contains(KeyModifiers::CONTROL) => flow.add_item(),
            KeyCode::Char('x') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                flow.remove_item()
            }
            KeyCode::Char(' ') => flow.cycle(),
            KeyCode::Char('+') | KeyCode::Char('=') => flow.adjust(1),
            KeyCode::Char('-') => flow.adjust(-1),
            KeyCode::Char('S') if editor == crate::install::flow::Editor::Volumes => {
                flow.scale_to_fit()
            }
            KeyCode::Backspace if text_field => flow.backspace(),
            KeyCode::Char(ch) if text_field => flow.insert(ch),
            KeyCode::Char('k') => flow.item_prev(),
            KeyCode::Char('j') => flow.item_next(),
            KeyCode::Char('h') => flow.field_prev(),
            KeyCode::Char('l') => flow.field_next(),
            KeyCode::Char('q') => flow.quit = true,
            _ => {}
        }
        return;
    }

    // Review: the secrets chooser (no usable key) floats over the page.
    if kind == StepKind::Review && flow.secrets_popup {
        if flow.secrets_key_edit.is_some() {
            match key.code {
                KeyCode::Enter => flow.secrets_key_apply(repo),
                KeyCode::Esc => flow.secrets_key_cancel(),
                KeyCode::Backspace => flow.secrets_key_backspace(),
                KeyCode::Char(ch) => flow.secrets_key_insert(ch),
                _ => {}
            }
            return;
        }
        match key.code {
            KeyCode::Esc => flow.secrets_popup = false,
            KeyCode::Char('y') => flow.secrets_choose_yubikey(repo),
            KeyCode::Char('k') => flow.secrets_key_begin(),
            KeyCode::Char('s') => flow.secrets_choose_skip(repo),
            KeyCode::Char('q') => flow.quit = true,
            _ => {}
        }
        return;
    }

    let input_step = matches!(
        kind,
        StepKind::Text | StepKind::Password | StepKind::Confirm
    );
    match key.code {
        KeyCode::Esc => {
            if flow.pos == 0 {
                flow.quit = true;
            } else {
                flow.back();
            }
        }
        KeyCode::Enter => flow.advance(),
        KeyCode::Backspace => flow.backspace(),
        KeyCode::Left if kind == StepKind::Text => flow.text_cursor_prev(),
        KeyCode::Right if kind == StepKind::Text => flow.text_cursor_next(),
        KeyCode::Up | KeyCode::Left | KeyCode::BackTab if !input_step => flow.select_prev(),
        KeyCode::Down | KeyCode::Right | KeyCode::Tab if !input_step => flow.select_next(),
        KeyCode::Char('k') if !input_step => flow.select_prev(),
        KeyCode::Char('j') if !input_step => flow.select_next(),
        KeyCode::Char(' ') if kind == StepKind::Review => flow.toggle(repo),
        // Reopen the key/skip chooser at any time on the review page.
        KeyCode::Char('s') if kind == StepKind::Review => flow.secrets_popup = true,
        KeyCode::Char('q') if !input_step => flow.quit = true,
        KeyCode::Char(ch) if input_step => flow.insert(ch),
        _ => {}
    }
}

// ── flow screen ─────────────────────────────────────────────────

fn render_flow(frame: &mut Frame<'_>, flow: &Flow) {
    let area = frame.area();
    frame.render_widget(Clear, area);

    let shell = full_screen(area);
    let scope = flow.state.scope.title();
    let target = match flow.state.scope {
        crate::install::state::InstallScope::Remote => flow.state.remote.clone(),
        crate::install::state::InstallScope::Local => "this machine".to_string(),
    };
    let (link_icon, link_word, link_color) = flow.link_badge();
    let (n, total) = flow.step_number();
    let outer = theme::panel_bare()
        .title(Line::from(vec![
            Span::styled(" ⬢ ", Style::default().fg(theme::ACCENT)),
            Span::styled("nox ", theme::title()),
            Span::styled("installer ", theme::dim()),
        ]))
        .title(
            Line::from(vec![
                Span::styled(
                    format!(" {link_icon} {scope} {target} · "),
                    Style::default().fg(link_color),
                ),
                Span::styled(link_word, theme::dim()),
                Span::styled(format!(" · step {n}/{total} "), theme::dim()),
            ])
            .right_aligned(),
        );
    frame.render_widget(outer, shell);

    let inner = shell.inner(Margin {
        horizontal: 2,
        vertical: 1,
    });
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // breadcrumb
            Constraint::Min(6),    // full-bleed stage
            Constraint::Length(3), // status line + shortcut chips
        ])
        .split(inner);

    render_breadcrumb(frame, rows[0], flow);
    render_stage(frame, rows[1], flow);
    render_flow_footer(frame, rows[2], flow);

    // The storage editor floats over the grayed-out wizard.
    if flow.current() == Step::Storage && flow.storage_popup {
        render_storage_editor_popup(frame, rows[1], flow);
    }
    // The users editor — same chrome, same rules.
    if flow.current().kind() == StepKind::Users && flow.users_popup {
        render_users_editor_popup(frame, rows[1], flow);
    }
    // The secrets chooser (no usable key found at preflight).
    if flow.current().kind() == StepKind::Review && flow.secrets_popup {
        render_secrets_popup(frame, rows[1], flow);
    }

    // The `?` shortcuts panel floats over everything.
    if flow.help_open {
        render_help_overlay(frame, flow);
    }
}

/// The "no usable key" chooser: keep the YubiKey, point at an age key file,
/// or deliberately install without secrets.
fn render_secrets_popup(frame: &mut Frame<'_>, stage: Rect, flow: &Flow) {
    dim_backdrop(frame);
    let width = 62.min(stage.width.saturating_sub(4)).max(30);
    let height = 12.min(stage.height.saturating_sub(2)).max(8);
    let rect = Rect {
        x: stage.x + (stage.width.saturating_sub(width)) / 2,
        y: stage.y + (stage.height.saturating_sub(height)) / 2,
        width,
        height,
    };
    frame.render_widget(Clear, rect);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(theme::ACCENT))
        .title(Span::styled(" secrets ", theme::title()))
        .padding(ratatui::widgets::Padding::new(2, 2, 1, 1));
    let inner = block.inner(rect);
    frame.render_widget(block, rect);

    let key = |k: &'static str| {
        Span::styled(
            format!(" {k} "),
            Style::default().fg(ratatui::style::Color::Black).bg(theme::ACCENT),
        )
    };
    let mut lines = vec![
        Line::from(Span::styled(
            "the encrypted secrets cannot be decrypted here.",
            theme::text(),
        )),
        Line::from(""),
        Line::from(vec![
            key("y"),
            Span::styled("  use the YubiKey (plug it in, start pcscd)", theme::subtle()),
        ]),
        Line::from(vec![
            key("k"),
            Span::styled("  use an age key file (type its path)", theme::subtle()),
        ]),
        Line::from(vec![
            key("s"),
            Span::styled("  install WITHOUT secrets — everything else", theme::subtle()),
        ]),
        Line::from(Span::styled(
            "        still installs; secrets stay off on the target",
            theme::dim(),
        )),
    ];
    if let Some(buf) = &flow.secrets_key_edit {
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled("path ❯ ", Style::default().fg(theme::ACCENT)),
            Span::styled(buf.clone(), theme::text()),
            Span::styled("▏", Style::default().fg(theme::ACCENT)),
        ]));
    } else {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled("esc closes", theme::dim())));
    }
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

fn render_breadcrumb(frame: &mut Frame<'_>, area: Rect, flow: &Flow) {
    let mut spans = Vec::new();
    if let Some(prev) = flow.prev_step() {
        spans.push(Span::styled(format!("{}  ", prev.name()), theme::dim()));
    }
    spans.push(Span::styled("‹ ", Style::default().fg(theme::ACCENT)));
    // Black on the accent pill, never bold/white — bold turns "bright" in some
    // terminals and the label vanishes into the background color.
    spans.push(Span::styled(
        flow.current().name().to_uppercase(),
        Style::default()
            .fg(ratatui::style::Color::Black)
            .bg(theme::ACCENT),
    ));
    spans.push(Span::styled(" ›", Style::default().fg(theme::ACCENT)));
    if let Some(next) = flow.next_step() {
        spans.push(Span::styled(format!("  {}", next.name()), theme::dim()));
    }

    frame.render_widget(
        Paragraph::new(Line::from(spans)).alignment(Alignment::Center),
        area,
    );
}

const STAGE_HEADER_H: u16 = 3; // title + help + spacer

/// Render the one full-bleed stage inside the outer installer shell.  This is
/// deliberately not a `Block`: the shell is the installer’s only frame.
fn render_stage(frame: &mut Frame<'_>, area: Rect, flow: &Flow) {
    let step = flow.current();
    let stage = area.inner(Margin {
        horizontal: 2,
        vertical: 1,
    });
    let header = vec![
        Line::from(Span::styled(step.question(), theme::title())),
        Line::from(Span::styled(step.help(), theme::dim())),
        Line::from(""),
    ];
    let body = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(STAGE_HEADER_H), Constraint::Min(1)])
        .split(stage);
    frame.render_widget(Paragraph::new(header).wrap(Wrap { trim: true }), body[0]);

    match step.kind() {
        StepKind::Choice if step == Step::Locale => render_locale(frame, body[1], flow),
        StepKind::Choice => render_options(frame, body[1], flow),
        StepKind::Text | StepKind::Password => render_input(frame, body[1], flow),
        StepKind::DiskSelect => render_disk_select(frame, body[1], flow),
        StepKind::ExtraDisks => render_extra_disks(frame, body[1], flow),
        StepKind::Users => render_users(frame, body[1], flow),
        StepKind::Editor(crate::install::flow::Editor::Disks) => {
            render_disk_stage(frame, body[1], flow)
        }
        StepKind::Editor(editor) => render_editor(frame, body[1], flow, editor),
        StepKind::Review => render_review(frame, body[1], flow),
        StepKind::Confirm => render_confirm(frame, body[1], flow),
    }
}

/// Multi-select disk picker with checkboxes + partition bars.
fn render_disk_select(frame: &mut Frame<'_>, area: Rect, flow: &Flow) {
    let disks = flow.installable_disks();
    if disks.is_empty() {
        let msg = flow
            .disk_error
            .clone()
            .map(|e| format!("discovery failed: {e}"))
            .unwrap_or_else(|| "no installable disks (boot media excluded)".to_string());
        frame.render_widget(
            Paragraph::new(Span::styled(msg, Style::default().fg(theme::RED))).wrap(Wrap { trim: true }),
            area,
        );
        return;
    }
    let mut rows: Vec<Row> = Vec::new();
    for (i, disk) in disks.iter().enumerate() {
        let on = flow.is_disk_selected(&disk.path);
        let selected = i == flow.cursor;
        let check = if on {
            Span::styled("[✓] ", Style::default().fg(theme::GREEN))
        } else {
            Span::styled("[ ] ", theme::dim())
        };
        let name = Span::styled(
            disk.path.clone(),
            if selected {
                theme::text().add_modifier(Modifier::BOLD)
            } else {
                theme::subtle()
            },
        );
        let desc = format!(
            "{}G · {} · {}",
            disk.size_gib,
            disk.model.as_deref().unwrap_or("disk"),
            flow.disk_contents(&disk.path),
        );
        rows.push(
            Row::new(vec![theme::cell2(
                Line::from(vec![check, name]),
                Span::styled(desc, theme::dim()),
            )])
            .height(2),
        );
    }
    let table = Table::new(rows, [Constraint::Percentage(100)])
        .row_highlight_style(theme::selected_row())
        .highlight_symbol(Text::from(vec![
            Line::from(Span::styled("▌", Style::default().fg(theme::ACCENT))),
            Line::from(Span::styled("▌", Style::default().fg(theme::ACCENT))),
        ]));
    let mut ts = TableState::default();
    ts.select(Some(flow.cursor.min(disks.len().saturating_sub(1))));
    frame.render_stateful_widget(table, area, &mut ts);
}

/// Multi-user editor: a user list on the left, the selected user's details
/// (name, password, dotfiles, groups) on the right. A group sub-panel overlays
/// The users step overview: who exists, then `e` opens the editor window.
fn render_users(frame: &mut Frame<'_>, area: Rect, flow: &Flow) {
    let mut lines = vec![Line::from("")];
    for (i, user) in flow.state.users.iter().enumerate() {
        let mut line = vec![
            Span::styled("  ● ", Style::default().fg(theme::GREEN)),
            Span::styled(
                format!("{:<14}", user.name),
                theme::text().add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                if user.password_hash.is_some() { "password set  " } else { "no password  " },
                if user.password_hash.is_some() { theme::dim() } else { Style::default().fg(theme::YELLOW) },
            ),
            Span::styled(format!("{} groups", user.groups.len()), theme::dim()),
        ];
        if i == 0 {
            line.push(Span::styled("   primary", theme::dim()));
        }
        lines.push(Line::from(line));
        if let Some(dots) = &user.dotfiles {
            lines.push(Line::from(vec![
                Span::raw("      "),
                Span::styled(format!("dotfiles: {dots}"), theme::dim()),
            ]));
        }
    }
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("  e ", Style::default().fg(theme::ACCENT).add_modifier(Modifier::BOLD)),
        Span::styled("edit the users", theme::subtle()),
    ]));
    frame.render_widget(Paragraph::new(lines), area);
}

/// USERS window · list tier: one row per user.
fn render_users_list(frame: &mut Frame<'_>, area: Rect, flow: &Flow) {
    let mut lines = vec![Line::from("")];
    for (i, user) in flow.state.users.iter().enumerate() {
        let selected = i == flow.user_sel;
        let mut line = vec![
            Span::styled(
                if selected { "  ▌ " } else { "    " },
                Style::default().fg(theme::ACCENT),
            ),
            Span::styled(
                format!("{:<14}", user.name),
                if selected {
                    theme::text().add_modifier(Modifier::BOLD)
                } else {
                    theme::subtle()
                },
            ),
            Span::styled(
                if user.password_hash.is_some() { "password set" } else { "no password" },
                theme::dim(),
            ),
        ];
        if i == 0 {
            line.push(Span::styled("   primary", theme::dim()));
        }
        lines.push(Line::from(line));
    }
    frame.render_widget(Paragraph::new(lines), area);
}

/// USERS window · detail tier: the user's fields on top, groups below.
fn render_user_detail(frame: &mut Frame<'_>, area: Rect, flow: &Flow) {
    use crate::install::state::AVAILABLE_GROUPS;
    let Some(user) = flow.state.users.get(flow.user_sel) else {
        return;
    };
    let editing = |row: usize| -> Option<&str> {
        flow.user_field_edit
            .as_ref()
            .filter(|(r, _)| *r == row)
            .map(|(_, b)| b.as_str())
    };
    let fields: Vec<(&str, String)> = vec![
        ("name", user.name.clone()),
        (
            "password",
            if user.password_hash.is_some() { "set".into() } else { "none".into() },
        ),
        ("dotfiles", user.dotfiles.clone().unwrap_or_else(|| "none".into())),
    ];
    let mut lines = vec![Line::from("")];
    for (row, (label, value)) in fields.iter().enumerate() {
        let selected = flow.user_row == row;
        let marker = Span::styled(
            if selected { "  ▌ " } else { "    " },
            Style::default().fg(theme::ACCENT),
        );
        let label_span = Span::styled(
            format!("{:<12}", label),
            if selected { theme::text() } else { theme::subtle() },
        );
        let value_span = if let Some(buf) = editing(row) {
            // The password buffer renders masked.
            let shown = if row == 1 { "•".repeat(buf.chars().count()) } else { buf.to_string() };
            Span::styled(format!("{shown}█"), Style::default().fg(theme::ACCENT))
        } else {
            Span::styled(value.clone(), theme::text())
        };
        lines.push(Line::from(vec![marker, label_span, value_span]));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled("    ── groups ──", theme::dim())));
    for (i, group) in AVAILABLE_GROUPS.iter().enumerate() {
        let selected = flow.user_row == 3 + i;
        let on = user.groups.iter().any(|g| g == group);
        lines.push(Line::from(vec![
            Span::styled(
                if selected { "  ▌ " } else { "    " },
                Style::default().fg(theme::ACCENT),
            ),
            Span::styled(
                if on { "[x] " } else { "[ ] " },
                Style::default().fg(if on { theme::GREEN } else { theme::MUTED }),
            ),
            Span::styled(
                group.to_string(),
                if selected { theme::text() } else { theme::subtle() },
            ),
        ]));
    }
    frame.render_widget(Paragraph::new(lines), area);
}

/// The users editor window, on the shared modal chrome.
fn render_users_editor_popup(frame: &mut Frame<'_>, stage: Rect, flow: &Flow) {
    use crate::install::flow::UserStage;
    let mut chips: Vec<Span> = Vec::new();
    for (key, label) in view_shortcuts(flow) {
        chips.extend(theme::chip(key, label));
    }
    let content = modal_editor_frame(
        frame,
        stage,
        "users",
        users_tabs_line(flow),
        ("‹ [esc] up", flow.user_stage == UserStage::Detail),
        ("in [↵] ›", flow.user_stage == UserStage::List),
        chips,
    );
    match flow.user_stage {
        UserStage::List => render_users_list(frame, content, flow),
        UserStage::Detail => render_user_detail(frame, content, flow),
    }
}
fn render_extra_disks(frame: &mut Frame<'_>, area: Rect, flow: &Flow) {
    let disks = flow.extra_disks();
    if disks.is_empty() {
        frame.render_widget(
            Paragraph::new(Span::styled("No other disks — press Enter to continue.", theme::dim())),
            area,
        );
        return;
    }
    let mut rows: Vec<Row> = Vec::new();
    for (i, disk) in disks.iter().enumerate() {
        let selected = i == flow.extra_sel;
        let mount = if selected && flow.extra_edit.is_some() {
            Span::styled(
                format!("[{}█]", flow.extra_edit.as_deref().unwrap_or("")),
                Style::default().fg(theme::ACCENT).add_modifier(Modifier::BOLD),
            )
        } else {
            match flow.extra_mount_of(&disk.path) {
                Some(m) => Span::styled(format!("→ {m}"), Style::default().fg(theme::GREEN)),
                None => Span::styled("skip", theme::dim()),
            }
        };
        let name = Span::styled(
            disk.path.clone(),
            if selected {
                theme::text().add_modifier(Modifier::BOLD)
            } else {
                theme::subtle()
            },
        );
        rows.push(
            Row::new(vec![theme::cell2(
                Line::from(vec![name, Span::raw("  "), mount]),
                Span::styled(
                    format!(
                        "{}G · {} · {}",
                        disk.size_gib,
                        disk.model.as_deref().unwrap_or("disk"),
                        flow.disk_contents(&disk.path)
                    ),
                    theme::dim(),
                ),
            )])
            .height(2),
        );
    }
    let table = Table::new(rows, [Constraint::Percentage(100)])
        .row_highlight_style(theme::selected_row())
        .highlight_symbol(Text::from(vec![
            Line::from(Span::styled("▌", Style::default().fg(theme::ACCENT))),
            Line::from(Span::styled("▌", Style::default().fg(theme::ACCENT))),
        ]));
    let mut ts = TableState::default();
    ts.select(Some(flow.extra_sel.min(disks.len().saturating_sub(1))));
    frame.render_stateful_widget(table, area, &mut ts);
}

fn render_options(frame: &mut Frame<'_>, area: Rect, flow: &Flow) {
    let options = flow.options();
    if options.is_empty() {
        let msg = flow
            .disk_error
            .clone()
            .map(|err| format!("no disks: {err}"))
            .unwrap_or_else(|| "no options available".to_string());
        frame.render_widget(
            Paragraph::new(Span::styled(msg, Style::default().fg(theme::RED)))
                .wrap(Wrap { trim: true }),
            area,
        );
        return;
    }

    let rows: Vec<Row> = options
        .iter()
        .enumerate()
        .map(|(index, opt)| {
            let selected = index == flow.cursor;
            let label = if selected {
                Span::styled(
                    opt.label.clone(),
                    Style::default()
                        .fg(theme::TEXT)
                        .add_modifier(Modifier::BOLD),
                )
            } else {
                Span::styled(opt.label.clone(), theme::subtle())
            };
            Row::new(vec![theme::cell2(
                label,
                Span::styled(opt.desc.clone(), theme::dim()),
            )])
            .height(2)
        })
        .collect();

    let table = Table::new(rows, [Constraint::Percentage(100)])
        .row_highlight_style(theme::selected_row())
        .highlight_symbol(ratatui::text::Text::from(vec![
            Line::from(Span::styled("▌", Style::default().fg(theme::ACCENT))),
            Line::from(Span::styled("▌", Style::default().fg(theme::ACCENT))),
        ]));
    let mut ts = TableState::default();
    ts.select(Some(flow.cursor.min(options.len() - 1)));
    frame.render_stateful_widget(table, area, &mut ts);
}

/// The locale step: a timezone list on the left, a globe on the right rotated
/// to the highlighted location with a pin. Ubuntu-installer "where are you?".
fn render_locale(frame: &mut Frame<'_>, area: Rect, flow: &Flow) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(48), Constraint::Percentage(52)])
        .split(area);

    render_options(frame, cols[0], flow);

    let map_area = cols[1];
    if map_area.width < 20 || map_area.height < 8 {
        return;
    }
    let (lat, lon) = flow.locale_coords();
    render_globe(frame, map_area, lat, lon, &flow.state.timezone);
}

/// A braille globe (d10n/tui-globe) rotated so the selected location faces the
/// camera, with a pin dropped on it and the timezone captioned below.
fn render_globe(frame: &mut Frame<'_>, area: Rect, lat: f32, lon: f32, tz: &str) {
    // Leave the bottom row for the caption.
    let globe_area = Rect {
        height: area.height.saturating_sub(1),
        ..area
    };
    let camera = Camera {
        yaw: -lon.to_radians(),
        pitch: lat.to_radians(),
        zoom: 1.4,
    };
    let map = MapData::embedded();
    frame.render_widget(Globe::new(&map, camera), globe_area);

    if let Some((px, py)) = project_point(lat, lon, camera, globe_area) {
        if let Some(cell) = frame.buffer_mut().cell_mut((px, py)) {
            cell.set_symbol("◉");
            cell.set_style(Style::default().fg(theme::RED).add_modifier(Modifier::BOLD));
        }
    }

    let caption = Rect {
        x: area.x,
        y: area.y + area.height.saturating_sub(1),
        width: area.width,
        height: 1,
    };
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("◉ ", Style::default().fg(theme::RED)),
            Span::styled(tz.to_string(), Style::default().fg(theme::TEXT)),
        ]))
        .alignment(Alignment::Center),
        caption,
    );
}

fn disk_role_color(role: crate::install::state::DiskRole) -> ratatui::style::Color {
    use crate::install::state::DiskRole;
    match role {
        DiskRole::System | DiskRole::PoolMember => theme::GREEN,
        DiskRole::Data => theme::YELLOW,
        DiskRole::Reserve => theme::BLUE,
        DiskRole::Ignore => theme::MUTED,
    }
}

/// The storage step: a calm OVERVIEW page (current disks + planned layout).
/// `e` opens the modal storage editor window where the whole tree lives.
fn render_disk_stage(frame: &mut Frame<'_>, area: Rect, flow: &Flow) {
    // ── the overview (always the base layer) ─────────────────────
    let disk_count = flow.facts.as_ref().map(|f| f.disks.len()).unwrap_or(0) as u16;
    let bars_h = (disk_count * 2 + 1).clamp(1, area.height / 3);
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(bars_h), Constraint::Min(4)])
        .split(area);
    if let Some(facts) = &flow.facts {
        render_partition_bars(frame, rows[0], facts, None);
    } else if let Some(err) = &flow.disk_error {
        frame.render_widget(
            Paragraph::new(Span::styled(
                format!("✗ disk discovery: {err}"),
                Style::default().fg(theme::RED),
            )),
            rows[0],
        );
    } else {
        frame.render_widget(
            Paragraph::new(Span::styled("○ discovering target disks…", theme::dim())),
            rows[0],
        );
    }

    // Planned layout summary: every pool with its partitions.
    let mut lines = vec![Line::from("")];
    let mut any = false;
    for group in &flow.state.volume_groups {
        let cap = flow.state.pool_capacity_gib(&group.name);
        if cap == 0 {
            continue;
        }
        any = true;
        lines.push(Line::from(vec![
            Span::styled("  ■ ", Style::default().fg(theme::GREEN)),
            Span::styled(
                format!("{} ", group.name),
                theme::text().add_modifier(Modifier::BOLD),
            ),
            Span::styled(format!("{cap}G"), theme::dim()),
        ]));
        for vol in flow
            .state
            .volumes
            .iter()
            .filter(|v| flow.state.volume_group_for_volume(&v.name) == group.name)
        {
            let size = if vol.fill {
                format!("rest≈{}G", flow.pool_free_gib(&group.name))
            } else {
                format!("{}G", vol.size_gib)
            };
            let mut line = vec![
                Span::raw("      "),
                Span::styled(format!("{:<10}", vol.name), theme::subtle()),
                Span::styled(format!("{:<10}", vol.mountpoint.label()), theme::dim()),
                Span::styled(format!("{:<7}", vol.fs.title()), theme::dim()),
                Span::styled(size, Style::default().fg(theme::YELLOW)),
            ];
            if vol.fs.is_btrfs() && !vol.subvolumes.is_empty() {
                line.push(Span::styled(
                    format!("  +{} subvols", vol.subvolumes.len()),
                    theme::dim(),
                ));
            }
            lines.push(Line::from(line));
        }
    }
    if !any {
        lines.push(Line::from(Span::styled(
            "  no layout yet",
            Style::default().fg(theme::YELLOW),
        )));
    }
    if !flow.storage_has_root() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  ✗ nothing mounts at / — press e and build a root",
            Style::default().fg(theme::RED),
        )));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("  e ", Style::default().fg(theme::ACCENT).add_modifier(Modifier::BOLD)),
        Span::styled("edit the layout", theme::subtle()),
    ]));
    frame.render_widget(Paragraph::new(lines), rows[1]);

}

/// Dim the whole frame to gray — the backdrop behind the storage editor.
fn dim_backdrop(frame: &mut Frame<'_>) {
    let area = frame.area();
    let buf = frame.buffer_mut();
    for y in area.top()..area.bottom() {
        for x in area.left()..area.right() {
            if let Some(cell) = buf.cell_mut(ratatui::layout::Position { x, y }) {
                cell.set_fg(theme::MUTED);
                if cell.bg != ratatui::style::Color::Reset {
                    cell.set_bg(theme::SURFACE_LO);
                }
            }
        }
    }
}

/// The reusable modal-editor chrome: dimmed backdrop, rounded window sized a
/// few columns/rows inside the stage, padding (sides + top), a breadcrumb
/// line and the standard nav bar at the bottom. Returns the CONTENT area for
/// the caller to fill. Storage and users editors share this.
fn modal_editor_frame(
    frame: &mut Frame<'_>,
    stage: Rect,
    title: &str,
    breadcrumb: Line<'static>,
    prev: (&str, bool),
    next: (&str, bool),
    chips: Vec<Span<'static>>,
) -> Rect {
    dim_backdrop(frame);

    let w = stage.width.saturating_sub(6);
    let h = stage.height.saturating_sub(2);
    let x = stage.x + (stage.width - w) / 2;
    let y = stage.y + (stage.height - h) / 2;
    let rect = Rect { x, y, width: w, height: h };
    frame.render_widget(Clear, rect);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .title(Line::from(Span::styled(
            format!(" {title} "),
            Style::default().fg(theme::ACCENT),
        )))
        .border_style(Style::default().fg(theme::ACCENT));
    // One empty column each side and one empty row on TOP — the nav bar sits
    // flush against the bottom border.
    let base = block.inner(rect);
    let inner = Rect {
        x: base.x + 1,
        y: base.y + 1,
        width: base.width.saturating_sub(2),
        height: base.height.saturating_sub(1),
    };
    frame.render_widget(block, rect);

    let prows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(4),    // content (returned)
            Constraint::Length(1), // breadcrumb
            Constraint::Length(2), // nav bar (rule + row)
        ])
        .split(inner);
    frame.render_widget(
        Paragraph::new(breadcrumb).alignment(Alignment::Center),
        prows[1],
    );
    render_nav_bar(frame, prows[2], (prev.0, prev.1, false), (next.0, next.1, false), chips);
    prows[0]
}

fn render_storage_editor_popup(frame: &mut Frame<'_>, stage: Rect, flow: &Flow) {
    use crate::install::flow::DiskStage;
    let mut chips: Vec<Span> = Vec::new();
    for (key, label) in view_shortcuts(flow) {
        chips.extend(theme::chip(key, label));
    }
    let content = modal_editor_frame(
        frame,
        stage,
        "storage",
        storage_tabs_line(flow),
        ("‹ [esc] up", flow.disk_stage != DiskStage::Disks),
        ("in [↵] ›", flow.can_drill()),
        chips,
    );
    match flow.disk_stage {
        DiskStage::Disks => render_disk_pick(frame, content, flow),
        DiskStage::Pools => render_pool_map(frame, content, flow),
        DiskStage::Partitions => render_volumes_panel(frame, content, flow),
        DiskStage::Subvols => render_subvols_page(frame, content, flow),
    }
}

/// The nested sub-tab breadcrumb line: disks › pools › partitions, current
/// bright.
fn storage_tabs_line(flow: &Flow) -> Line<'static> {
    use crate::install::flow::DiskStage;
    let pool = flow.selected_pool_name().unwrap_or_default();
    let mut stages = vec![
        ("disks".to_string(), DiskStage::Disks),
        ("pools".to_string(), DiskStage::Pools),
        (
            if pool.is_empty() {
                "partitions".to_string()
            } else {
                format!("partitions·{pool}")
            },
            DiskStage::Partitions,
        ),
    ];
    if flow.disk_stage == DiskStage::Subvols {
        let vol = flow
            .subvol_target
            .and_then(|i| flow.state.volumes.get(i))
            .map(|v| v.name.clone())
            .unwrap_or_default();
        stages.push((format!("subvols·{vol}"), DiskStage::Subvols));
    }
    let mut spans = Vec::new();
    for (i, (label, stage)) in stages.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled("   ›   ", theme::dim()));
        }
        if *stage == flow.disk_stage {
            spans.push(Span::styled(
                format!("▸ {}", label.to_uppercase()),
                Style::default().fg(theme::ACCENT).add_modifier(Modifier::BOLD),
            ));
        } else {
            spans.push(Span::styled(label.clone(), theme::dim()));
        }
    }
    Line::from(spans)
}

/// The users editor breadcrumb: users › user·name.
fn users_tabs_line(flow: &Flow) -> Line<'static> {
    use crate::install::flow::UserStage;
    let name = flow
        .state
        .users
        .get(flow.user_sel)
        .map(|u| u.name.clone())
        .unwrap_or_default();
    let mut spans = Vec::new();
    if flow.user_stage == UserStage::List {
        spans.push(Span::styled(
            "▸ USERS",
            Style::default().fg(theme::ACCENT).add_modifier(Modifier::BOLD),
        ));
    } else {
        spans.push(Span::styled("users", theme::dim()));
        spans.push(Span::styled("   ›   ", theme::dim()));
        spans.push(Span::styled(
            format!("▸ USER·{}", name.to_uppercase()),
            Style::default().fg(theme::ACCENT).add_modifier(Modifier::BOLD),
        ));
    }
    Line::from(spans)
}

/// PAGE 1: plain disk selection — checkbox per disk, nothing else. The graphs
/// above already show what's on each disk.
fn render_disk_pick(frame: &mut Frame<'_>, area: Rect, flow: &Flow) {
    let disks = flow.installable_disks();
    let mut lines = Vec::new();
    if disks.is_empty() {
        lines.push(Line::from(Span::styled(
            "  (no installable disks found)",
            theme::dim(),
        )));
    }
    let efi_path = disks
        .iter()
        .find(|d| flow.is_disk_selected(&d.path))
        .map(|d| d.path.clone());
    for (i, disk) in disks.iter().enumerate() {
        let picked = flow.is_disk_selected(&disk.path);
        let on_cursor = i == flow.disk_cursor;
        let mut spans = vec![
            Span::styled(
                if on_cursor { "▌ " } else { "  " },
                Style::default().fg(theme::ACCENT),
            ),
            Span::styled(
                if picked { "[x] " } else { "[ ] " },
                Style::default().fg(if picked { theme::GREEN } else { theme::MUTED }),
            ),
            Span::styled(
                format!("{:<9}", short_disk(&disk.path)),
                if picked {
                    theme::text().add_modifier(Modifier::BOLD)
                } else {
                    theme::subtle()
                },
            ),
            Span::styled(format!("{:>6}G  ", disk.size_gib), theme::dim()),
            Span::styled(
                disk.model.clone().unwrap_or_else(|| "disk".into()),
                theme::dim(),
            ),
        ];
        if Some(&disk.path) == efi_path.as_ref() {
            spans.push(Span::styled(
                "  EFI",
                Style::default().fg(theme::YELLOW).add_modifier(Modifier::BOLD),
            ));
        } else if !picked {
            spans.push(Span::styled("  (data disk)", theme::dim()));
        }
        lines.push(Line::from(spans));
    }
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), area);
}

/// One segment of a disk band on the pool map.
struct MapSeg {
    label: String,
    cells: usize,
    color: ratatui::style::Color,
    selected: bool,
}

/// Append a chunky three-row segment band (solid, labelled middle, solid) plus
/// the ▲ selection-marker row. This is THE storage widget — disks-into-pools
/// and pool-into-partitions both draw with it, so the two pages feel identical.
fn push_band(lines: &mut Vec<Line<'static>>, segs: &[MapSeg], with_arrow: bool) {
    let band = |with_label: bool| -> Line<'static> {
        let mut spans: Vec<Span> = vec![Span::raw("  ")];
        for seg in segs {
            let bg = Style::default().bg(seg.color);
            if with_label && seg.cells >= seg.label.chars().count() + 2 {
                let pad = seg.cells - seg.label.chars().count();
                let left = pad / 2;
                let right = pad - left;
                // Plain black, never bold: bold renders as "bright" grey in
                // some terminals and washes out against the band color. The
                // ▲ underneath marks the selection instead.
                let label_style = Style::default()
                    .fg(ratatui::style::Color::Black)
                    .bg(seg.color);
                spans.push(Span::styled(" ".repeat(left), bg));
                spans.push(Span::styled(seg.label.clone(), label_style));
                spans.push(Span::styled(" ".repeat(right), bg));
            } else {
                spans.push(Span::styled(" ".repeat(seg.cells), bg));
            }
        }
        Line::from(spans)
    };
    lines.push(band(false));
    lines.push(band(true));
    lines.push(band(false));
    if with_arrow {
        let mut pre = 2usize;
        let mut arrow_at = None;
        for seg in segs {
            if seg.selected {
                arrow_at = Some(pre + seg.cells / 2);
                break;
            }
            pre += seg.cells;
        }
        if let Some(at) = arrow_at {
            lines.push(Line::from(Span::styled(
                format!("{}▲", " ".repeat(at)),
                Style::default().fg(theme::ACCENT).add_modifier(Modifier::BOLD),
            )));
        } else {
            lines.push(Line::from(""));
        }
    } else {
        lines.push(Line::from(""));
    }
}

/// PAGE 2: the disk↔pool map. Every selected disk is a chunky THREE-ROW bar
/// (the bash capacity-graph style): solid color bands with the label written
/// across the middle row. Each segment is the share of that disk a pool
/// receives; the muted tail is unassigned space. You paint the bars.
fn render_pool_map(frame: &mut Frame<'_>, area: Rect, flow: &Flow) {
    let pools: Vec<String> = flow
        .state
        .volume_groups
        .iter()
        .map(|g| g.name.clone())
        .collect();
    let pool_color = |name: &str| -> ratatui::style::Color {
        pools
            .iter()
            .position(|p| p == name)
            .map(volume_color)
            .unwrap_or(theme::MUTED)
    };
    let bar_w = (area.width as usize).saturating_sub(6).clamp(20, 160);
    let map_disks = flow.map_disks();
    let mut lines = Vec::new();

    for (di, path) in map_disks.iter().enumerate() {
        let total = flow.state.disk_size_gib(path).max(1);
        let esp = flow.state.esp_reserved_gib(path);
        let free = flow.state.disk_free_gib(path);
        let slices = flow.state.slices_for_disk(path).to_vec();
        let on_disk = di == flow.map_disk;

        // Disk label line.
        let mut label = vec![
            Span::styled(
                format!("  {:<9}", short_disk(path)),
                if on_disk {
                    theme::text().add_modifier(Modifier::BOLD)
                } else {
                    theme::subtle()
                },
            ),
            Span::styled(format!("{total}G"), theme::dim()),
        ];
        if esp > 0 {
            label.push(Span::styled(
                format!("  · efi {esp}G"),
                Style::default().fg(theme::YELLOW),
            ));
        }
        if free > 0 {
            label.push(Span::styled(format!("  · free {free}G"), theme::dim()));
        }
        // Always spell out what the cursor is on — a freshly created segment
        // can be too narrow to carry its own label, and the size being typed
        // must never be invisible.
        if on_disk {
            let sel_txt = if flow.size_editing() {
                let target = flow
                    .selected_slice()
                    .map(|(_, idx)| slices[idx].pool.clone())
                    .unwrap_or_else(|| "free".into());
                format!(
                    "   ▸ {target} → [{}█]G",
                    flow.size_edit.as_deref().unwrap_or("")
                )
            } else if let Some((_, idx)) = flow.selected_slice() {
                format!("   ▸ {} {}G", slices[idx].pool, slices[idx].size_gib)
            } else {
                format!("   ▸ free {free}G")
            };
            label.push(Span::styled(
                sel_txt,
                Style::default().fg(theme::ACCENT),
            ));
        }
        lines.push(Line::from(label));

        // Collect the segments: [efi][slice…][free].
        let cells_of = |gib: u64| ((gib as usize * bar_w) / total as usize).max(1);
        let mut segs: Vec<MapSeg> = Vec::new();
        if esp > 0 {
            segs.push(MapSeg {
                label: "efi".into(),
                cells: cells_of(esp),
                color: theme::YELLOW,
                selected: false,
            });
        }
        for (si, slice) in slices.iter().enumerate() {
            let selected = on_disk && flow.seg_sel == si;
            let text = if selected && flow.size_editing() {
                format!("{} [{}█]G", slice.pool, flow.size_edit.as_deref().unwrap_or(""))
            } else {
                format!("{} {}G", slice.pool, slice.size_gib)
            };
            segs.push(MapSeg {
                label: text,
                cells: cells_of(slice.size_gib),
                color: pool_color(&slice.pool),
                selected,
            });
        }
        if free > 0 {
            segs.push(MapSeg {
                label: format!("free {free}G"),
                cells: cells_of(free),
                color: theme::SURFACE,
                selected: on_disk && flow.seg_sel == slices.len(),
            });
        }

        push_band(&mut lines, &segs, on_disk);
    }

    // Legend: every pool with its color and total capacity.
    let mut legend = vec![Span::raw("  ")];
    for (i, pool) in pools.iter().enumerate() {
        if i > 0 {
            legend.push(Span::raw("   "));
        }
        legend.push(Span::styled("■ ", Style::default().fg(pool_color(pool))));
        legend.push(Span::styled(
            format!("{pool} {}G", flow.state.pool_capacity_gib(pool)),
            theme::subtle(),
        ));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(legend));

    frame.render_widget(Paragraph::new(lines), area);
}

/// PAGE 3: the selected pool as the SAME chunky band as the disk map — each
/// segment is a partition (the fill partition shows the live remainder), the
/// muted tail is unallocated space. A detail line under the ▲ describes the
/// selected partition.
fn render_volumes_panel(frame: &mut Frame<'_>, area: Rect, flow: &Flow) {
    use crate::install::flow::PartField;
    let members = flow.volumes_in_selected_pool();
    let pool = flow.selected_pool_name().unwrap_or_default();
    let cap = flow.pool_capacity_gib(&pool);
    let free = flow.pool_free_gib(&pool);
    let has_fill = members.iter().any(|&vi| flow.state.volumes[vi].fill);
    let bar_w = (area.width as usize).saturating_sub(6).clamp(20, 160);

    let mut lines = Vec::new();

    // The pool's OWN values, editable in place (e), above its partitions.
    let pool_editing = |row: usize| -> Option<&str> {
        flow.pool_edit
            .as_ref()
            .filter(|(r, _)| *r == row)
            .map(|(_, b)| b.as_str())
    };
    let name_marker = Span::styled(
        if flow.part_zone == 0 { "  ▌ " } else { "    " },
        Style::default().fg(theme::ACCENT),
    );
    let name_value = if let Some(buf) = pool_editing(0) {
        Span::styled(format!("{buf}█"), Style::default().fg(theme::ACCENT))
    } else {
        Span::styled(pool.clone(), theme::text().add_modifier(Modifier::BOLD))
    };
    lines.push(Line::from(vec![
        name_marker,
        Span::styled(
            format!("{:<12}", "pool name"),
            if flow.part_zone == 0 { theme::text() } else { theme::subtle() },
        ),
        name_value,
    ]));
    let size_marker = Span::styled(
        if flow.part_zone == 1 { "  ▌ " } else { "    " },
        Style::default().fg(theme::ACCENT),
    );
    let size_value = if let Some(buf) = pool_editing(1) {
        Span::styled(format!("{buf}█"), Style::default().fg(theme::ACCENT))
    } else {
        let mut txt = format!("{cap}G");
        if !has_fill && free > 0 {
            txt.push_str(&format!("  · free {free}G"));
        }
        Span::styled(txt, Style::default().fg(theme::YELLOW))
    };
    lines.push(Line::from(vec![
        size_marker,
        Span::styled(
            format!("{:<12}", "pool size"),
            if flow.part_zone == 1 { theme::text() } else { theme::subtle() },
        ),
        size_value,
    ]));
    lines.push(Line::from(""));

    if cap == 0 {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  this pool has no disk space — esc, then give it a segment on the map",
            Style::default().fg(theme::YELLOW),
        )));
        frame.render_widget(Paragraph::new(lines), area);
        return;
    }

    // Segments: one per partition (+ trailing free). Fill shows the remainder.
    let cells_of = |gib: u64| ((gib as usize * bar_w) / cap.max(1) as usize).max(1);
    let mut segs: Vec<MapSeg> = Vec::new();
    for (row, &vi) in members.iter().enumerate() {
        let vol = &flow.state.volumes[vi];
        let selected = row == flow.vol_sel;
        let shown_gib = if vol.fill { free } else { vol.size_gib };
        let text = if selected && flow.size_editing() {
            format!("{} [{}█]G", vol.name, flow.size_edit.as_deref().unwrap_or(""))
        } else if vol.fill {
            format!("{} rest≈{}G", vol.name, free)
        } else {
            format!("{} {}G", vol.name, vol.size_gib)
        };
        segs.push(MapSeg {
            label: text,
            cells: cells_of(shown_gib.max(1)),
            color: volume_color(row),
            selected,
        });
    }
    if !has_fill && free > 0 {
        segs.push(MapSeg {
            label: format!("free {free}G"),
            cells: cells_of(free),
            color: theme::SURFACE,
            selected: flow.on_free_partition(),
        });
    }
    if segs.is_empty() {
        // Pool with space but zero partitions and zero free can't happen; an
        // empty pool shows one big free segment via the branch above. Guard
        // anyway for the degenerate case.
        segs.push(MapSeg {
            label: format!("free {free}G"),
            cells: bar_w,
            color: theme::SURFACE,
            selected: true,
        });
    }
    push_band(&mut lines, &segs, true);

    // Detail line for the selection (or the free tail).
    let editing = flow.disk_rename.is_some();
    if let Some(&vi) = members.get(flow.vol_sel) {
        let vol = &flow.state.volumes[vi];
        let name_txt = if editing && flow.disk_edit_field == PartField::Name {
            format!("[{}█]", flow.disk_rename.as_deref().unwrap_or(""))
        } else {
            vol.name.clone()
        };
        let mount_txt = if editing && flow.disk_edit_field == PartField::Mount {
            format!("[{}█]", flow.disk_rename.as_deref().unwrap_or(""))
        } else {
            vol.mountpoint.label().to_string()
        };
        let fs_color = if vol.fs.is_btrfs() { theme::GREEN } else { theme::MAUVE };
        let mut detail = vec![
            Span::raw("  "),
            Span::styled(name_txt, theme::text().add_modifier(Modifier::BOLD)),
            Span::styled("  ·  ", theme::dim()),
            Span::styled(mount_txt, theme::subtle()),
            Span::styled("  ·  ", theme::dim()),
            Span::styled(vol.fs.title().to_string(), Style::default().fg(fs_color)),
        ];
        // The size — including the live typing buffer — always lives here too,
        // because a tiny fresh partition's band segment can't show any label.
        if flow.size_editing() {
            detail.push(Span::styled(
                format!("  ·  → [{}█]G", flow.size_edit.as_deref().unwrap_or("")),
                Style::default().fg(theme::ACCENT),
            ));
        } else if vol.fill {
            detail.push(Span::styled(
                format!("  ·  takes the rest (≈{free}G)"),
                Style::default().fg(theme::GREEN),
            ));
        } else {
            detail.push(Span::styled(
                format!("  ·  {}G", vol.size_gib),
                Style::default().fg(theme::YELLOW),
            ));
        }
        if vol.fs.is_btrfs() {
            let mut subs = vec![format!("@{}", vol.name)];
            subs.extend(vol.subvolumes.iter().map(|s| format!("@{}", s.name)));
            detail.push(Span::styled(
                format!("  ·  {}", subs.join(" ")),
                theme::dim(),
            ));
        }
        lines.push(Line::from(detail));
    } else if flow.on_free_partition() {
        lines.push(Line::from(vec![
            Span::raw("  "),
            Span::styled(format!("free {free}G"), Style::default().fg(theme::MUTED)),
            Span::styled("  — a adds a partition here", theme::dim()),
        ]));
    } else if members.is_empty() {
        lines.push(Line::from(Span::styled(
            "  no partitions yet — a adds one",
            theme::dim(),
        )));
    }

    frame.render_widget(Paragraph::new(lines), area);
}

/// Modal list of a btrfs volume's subvolumes, drawn centred over the volumes
/// panel while the sub-editor is open.
/// PAGE 4: inside one partition — its editable values on top, its subvolumes
/// (btrfs) below. `e` edits the selected row, `b` climbs back out.
fn render_subvols_page(frame: &mut Frame<'_>, area: Rect, flow: &Flow) {
    let Some(vi) = flow.subvol_target else { return };
    let vol = &flow.state.volumes[vi];
    let pool = flow.selected_pool_name().unwrap_or_default();
    let free = flow.pool_free_gib(&pool);

    let editing = |row: usize| -> Option<&str> {
        flow.detail_edit
            .as_ref()
            .filter(|(r, _)| *r == row)
            .map(|(_, b)| b.as_str())
    };
    let fs_color = if vol.fs.is_btrfs() { theme::GREEN } else { theme::MAUVE };
    let size_text = if vol.fill {
        format!("rest≈{free}G")
    } else {
        format!("{}G", vol.size_gib)
    };
    let fields: Vec<(&str, String, ratatui::style::Color)> = vec![
        ("name", vol.name.clone(), theme::TEXT),
        ("mount", vol.mountpoint.label().to_string(), theme::TEXT),
        ("filesystem", vol.fs.title().to_string(), fs_color),
        ("size", size_text, theme::YELLOW),
        (
            "take the rest",
            if vol.fill { "[x] yes" } else { "[ ] no" }.to_string(),
            theme::TEXT,
        ),
    ];

    let mut lines = Vec::new();
    for (row, (label, value, color)) in fields.iter().enumerate() {
        let selected = flow.part_cursor == row;
        let marker = Span::styled(
            if selected { "  ▌ " } else { "    " },
            Style::default().fg(theme::ACCENT),
        );
        let label_span = Span::styled(
            format!("{:<15}", label),
            if selected { theme::text() } else { theme::subtle() },
        );
        let value_span = if let Some(buf) = editing(row) {
            Span::styled(
                format!("{buf}█"),
                Style::default().fg(theme::ACCENT),
            )
        } else {
            Span::styled(value.clone(), Style::default().fg(*color))
        };
        lines.push(Line::from(vec![marker, label_span, value_span]));
    }

    // Subvolumes below (btrfs only): root first, then extras.
    if vol.fs.is_btrfs() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "    ── subvolumes ──",
            theme::dim(),
        )));
        let root_sel = flow.part_cursor == 5;
        lines.push(Line::from(vec![
            Span::styled(
                if root_sel { "  ▌ " } else { "    " },
                Style::default().fg(theme::ACCENT),
            ),
            Span::styled(
                format!("{:<14}", format!("@{}", vol.name)),
                if root_sel { theme::text() } else { theme::subtle() },
            ),
            Span::styled("→ ", theme::dim()),
            Span::styled(vol.mountpoint.label().to_string(), theme::subtle()),
            Span::styled("   (root — always present)", theme::dim()),
        ]));
        for (i, sub) in vol.subvolumes.iter().enumerate() {
            let selected = flow.part_cursor == 6 + i;
            let editing_sub = flow.subvol_edit.as_ref().filter(|_| selected);
            let (name_txt, mount_txt) = match editing_sub {
                Some((crate::install::flow::SubvolField::Name, buf)) => {
                    (format!("@{buf}█"), sub.mountpoint.clone())
                }
                Some((crate::install::flow::SubvolField::Mount, buf)) => {
                    (format!("@{}", sub.name), format!("{buf}█"))
                }
                _ => (format!("@{}", sub.name), sub.mountpoint.clone()),
            };
            lines.push(Line::from(vec![
                Span::styled(
                    if selected { "  ▌ " } else { "    " },
                    Style::default().fg(theme::ACCENT),
                ),
                Span::styled(
                    format!("{:<14}", name_txt),
                    if selected { theme::text() } else { theme::subtle() },
                ),
                Span::styled("→ ", theme::dim()),
                Span::styled(mount_txt, theme::subtle()),
            ]));
        }
        if vol.subvolumes.is_empty() {
            lines.push(Line::from(Span::styled(
                "    (no extra subvolumes — a adds one)",
                theme::dim(),
            )));
        }
    }
    frame.render_widget(Paragraph::new(lines), area);
}

fn render_partition_bars(
    frame: &mut Frame<'_>,
    area: Rect,
    facts: &crate::facts::TargetFacts,
    selected_path: Option<&str>,
) {
    let mut lines = Vec::new();
    for disk in facts.disks.iter().take(area.height as usize / 2) {
        let selected = Some(disk.path.as_str()) == selected_path;
        let marker = if selected { "▌" } else { " " };
        let in_use = disk
            .partitions
            .iter()
            .any(|partition| !partition.mountpoints.is_empty());
        lines.push(Line::from(vec![
            Span::styled(marker, Style::default().fg(theme::ACCENT)),
            Span::styled(
                format!(
                    " {}  {}  {}{}",
                    short_disk(&disk.path),
                    format_bytes(disk.size_bytes),
                    disk.model.as_deref().unwrap_or("disk"),
                    if in_use { "  (in use)" } else { "" },
                ),
                if selected {
                    theme::text().add_modifier(Modifier::BOLD)
                } else {
                    theme::subtle()
                },
            ),
        ]));
        lines.push(partition_bar_line(
            disk,
            area.width.saturating_sub(2) as usize,
        ));
    }
    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            "No block disks reported by target",
            theme::dim(),
        )));
    }
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), area);
}

fn partition_bar_line(disk: &crate::facts::DiskFacts, width: usize) -> Line<'static> {
    let width = width.clamp(12, 76);
    let total = disk.size_bytes.max(1);
    let used: u64 = disk.partitions.iter().map(|part| part.size_bytes).sum();
    let mut spans = Vec::new();
    for part in &disk.partitions {
        let cells = ((part.size_bytes.saturating_mul(width as u64) / total) as usize).max(1);
        let label = part
            .fstype
            .as_deref()
            .or(part.label.as_deref())
            .unwrap_or("other");
        spans.extend(bar_segment(label, cells, fstype_color(part.fstype.as_deref())));
        spans.push(Span::raw(" "));
    }
    let free = total.saturating_sub(used);
    if free > 0 || spans.is_empty() {
        let cells = ((free.saturating_mul(width as u64) / total) as usize).max(1);
        spans.extend(bar_segment("free", cells, theme::MUTED));
    }
    Line::from(spans)
}

/// One bar segment: a solid block fill in `color`, with `label` cut out of the
/// middle (dark ink on the colored fill) when it fits. Returned as spans so the
/// label stays readable rather than blending into the fill.
fn bar_segment(label: &str, cells: usize, color: ratatui::style::Color) -> Vec<Span<'static>> {
    let block = Style::default().fg(color);
    if cells <= 1 {
        return vec![Span::styled("▏", block)];
    }
    let label_len = label.chars().count();
    if cells < label_len + 2 {
        return vec![Span::styled("█".repeat(cells), block)];
    }
    let pad = cells - label_len;
    let left = pad / 2;
    let right = pad - left;
    vec![
        Span::styled("█".repeat(left), block),
        // Plain black, never bold — bold turns "bright" grey in some terminals
        // and disappears against the band color.
        Span::styled(
            label.to_string(),
            Style::default()
                .fg(ratatui::style::Color::Black)
                .bg(color),
        ),
        Span::styled("█".repeat(right), block),
    ]
}


fn fstype_color(fstype: Option<&str>) -> ratatui::style::Color {
    match fstype.unwrap_or("").to_ascii_lowercase().as_str() {
        "vfat" | "fat" | "fat32" => theme::BLUE,
        "ext4" => theme::GREEN,
        "btrfs" => theme::MAUVE,
        "xfs" => theme::PEACH,
        "swap" => theme::YELLOW,
        "lvm2_member" => theme::SKY,
        "ntfs" | "exfat" => theme::RED,
        _ => theme::MUTED,
    }
}

fn volume_color(index: usize) -> ratatui::style::Color {
    [
        theme::GREEN,
        theme::MAUVE,
        theme::BLUE,
        theme::PEACH,
        theme::YELLOW,
        theme::SKY,
    ][index % 6]
}

fn short_disk(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn format_bytes(bytes: u64) -> String {
    const GIB: u64 = 1024 * 1024 * 1024;
    if bytes >= GIB {
        format!("{:.1}G", bytes as f64 / GIB as f64)
    } else {
        format!("{}M", bytes / (1024 * 1024))
    }
}

/// A field value inside an editor row. The focused field is bracketed and, when
/// it is a text field, shows the live edit buffer with a cursor.
fn field_span(
    flow: &Flow,
    editor: crate::install::flow::Editor,
    item: usize,
    field: usize,
    value: String,
    base: ratatui::style::Color,
) -> Span<'static> {
    let focused = item == flow.item && field == flow.field;
    if focused && editor.is_text(field) {
        Span::styled(
            format!("[{}█]", flow.buffer),
            Style::default()
                .fg(theme::ACCENT)
                .add_modifier(Modifier::BOLD),
        )
    } else if focused {
        Span::styled(
            format!("[{value}]"),
            Style::default()
                .fg(theme::ACCENT)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(value, Style::default().fg(base))
    }
}

fn render_editor(
    frame: &mut Frame<'_>,
    area: Rect,
    flow: &Flow,
    editor: crate::install::flow::Editor,
) {
    use crate::install::flow::Editor;

    if flow.item_count() == 0 {
        let msg = flow
            .disk_error
            .clone()
            .map(|e| format!("discovery failed: {e}"))
            .unwrap_or_else(|| "empty — press ^n to add".to_string());
        frame.render_widget(
            Paragraph::new(Span::styled(msg, theme::dim())).wrap(Wrap { trim: true }),
            area,
        );
        return;
    }

    let state = &flow.state;
    let (rows, widths): (Vec<Row>, Vec<Constraint>) = match editor {
        Editor::Disks => {
            let rows = state
                .disks
                .iter()
                .enumerate()
                .map(|(i, disk)| {
                    let role = state.disk_role_for_path(&disk.path);
                    let pool = state
                        .disk_volume_group_for_path(&disk.path)
                        .unwrap_or("-")
                        .to_string();
                    let rc = disk_role_color(role);
                    Row::new(vec![
                        theme::cell2(
                            field_span(
                                flow,
                                editor,
                                i,
                                0,
                                format!("{} {}", role.marker(), role.title()),
                                rc,
                            ),
                            Line::from(vec![
                                Span::styled("pool ", theme::dim()),
                                field_span(flow, editor, i, 1, pool, theme::BLUE),
                            ]),
                        ),
                        theme::cell2(
                            field_span(flow, editor, i, 2, disk.path.clone(), theme::TEXT),
                            Line::from(vec![
                                field_span(
                                    flow,
                                    editor,
                                    i,
                                    3,
                                    format!("{}G", disk.size_gib),
                                    theme::YELLOW,
                                ),
                                Span::styled(
                                    format!(" · {}", disk.model.as_deref().unwrap_or("disk")),
                                    theme::dim(),
                                ),
                            ]),
                        ),
                    ])
                    .height(2)
                })
                .collect();
            (rows, vec![Constraint::Length(20), Constraint::Min(16)])
        }
        Editor::Volumes => {
            let rows = state
                .volumes
                .iter()
                .enumerate()
                .map(|(i, vol)| {
                    let pool = state.volume_group_for_volume(&vol.name).to_string();
                    Row::new(vec![
                        theme::cell2(
                            field_span(flow, editor, i, 0, vol.name.clone(), theme::TEXT),
                            field_span(
                                flow,
                                editor,
                                i,
                                1,
                                vol.mountpoint.label().to_string(),
                                theme::GREEN,
                            ),
                        ),
                        theme::cell2(
                            field_span(
                                flow,
                                editor,
                                i,
                                3,
                                format!("{}G", vol.size_gib),
                                theme::YELLOW,
                            ),
                            Line::from(vec![
                                Span::styled("on ", theme::dim()),
                                field_span(flow, editor, i, 2, pool, theme::BLUE),
                            ]),
                        ),
                    ])
                    .height(2)
                })
                .collect();
            (rows, vec![Constraint::Min(16), Constraint::Length(14)])
        }
        Editor::Pools => {
            let rows = state
                .volume_groups
                .iter()
                .enumerate()
                .map(|(i, pool)| {
                    let disks = state
                        .disks
                        .iter()
                        .filter(|d| {
                            state.disk_volume_group_for_path(&d.path) == Some(pool.name.as_str())
                        })
                        .map(|d| d.path.rsplit('/').next().unwrap_or(&d.path))
                        .collect::<Vec<_>>()
                        .join("+");
                    let vols = state
                        .volumes
                        .iter()
                        .filter(|v| state.volume_group_for_volume(&v.name) == pool.name)
                        .map(|v| v.name.as_str())
                        .collect::<Vec<_>>()
                        .join(",");
                    Row::new(vec![theme::cell2(
                        field_span(flow, editor, i, 0, pool.name.clone(), theme::TEXT),
                        Line::from(vec![
                            Span::styled("disks ", theme::dim()),
                            Span::styled(
                                if disks.is_empty() { "-".into() } else { disks },
                                Style::default().fg(theme::BLUE),
                            ),
                            Span::styled("  vols ", theme::dim()),
                            Span::styled(
                                if vols.is_empty() { "-".into() } else { vols },
                                Style::default().fg(theme::GREEN),
                            ),
                        ]),
                    )])
                    .height(2)
                })
                .collect();
            (rows, vec![Constraint::Percentage(100)])
        }
        Editor::DocSubvols => {
            let rows = state
                .doc_subvolumes
                .iter()
                .enumerate()
                .map(|(i, sub)| {
                    Row::new(vec![theme::cell2(
                        Line::from(vec![
                            Span::styled("/doc/", theme::dim()),
                            field_span(flow, editor, i, 0, sub.clone(), theme::TEXT),
                        ]),
                        Span::styled("btrfs subvolume", theme::dim()),
                    )])
                    .height(2)
                })
                .collect();
            (rows, vec![Constraint::Percentage(100)])
        }
    };

    let table = Table::new(rows, widths)
        .row_highlight_style(theme::selected_row())
        .highlight_symbol(ratatui::text::Text::from(vec![
            Line::from(Span::styled("▌", Style::default().fg(theme::ACCENT))),
            Line::from(Span::styled("▌", Style::default().fg(theme::ACCENT))),
        ]));
    let mut ts = TableState::default();
    ts.select(Some(flow.item.min(flow.item_count().saturating_sub(1))));
    frame.render_stateful_widget(table, area, &mut ts);
}

fn render_input(frame: &mut Frame<'_>, area: Rect, flow: &Flow) {
    let step = flow.current();
    let masked = step.kind() == StepKind::Password;
    let raw = if step == Step::PasswordConfirm {
        &flow.password_confirm
    } else if masked {
        &flow.password
    } else {
        &flow.buffer
    };
    let shown = if masked {
        "•".repeat(raw.chars().count())
    } else {
        raw.clone()
    };
    let value_empty = shown.is_empty();
    let cursor = if masked {
        shown.chars().count()
    } else {
        flow.text_cursor().min(shown.chars().count())
    };

    // Underlined input line — the outer shell is the only frame.
    let field = Line::from(vec![
        Span::styled("❯ ", Style::default().fg(theme::ACCENT)),
        if value_empty {
            Span::styled(
                match step {
                    Step::Dotfiles => "(blank to skip)",
                    Step::Password | Step::PasswordConfirm => "(hidden)",
                    _ => "type here…",
                },
                theme::dim(),
            )
        } else {
            Span::styled(
                shown.chars().take(cursor).collect::<String>(),
                Style::default().fg(theme::TEXT).add_modifier(Modifier::BOLD),
            )
        },
        Span::styled("█", Style::default().fg(theme::ACCENT)),
        Span::styled(
            shown.chars().skip(cursor).collect::<String>(),
            Style::default().fg(theme::TEXT).add_modifier(Modifier::BOLD),
        ),
    ]);

    // Status line under the field: password match / strength / hint.
    let status = match step {
        Step::PasswordConfirm => {
            if flow.password_confirm.is_empty() {
                Line::from(Span::styled("re-enter to confirm", theme::dim()))
            } else if flow.password_confirm == flow.password {
                Line::from(Span::styled("✓ passwords match", Style::default().fg(theme::GREEN)))
            } else {
                Line::from(Span::styled("✗ does not match", Style::default().fg(theme::RED)))
            }
        }
        Step::Password => {
            if flow.password.is_empty() {
                Line::from(Span::styled("no password — account will be unlocked", theme::dim()))
            } else {
                Line::from(vec![
                    Span::styled(
                        format!("{} chars  ", flow.password.chars().count()),
                        theme::dim(),
                    ),
                    Span::styled(
                        password_strength(&flow.password),
                        Style::default().fg(theme::YELLOW),
                    ),
                ])
            }
        }
        _ => Line::from(Span::raw("")),
    };

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(2), Constraint::Min(1)])
        .split(area);
    frame.render_widget(
        Paragraph::new(field).block(
            Block::default()
                .borders(Borders::BOTTOM)
                .border_style(Style::default().fg(theme::SURFACE)),
        ),
        rows[0],
    );
    frame.render_widget(Paragraph::new(status), rows[1]);
}

fn password_strength(pw: &str) -> &'static str {
    let len = pw.chars().count();
    let classes = [
        pw.chars().any(|c| c.is_lowercase()),
        pw.chars().any(|c| c.is_uppercase()),
        pw.chars().any(|c| c.is_ascii_digit()),
        pw.chars().any(|c| !c.is_alphanumeric()),
    ]
    .iter()
    .filter(|b| **b)
    .count();
    match (len, classes) {
        (0..=5, _) => "weak",
        (6..=9, 0..=2) => "fair",
        (_, 0..=2) => "good",
        _ => "strong",
    }
}

/// A compact per-volume filesystem breakdown for the review screen, e.g.
/// "6 vols · btrfs×4 ext4×1 swap×1".
fn volumes_summary(state: &crate::install::state::InstallState) -> String {
    use crate::install::state::VolumeFs;
    let (mut btrfs, mut ext4, mut xfs, mut swap) = (0, 0, 0, 0);
    for v in &state.volumes {
        match v.fs {
            VolumeFs::Btrfs => btrfs += 1,
            VolumeFs::Ext4 => ext4 += 1,
            VolumeFs::Xfs => xfs += 1,
            VolumeFs::Swap => swap += 1,
        }
    }
    let mut parts = Vec::new();
    if btrfs > 0 {
        parts.push(format!("btrfs×{btrfs}"));
    }
    if ext4 > 0 {
        parts.push(format!("ext4×{ext4}"));
    }
    if xfs > 0 {
        parts.push(format!("xfs×{xfs}"));
    }
    if swap > 0 {
        parts.push(format!("swap×{swap}"));
    }
    format!("{} vols · {}", state.volumes.len(), parts.join(" "))
}

fn render_review(frame: &mut Frame<'_>, area: Rect, flow: &Flow) {
    let state = &flow.state;
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    // Left: the plan summary.
    let disk = state
        .disks
        .first()
        .map(|d| format!("{} ({}G)", d.path, d.size_gib))
        .unwrap_or_else(|| "-".to_string());
    let kv = |k: &str, v: String, color| {
        Line::from(vec![
            Span::styled(format!("{k:<11}"), theme::dim()),
            Span::styled(v, Style::default().fg(color)),
        ])
    };
    let summary = vec![
        kv(
            "scope",
            format!(
                "{} {}",
                state.scope.title(),
                if state.scope == crate::install::state::InstallScope::Remote {
                    state.remote.clone()
                } else {
                    "this machine".into()
                }
            ),
            theme::TEXT,
        ),
        kv("hostname", state.hostname.clone(), theme::TEXT),
        kv("user", state.install_user.clone(), theme::TEXT),
        kv(
            "password",
            if flow.password.is_empty() {
                "none".into()
            } else {
                "set".into()
            },
            if flow.password.is_empty() {
                theme::YELLOW
            } else {
                theme::GREEN
            },
        ),
        kv("role", state.role.title().to_string(), theme::TEXT),
        kv(
            "ssh",
            if state.allow_ssh {
                "enabled".into()
            } else {
                "disabled".into()
            },
            if state.allow_ssh {
                theme::GREEN
            } else {
                theme::MUTED
            },
        ),
        kv("disk", disk, theme::TEXT),
        kv("volumes", volumes_summary(state), theme::TEXT),
        kv(
            "encrypt",
            if state.encrypt {
                "yes".into()
            } else {
                "no".into()
            },
            if state.encrypt {
                theme::GREEN
            } else {
                theme::MUTED
            },
        ),
        kv(
            "overwrite",
            if state.overwrite_existing_storage {
                "wipe".into()
            } else {
                "keep".into()
            },
            if state.overwrite_existing_storage {
                theme::RED
            } else {
                theme::MUTED
            },
        ),
        kv(
            "dotfiles",
            state.dotfiles_repo.clone().unwrap_or_else(|| "skip".into()),
            theme::SUBTEXT,
        ),
    ];
    frame.render_widget(Paragraph::new(summary).wrap(Wrap { trim: true }), cols[0]);

    // Right: insights + preflight.
    let mut lines: Vec<Line> = Vec::new();
    if let Some(facts) = &flow.facts {
        let plan = crate::facts::InstallAssessment {
            selected_disks: state.disks.iter().map(|d| d.path.clone()).collect(),
            planned_vgs: state.volume_groups.iter().map(|g| g.name.clone()).collect(),
            planned_gib: state.used_gib(),
            overwrite: state.overwrite_existing_storage,
        };
        for insight in crate::facts::assess(facts, &plan) {
            let (marker, color) = match insight.severity {
                crate::facts::Severity::Critical => ("!!", theme::RED),
                crate::facts::Severity::Warning => ("! ", theme::YELLOW),
                crate::facts::Severity::Info => ("· ", theme::MUTED),
            };
            lines.push(Line::from(vec![
                Span::styled(format!("{marker} "), Style::default().fg(color)),
                Span::styled(insight.message.clone(), Style::default().fg(color)),
            ]));
        }
    }
    if !lines.is_empty() {
        lines.push(Line::from(""));
    }
    match &flow.preflight {
        Some(report) => {
            for check in &report.checks {
                let (marker, color) = match check.status {
                    PreflightStatus::Pass => ("✓", theme::GREEN),
                    PreflightStatus::Fail => ("✗", theme::RED),
                };
                lines.push(Line::from(vec![
                    Span::styled(format!("{marker} "), Style::default().fg(color)),
                    Span::styled(check.name, Style::default().fg(theme::TEXT)),
                    Span::styled(format!("  {}", check.detail), theme::dim()),
                ]));
            }
        }
        None if flow.preflight_running() => lines.push(Line::from(Span::styled(
            "◌ preflight running… (progress below)",
            Style::default().fg(theme::YELLOW),
        ))),
        None => lines.push(Line::from(Span::styled(
            "press space to run preflight",
            Style::default().fg(theme::YELLOW),
        ))),
    }
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), cols[1]);
}

fn render_confirm(frame: &mut Frame<'_>, area: Rect, flow: &Flow) {
    let phrase = flow.confirm_phrase();
    let armed = flow.confirm_armed();
    let lines = vec![
        Line::from(Span::styled(
            "This erases the target disk. Type the phrase exactly:",
            Style::default().fg(theme::RED),
        )),
        Line::from(""),
        Line::from(Span::styled(
            phrase,
            Style::default()
                .fg(theme::YELLOW)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("❯ ", Style::default().fg(theme::ACCENT)),
            Span::styled(
                flow.confirm_input.clone(),
                Style::default().fg(if armed { theme::GREEN } else { theme::TEXT }),
            ),
            Span::styled("█", Style::default().fg(theme::ACCENT)),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            if armed {
                "✓ armed — enter to install"
            } else {
                "locked"
            },
            Style::default().fg(if armed { theme::GREEN } else { theme::MUTED }),
        )),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: true }),
        area,
    );
}

/// Every shortcut for the CURRENT view — feeds both the (clippable) chip
/// strip and the `?` panel, so they can never drift apart.
fn view_shortcuts(flow: &Flow) -> Vec<(&'static str, &'static str)> {
    use crate::install::flow::DiskStage;
    if flow.current() == Step::Storage {
        if !flow.storage_popup {
            return vec![("e", "edit layout")];
        }
        if flow.edit_popup.is_some() {
            return vec![
                ("↑↓", "field"),
                ("type", "edit"),
                ("←→", "cycle"),
                ("↵", "apply"),
                ("esc", "cancel"),
            ];
        }
        if flow.disk_rename.is_some() || flow.size_editing() || flow.subvol_edit.is_some() {
            return vec![("type", "edit"), ("↵", "apply"), ("esc", "cancel")];
        }
        // Live field buffers: the cursor is IN the field; moving saves.
        if flow.pool_edit.is_some() || flow.detail_edit.is_some() {
            return vec![("type", "edit"), ("↑↓/↵", "save + move"), ("esc", "up")];
        }
        return match flow.disk_stage {
            DiskStage::Disks => {
                let mut list = vec![("↑↓", "disk"), ("␣", "toggle")];
                if flow.storage_has_root() {
                    list.push(("f", "finish ▸"));
                }
                list
            }
            DiskStage::Pools => vec![
                ("←→", "segment"),
                ("↑↓", "disk"),
                ("a", "new pool"),
                ("p", "join/move"),
                ("0-9", "size"),
                ("s", "split"),
                ("d", "free"),
                ("r", "rename"),
            ],
            DiskStage::Partitions => vec![
                ("↑↓", "pool/parts"),
                ("←→", "part"),
                ("e", "edit"),
                ("a", "add"),
                ("0-9", "size"),
                ("s", "split"),
                ("*", "rest"),
                ("d", "del"),
            ],
            DiskStage::Subvols => vec![
                ("↑↓", "row"),
                ("e", "edit"),
                ("a", "add subvol"),
                ("d", "del subvol"),
            ],
        };
    }
    match flow.current().kind() {
        StepKind::Choice => vec![("↑↓", "choose")],
        StepKind::Text | StepKind::Password => vec![("type", "edit")],
        StepKind::DiskSelect => vec![("↑↓", "disk"), ("␣", "toggle")],
        StepKind::ExtraDisks => vec![("↑↓", "disk"), ("m", "mount"), ("s", "skip")],
        StepKind::Users if !flow.users_popup => vec![("e", "edit users")],
        StepKind::Users if flow.user_field_edit.is_some() => {
            vec![("type", "edit"), ("↑↓/↵", "save + move"), ("esc", "list")]
        }
        StepKind::Users if flow.user_stage == crate::install::flow::UserStage::Detail => {
            vec![("↑↓", "row"), ("␣", "toggle group")]
        }
        StepKind::Users => {
            let mut list = vec![("↑↓", "user"), ("a", "add"), ("d", "del")];
            if !flow.state.users.iter().any(|u| u.name.trim().is_empty()) {
                list.push(("f", "finish ▸"));
            }
            list
        }
        StepKind::Editor(_) => vec![
            ("↑↓", "item"),
            ("←→", "field"),
            ("␣", "cycle"),
            ("^n", "add"),
            ("^x", "del"),
        ],
        StepKind::Review if flow.secrets_popup && flow.secrets_key_edit.is_some() => {
            vec![("type", "path"), ("↵", "check"), ("esc", "cancel")]
        }
        StepKind::Review if flow.secrets_popup => vec![
            ("y", "yubikey"),
            ("k", "key file"),
            ("s", "no secrets"),
            ("esc", "close"),
        ],
        StepKind::Review => vec![("␣", "preflight"), ("s", "secrets")],
        StepKind::Confirm => vec![("type", "phrase"), ("↵", "install")],
    }
}

/// A footer button: `[ ‹ prev ]` / `[ next › ]` — color0 text on color1 when
/// usable; when inactive only the BACKGROUND turns gray, the text stays. A
/// keyboard-focused button (Tab) lights up bright.
fn nav_button(label: &str, enabled: bool, focused: bool) -> Span<'static> {
    let bg = if focused {
        theme::TEXT
    } else if enabled {
        theme::ACCENT
    } else {
        theme::MUTED
    };
    Span::styled(
        format!(" {label} "),
        Style::default().fg(ratatui::style::Color::Indexed(0)).bg(bg),
    )
}

/// The navigation bar: rule on top, [ prev ]│ centered chips │[ next ] below.
/// Shared by the main footer and the storage editor window so they look
/// identical. Chips collapse to a centered [ ? ] on overflow.
#[allow(clippy::too_many_arguments)]
fn render_nav_bar(
    frame: &mut Frame<'_>,
    area: Rect,
    prev: (&str, bool, bool),
    next: (&str, bool, bool),
    chips: Vec<Span<'static>>,
) {
    let prev_w = (prev.0.chars().count() + 2) as u16;
    let next_w = (next.0.chars().count() + 2) as u16;
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(prev_w),
            Constraint::Length(1),
            Constraint::Min(0),
            Constraint::Length(1),
            Constraint::Length(next_w),
        ])
        .split(area);
    let rule = Block::default()
        .borders(Borders::TOP)
        .border_style(Style::default().fg(theme::SURFACE));
    let sep = |frame: &mut Frame<'_>, at: Rect| {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled("│", theme::dim()))).block(rule.clone()),
            at,
        );
    };
    frame.render_widget(
        Paragraph::new(Line::from(nav_button(prev.0, prev.1, prev.2))).block(rule.clone()),
        cols[0],
    );
    sep(frame, cols[1]);
    let chips_w: usize = chips.iter().map(|sp| sp.content.chars().count()).sum();
    let middle = if chips_w <= cols[2].width as usize {
        Line::from(chips)
    } else {
        Line::from(nav_button("?", true, false))
    };
    frame.render_widget(
        Paragraph::new(middle)
            .alignment(Alignment::Center)
            .block(rule.clone()),
        cols[2],
    );
    sep(frame, cols[3]);
    frame.render_widget(
        Paragraph::new(Line::from(nav_button(next.0, next.1, next.2))).block(rule),
        cols[4],
    );
}

fn render_flow_footer(frame: &mut Frame<'_>, area: Rect, flow: &Flow) {
    // Status gets its OWN full-width row above the rule.
    let status = if !flow.status.is_empty() {
        Span::styled(format!(" {}", flow.status), Style::default().fg(theme::YELLOW))
    } else if flow.current() == Step::Storage && flow.storage_popup {
        Span::styled(
            format!(" tier: {}", flow.disk_stage.title()),
            theme::subtle(),
        )
    } else if flow.current() == Step::Storage {
        Span::raw("")
    } else if let StepKind::Editor(editor) = flow.current().kind() {
        Span::styled(
            format!(" field: {}", editor.field_name(flow.field)),
            theme::subtle(),
        )
    } else {
        Span::raw("")
    };
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Length(2)])
        .split(area);
    frame.render_widget(Paragraph::new(Line::from(status)), rows[0]);

    // Bottom row: [ esc back ]│ …centered chips… │[ next ↵ ]. The buttons
    // NEVER clip; when the chips don't fit the middle, a centered [ ? ]
    // replaces them (the panel then holds the full list).
    let prev_txt = "‹ back";
    let next_txt = "next ›";
    let prev_w = (prev_txt.chars().count() + 2) as u16;
    let next_w = (next_txt.chars().count() + 2) as u16;
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(prev_w), // [ ‹ prev ]
            Constraint::Length(1),      // │
            Constraint::Min(0),         // centered chips (or [ ? ])
            Constraint::Length(1),      // │
            Constraint::Length(next_w), // [ next › ]
        ])
        .split(rows[1]);
    let rule = Block::default()
        .borders(Borders::TOP)
        .border_style(Style::default().fg(theme::SURFACE));
    let sep = |frame: &mut Frame<'_>, at: Rect| {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled("│", theme::dim())))
                .block(rule.clone()),
            at,
        );
    };

    use crate::install::flow::FooterFocus;
    frame.render_widget(
        Paragraph::new(Line::from(nav_button(
            prev_txt,
            flow.can_prev(),
            flow.footer_focus == Some(FooterFocus::Prev),
        )))
        .block(rule.clone()),
        cols[0],
    );
    sep(frame, cols[1]);
    // Middle: the chips when they fit, otherwise a lone centered [ ? ].
    let mut chips: Vec<Span> = Vec::new();
    for (key, label) in view_shortcuts(flow) {
        chips.extend(theme::chip(key, label));
    }
    let chips_w: usize = chips.iter().map(|sp| sp.content.chars().count()).sum();
    let middle = if chips_w <= cols[2].width as usize {
        Line::from(chips)
    } else {
        Line::from(nav_button("?", true, false))
    };
    frame.render_widget(
        Paragraph::new(middle)
            .alignment(Alignment::Center)
            .block(rule.clone()),
        cols[2],
    );
    sep(frame, cols[3]);
    frame.render_widget(
        Paragraph::new(Line::from(nav_button(
            next_txt,
            flow.can_next(),
            flow.footer_focus == Some(FooterFocus::Next),
        )))
        .block(rule),
        cols[4],
    );
}

/// The `?` panel: every shortcut for the current view, plus the globals.
fn render_help_overlay(frame: &mut Frame<'_>, flow: &Flow) {
    let area = frame.area();
    let shortcuts = view_shortcuts(flow);
    let w = area.width.saturating_sub(4).min(46).max(28);
    let h = (shortcuts.len() as u16 + 8).min(area.height.saturating_sub(2));
    let x = area.x + (area.width.saturating_sub(w)) / 2;
    let y = area.y + (area.height.saturating_sub(h)) / 2;
    let rect = Rect { x, y, width: w, height: h };
    frame.render_widget(Clear, rect);

    let mut lines = vec![Line::from("")];
    for (key, label) in &shortcuts {
        lines.push(Line::from(vec![
            Span::raw("  "),
            Span::styled(format!("{key:>6}"), Style::default().fg(theme::ACCENT)),
            Span::raw("  "),
            Span::styled(label.to_string(), theme::text()),
        ]));
    }
    lines.push(Line::from(""));
    for (key, label) in [
        ("⇥", "focus the esc/next buttons"),
        ("?", "this panel"),
        ("q", "quit"),
    ] {
        lines.push(Line::from(vec![
            Span::raw("  "),
            Span::styled(format!("{key:>6}"), Style::default().fg(theme::YELLOW)),
            Span::raw("  "),
            Span::styled(label.to_string(), theme::dim()),
        ]));
    }

    let block = Block::default()
        .borders(Borders::ALL)
        .title(Line::from(Span::styled(
            " shortcuts ",
            Style::default().fg(theme::ACCENT),
        )))
        .border_style(Style::default().fg(theme::ACCENT));
    frame.render_widget(Paragraph::new(lines).block(block), rect);
}

// ── live install progress ───────────────────────────────────────

fn run_install_screen(
    terminal: &mut PreviewTerminal,
    repo: &Path,
    state: &InstallState,
) -> Result<u8> {
    let mut run = crate::install::progress::InstallRun::spawn(repo.to_path_buf(), state.clone());

    loop {
        run.pump();
        let elapsed = run.elapsed().as_secs();
        terminal
            .terminal
            .draw(|frame| render_progress(frame, &run.state, elapsed))
            .map_err(|err| format!("failed to draw install progress: {err}"))?;

        if event::poll(Duration::from_millis(120))
            .map_err(|err| format!("failed to poll terminal input: {err}"))?
        {
            if let Event::Key(key) =
                event::read().map_err(|err| format!("failed to read terminal input: {err}"))?
            {
                if key.kind == KeyEventKind::Press && run.is_finished() {
                    if matches!(key.code, KeyCode::Char('q') | KeyCode::Esc | KeyCode::Enter) {
                        return Ok(if run.state.failed { 1 } else { 0 });
                    }
                }
            }
        }
    }
}

fn render_progress(
    frame: &mut Frame<'_>,
    progress: &crate::install::progress::ProgressState,
    elapsed: u64,
) {
    use crate::install::progress::StepStatus;

    let area = frame.area();
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(6),
            Constraint::Length(3),
        ])
        .split(area);

    let label = if progress.finished {
        progress
            .summary
            .clone()
            .unwrap_or_else(|| "done".to_string())
    } else {
        format!(
            "{} — step {}/{}",
            if progress.phase.is_empty() {
                "installing"
            } else {
                progress.phase.as_str()
            },
            progress.completed_steps(),
            progress.total.max(1),
        )
    };
    let gauge_color = if progress.failed {
        theme::RED
    } else if progress.finished {
        theme::GREEN
    } else {
        theme::ACCENT
    };
    frame.render_widget(
        Gauge::default()
            .block(panel_titled(format!("install · {elapsed}s")))
            .gauge_style(Style::default().fg(gauge_color))
            .ratio(progress.ratio())
            .label(label),
        rows[0],
    );

    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(38), Constraint::Percentage(62)])
        .split(rows[1]);

    let step_rows: Vec<Row> = progress
        .steps
        .iter()
        .enumerate()
        .map(|(index, step)| {
            let (icon, color, word) = match step.status {
                StepStatus::Pending => ("○", theme::MUTED, "pending"),
                StepStatus::Running => ("▶", theme::ACCENT, "running"),
                StepStatus::Done => ("✓", theme::GREEN, "done"),
                StepStatus::Failed => ("✗", theme::RED, "failed"),
                StepStatus::Refused => ("⊘", theme::YELLOW, "refused"),
            };
            let mut name = theme::primary(step.name.clone());
            if Some(index) == progress.running_index {
                name = name.patch_style(Style::default().fg(theme::TEXT));
            }
            let detail = match step.millis {
                Some(ms) => format!("{word} · {:.1}s", ms as f64 / 1000.0),
                None => word.to_string(),
            };
            Row::new(vec![
                theme::cell1(Span::styled(icon, Style::default().fg(color))),
                theme::cell2(name, Span::styled(detail, Style::default().fg(color))),
            ])
            .height(2)
        })
        .collect();
    frame.render_widget(
        Table::new(step_rows, [Constraint::Length(3), Constraint::Min(10)]).block(panel("steps")),
        columns[0],
    );

    let output_area = columns[1];
    let visible = output_area.height.saturating_sub(2) as usize;
    let start = progress.output.len().saturating_sub(visible.max(1));
    let output_lines: Vec<Line> = progress.output[start..]
        .iter()
        .map(|line| {
            let color = if line.starts_with("! ") {
                theme::RED
            } else if line.starts_with('$') {
                theme::ACCENT
            } else if line.starts_with('•') {
                theme::MUTED
            } else {
                theme::SUBTEXT
            };
            Line::from(Span::styled(line.clone(), Style::default().fg(color)))
        })
        .collect();
    frame.render_widget(
        Paragraph::new(output_lines)
            .block(panel("output"))
            .wrap(Wrap { trim: false }),
        output_area,
    );

    let footer = if progress.finished {
        Line::from(vec![
            Span::styled(
                if progress.failed {
                    " FAILED "
                } else {
                    " DONE "
                },
                Style::default()
                    .fg(ratatui::style::Color::Black)
                    .bg(if progress.failed {
                        theme::RED
                    } else {
                        theme::GREEN
                    }),
            ),
            Span::raw("  "),
            Span::styled(progress.summary.clone().unwrap_or_default(), theme::dim()),
        ])
    } else {
        Line::from(vec![
            Span::styled("● ", Style::default().fg(theme::PEACH)),
            Span::styled(
                "installing — do not power off the target",
                Style::default().fg(theme::YELLOW),
            ),
        ])
    };
    let hint = if progress.finished {
        Line::from([theme::chip("q", "exit"), theme::chip("↵", "exit")].concat()).right_aligned()
    } else {
        Line::from(Span::styled(" running… ", theme::dim())).right_aligned()
    };
    frame.render_widget(
        Paragraph::new(footer).block(theme::panel_bare().title(hint)),
        rows[2],
    );
    if progress.finished {
        render_install_result_popup(frame, progress);
    }
}

fn render_install_result_popup(
    frame: &mut Frame<'_>,
    progress: &crate::install::progress::ProgressState,
) {
    let (title, color, headline) = if progress.failed {
        (
            " install failed ",
            theme::RED,
            "✗ installation did not complete",
        )
    } else {
        (
            " install complete ",
            theme::GREEN,
            "✓ installation completed",
        )
    };
    let body = Text::from(vec![
        Line::from(Span::styled(
            headline,
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            progress
                .summary
                .clone()
                .unwrap_or_else(|| "No summary was reported.".to_string()),
            theme::text(),
        )),
        Line::from(""),
        Line::from(Span::styled("Press Enter, Esc, or q to exit", theme::dim())),
    ]);
    let popup = Popup::new(body)
        .title(Line::from(Span::styled(
            title,
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        )))
        .style(Style::default().fg(theme::TEXT).bg(theme::SURFACE_LO))
        .border_style(Style::default().fg(color));
    frame.render_widget(&popup, frame.area());
}

// ── terminal plumbing ───────────────────────────────────────────

fn panel(title: &str) -> Block<'static> {
    theme::panel(title)
}

fn panel_titled(title: String) -> Block<'static> {
    theme::panel(&title)
}

fn full_screen(area: Rect) -> Rect {
    let horizontal = if area.width >= 100 { 1 } else { 0 };
    let vertical = if area.height >= 30 { 1 } else { 0 };
    Rect {
        x: area.x + horizontal,
        y: area.y + vertical,
        width: area.width.saturating_sub(horizontal * 2),
        height: area.height.saturating_sub(vertical * 2),
    }
}

struct PreviewTerminal {
    terminal: Terminal<CrosstermBackend<io::Stdout>>,
    left: bool,
}

impl PreviewTerminal {
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

impl Drop for PreviewTerminal {
    fn drop(&mut self) {
        if !self.left {
            let _ = disable_raw_mode();
            let _ = execute!(self.terminal.backend_mut(), LeaveAlternateScreen);
            let _ = self.terminal.show_cursor();
        }
    }
}

#[cfg(test)]
mod tests {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    use super::{render_flow, render_progress};
    use crate::install::flow::{Flow, Step};
    use crate::install::state::InstallState;

    fn draw(flow: &Flow) -> String {
        let mut terminal = Terminal::new(TestBackend::new(110, 34)).unwrap();
        terminal.draw(|frame| render_flow(frame, flow)).unwrap();
        let buf = terminal.backend().buffer().clone();
        buf.content().iter().map(|c| c.symbol()).collect()
    }

    #[test]
    fn renders_first_question_without_panic() {
        let flow = Flow::new(InstallState::draft());
        let text = draw(&flow);
        assert!(text.contains("Where do you want to install"));
        assert!(text.contains("local"));
        assert!(text.contains("remote"));
    }

    #[test]
    fn renders_breadcrumb_current_step() {
        let flow = Flow::new(InstallState::draft());
        let text = draw(&flow);
        assert!(text.contains("SCOPE"));
        assert!(text.contains("step 1/"));
    }

    #[test]
    fn password_step_masks_input() {
        let mut flow = Flow::new(InstallState::draft());
        flow.disable_discovery = true;
        flow.state.discovered_disks = vec![crate::install::state::DiskChoice {
            path: "/dev/sda".into(),
            size_gib: 512,
            model: None,
        }];
        flow.cursor = 0; // local
        for _ in 0..40 {
            if flow.current() == Step::Users {
                break;
            }
            if flow.current() == Step::Storage && !flow.storage_has_root() {
                flow.goto_pools();
                flow.pool_from_free();
                flow.pool_enter();
                flow.disk_add();
                flow.goto_disks();
            }
            flow.advance();
        }
        assert_eq!(flow.current(), Step::Users);
        // open the users editor, drill into the user, edit the password row
        flow.users_popup_open();
        flow.users_enter();
        flow.user_row = 1; // password
        flow.user_edit_row();
        flow.user_field_insert('s');
        flow.user_field_insert('e');
        flow.user_field_insert('c');
        let text = draw(&flow);
        assert!(!text.contains("sec"));
        assert!(text.contains('•'));
    }

    #[test]
    fn renders_progress_screen_without_panic() {
        use crate::report::{Event, Stream};
        let mut progress = crate::install::progress::ProgressState::default();
        progress.apply(Event::StepStarted {
            index: 0,
            total: 3,
            name: "prepare target disk".to_string(),
            command: "nox-agent disk-prepare /dev/sda".to_string(),
            destructive: true,
        });
        progress.apply(Event::StepOutput {
            stream: Stream::Stdout,
            chunk: b"copying paths...\n".to_vec(),
        });
        progress.apply(Event::StepCompleted {
            index: 0,
            name: "prepare target disk".to_string(),
            status: 0,
            stdout: String::new(),
            stderr: String::new(),
            millis: 1500,
        });

        let mut terminal = Terminal::new(TestBackend::new(120, 36)).unwrap();
        terminal
            .draw(|frame| render_progress(frame, &progress, 12))
            .unwrap();

        progress.finished = true;
        progress.failed = true;
        progress.summary = Some("install failed: boom".to_string());
        terminal
            .draw(|frame| render_progress(frame, &progress, 30))
            .unwrap();
    }

    fn storage_flow() -> Flow {
        let mut flow = Flow::new(InstallState::sample());
        flow.disable_discovery = true;
        flow.facts = Some(crate::facts::TargetFacts {
            disks: vec![crate::facts::DiskFacts {
                path: "/dev/nvme0n1".into(),
                size_bytes: 465 * 1024 * 1024 * 1024,
                ..crate::facts::DiskFacts::default()
            }],
            ..crate::facts::TargetFacts::default()
        });
        for _ in 0..40 {
            if flow.current() == Step::Storage {
                break;
            }
            flow.advance();
        }
        // Most tests exercise the tiers, which live inside the editor window.
        flow.storage_popup = true;
        flow
    }

    #[test]
    fn storage_disks_page_is_a_checkbox_list() {
        let mut flow = storage_flow();
        assert_eq!(flow.current(), Step::Storage);
        flow.goto_disks();
        let text = draw(&flow);
        assert!(text.contains("DISKS")); // the focused sub-tab, upper-cased
        assert!(text.contains("[x]"));
        assert!(text.contains("EFI"));
    }

    #[test]
    fn storage_pools_page_is_a_segment_map() {
        let mut flow = storage_flow();
        flow.goto_pools();
        // Split the disk's segment, so the map shows two segments + legend.
        flow.map_disk = 0;
        flow.seg_sel = 0;
        flow.slice_split();
        let text = draw(&flow);
        assert!(text.contains("POOLS"));
        // Bar labels carry "<pool> <size>G", and the legend lists the pool.
        assert!(text.contains("pool"));
        assert!(text.contains("efi"));
    }

    #[test]
    fn storage_editor_drills_from_pool_into_partitions() {
        let mut flow = storage_flow();
        flow.goto_pools();
        flow.pool_enter();
        assert_eq!(flow.disk_stage, crate::install::flow::DiskStage::Partitions);
        let text = draw(&flow);
        assert!(text.contains("PARTITIONS"));
    }

    #[test]
    fn storage_editor_shows_per_volume_filesystem() {
        let mut flow = storage_flow();
        assert_eq!(flow.current(), Step::Storage);
        // Claim the disk for the pool, then drill into its partitions.
        flow.goto_pools();
        flow.pool_from_free();
        flow.pool_enter();
        // The detail line under the band shows the SELECTED partition's fs.
        let members = flow.volumes_in_selected_pool();
        let select = |flow: &mut Flow, name: &str| {
            flow.vol_sel = members
                .iter()
                .position(|&i| flow.state.volumes[i].name == name)
                .unwrap();
        };
        select(&mut flow, "root");
        assert!(draw(&flow).contains("btrfs"));
        select(&mut flow, "pkg");
        assert!(draw(&flow).contains("ext4"));
        select(&mut flow, "swap");
        assert!(draw(&flow).contains("swap"));
        // Wide segments carry their name inside the band (narrow ones rely on
        // the detail line, like gparted).
        let text = draw(&flow);
        for name in ["docs", "nix"] {
            assert!(text.contains(name), "band shows {name}");
        }
    }

    #[test]
    fn storage_editor_enters_the_subvolume_tier() {
        let mut flow = storage_flow();
        flow.goto_pools();
        flow.pool_from_free();
        flow.pool_enter();
        // Select the docs volume (has subvolumes in the sample fixture) and
        // ENTER it — subvolumes are a full tier of the tree now.
        let members = flow.volumes_in_selected_pool();
        flow.vol_sel = members
            .iter()
            .position(|&i| flow.state.volumes[i].name == "docs")
            .unwrap();
        flow.storage_forward();
        assert_eq!(flow.disk_stage, crate::install::flow::DiskStage::Subvols);
        let text = draw(&flow);
        assert!(text.contains("SUBVOLS·DOCS")); // breadcrumb, current tier
        assert!(text.contains("@code"));
        assert!(text.contains("root — always present"));
    }

    #[test]
    fn partition_categories_have_stable_distinct_colors() {
        let colors = [
            super::fstype_color(Some("vfat")),
            super::fstype_color(Some("ext4")),
            super::fstype_color(Some("btrfs")),
            super::fstype_color(Some("xfs")),
            super::fstype_color(Some("swap")),
            super::fstype_color(Some("LVM2_member")),
            super::fstype_color(Some("ntfs")),
        ];
        for (index, color) in colors.iter().enumerate() {
            assert!(
                !colors[..index].contains(color),
                "category color {index} duplicates an earlier category"
            );
        }
    }
}
