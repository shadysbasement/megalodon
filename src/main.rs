mod engine;
mod packet;
mod ui;

use std::io::{self, stdout};
use std::panic;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};

use engine::{CaptureSource, Engine};
use ui::{ActivePane, AppState};

#[derive(Parser, Debug)]
#[command(
    name = "megalodon",
    author = "megalodon developers",
    version = "0.1.0",
    about = "MEGALODON: A blazing-fast, modern TUI for Wireshark & tshark",
    long_about = "Megalodon is an ultra-fast, zero-overhead terminal packet analyzer inspired by Wireshark and Termshark."
)]
struct Cli {
    /// Read packet data from a pcap/pcapng capture file
    #[arg(short = 'r', long = "read")]
    read_file: Option<String>,

    /// Sniff packets live on network interface
    #[arg(short = 'i', long = "interface")]
    interface: Option<String>,

    /// Wireshark display filter to apply
    #[arg(short = 'Y', long = "filter")]
    filter: Option<String>,

    /// Limit maximum number of packets to load
    #[arg(short = 'c', long = "count")]
    count: Option<usize>,

    /// Positional capture file path (optional alternative to -r)
    file_pos: Option<String>,
}

fn setup_panic_hook() {
    let original_hook = panic::take_hook();
    panic::set_hook(Box::new(move |panic_info| {
        let _ = disable_raw_mode();
        let _ = execute!(stdout(), LeaveAlternateScreen, DisableMouseCapture);
        original_hook(panic_info);
    }));
}

fn update_packet_detail(state: &mut AppState, engine: &mut Engine) {
    if state.packets.is_empty() {
        state.current_detail = None;
        return;
    }

    let p_idx = state.selected_packet.min(state.packets.len().saturating_sub(1));
    let frame_num = state.packets[p_idx].number;

    match engine.get_detail(frame_num) {
        Ok(detail) => {
            state.current_detail = Some(detail);
            state.selected_layer = 0;
            state.hex_scroll = 0;
        }
        Err(e) => {
            state.status_msg = Some(format!("Detail error: {}", e));
        }
    }
}

fn reload_packets(state: &mut AppState, engine: &mut Engine) {
    match engine.load_summaries() {
        Ok(summaries) => {
            state.packets = summaries;
            state.selected_packet = 0;
            state.status_msg = None;
            update_packet_detail(state, engine);
        }
        Err(e) => {
            state.status_msg = Some(format!("Error loading packets: {}", e));
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let target_file = cli.read_file.or(cli.file_pos);
    let (source, source_name) = match (target_file, cli.interface) {
        (Some(file), _) => (CaptureSource::File(file.clone()), file),
        (None, Some(iface)) => (CaptureSource::Interface(iface.clone()), format!("Live [{}]", iface)),
        (None, None) => {
            eprintln!("Error: Please provide a capture file (-r <file.pcap>) or interface (-i <eth0>)");
            eprintln!("Example: megalodon -r test.pcap");
            std::process::exit(1);
        }
    };

    setup_panic_hook();

    let mut engine = Engine::new(source, cli.filter.clone(), cli.count);
    let mut state = AppState::new(source_name);
    state.active_filter = cli.filter;

    // Load initial packets
    reload_packets(&mut state, &mut engine);

    // Initialize terminal
    enable_raw_mode().context("Failed to enable raw mode")?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)
        .context("Failed to initialize alternate screen")?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("Failed to create terminal")?;

    let res = run_app(&mut terminal, &mut state, &mut engine);

    // Clean up terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        eprintln!("Application error: {:?}", err);
    }

    Ok(())
}

fn run_app<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    state: &mut AppState,
    engine: &mut Engine,
) -> Result<()> {
    loop {
        terminal.draw(|f| ui::render(f, state))?;

        if event::poll(Duration::from_millis(40))? {
            if let Event::Key(key) = event::read()? {
                if state.filter_mode {
                    match key.code {
                        KeyCode::Esc => {
                            state.filter_mode = false;
                        }
                        KeyCode::Enter => {
                            state.filter_mode = false;
                            let input = state.filter_input.trim().to_string();
                            if input.is_empty() {
                                state.active_filter = None;
                                engine.filter = None;
                            } else {
                                state.active_filter = Some(input.clone());
                                engine.filter = Some(input);
                            }
                            reload_packets(state, engine);
                        }
                        KeyCode::Backspace => {
                            state.filter_input.pop();
                        }
                        KeyCode::Char(c) => {
                            state.filter_input.push(c);
                        }
                        _ => {}
                    }
                    continue;
                }

                // Global Shortcuts
                if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
                    break;
                }

                match key.code {
                    KeyCode::Char('q') => break,
                    KeyCode::Tab => state.next_pane(),
                    KeyCode::BackTab => state.prev_pane(),
                    KeyCode::Char('/') => {
                        state.filter_mode = true;
                        state.filter_input = state.active_filter.clone().unwrap_or_default();
                    }
                    KeyCode::Char('c') => {
                        state.active_filter = None;
                        engine.filter = None;
                        reload_packets(state, engine);
                    }
                    KeyCode::Up | KeyCode::Char('k') => match state.active_pane {
                        ActivePane::Packets => {
                            if state.selected_packet > 0 {
                                state.selected_packet -= 1;
                                update_packet_detail(state, engine);
                            }
                        }
                        ActivePane::Layers => {
                            state.selected_layer = state.selected_layer.saturating_sub(1);
                        }
                        ActivePane::Hex => {
                            state.hex_scroll = state.hex_scroll.saturating_sub(1);
                        }
                    },
                    KeyCode::Down | KeyCode::Char('j') => match state.active_pane {
                        ActivePane::Packets => {
                            if !state.packets.is_empty()
                                && state.selected_packet + 1 < state.packets.len()
                            {
                                state.selected_packet += 1;
                                update_packet_detail(state, engine);
                            }
                        }
                        ActivePane::Layers => {
                            if let Some(detail) = &state.current_detail {
                                if state.selected_layer + 1 < detail.layers.len() {
                                    state.selected_layer += 1;
                                }
                            }
                        }
                        ActivePane::Hex => {
                            state.hex_scroll += 1;
                        }
                    },
                    KeyCode::PageUp => match state.active_pane {
                        ActivePane::Packets => {
                            state.selected_packet = state.selected_packet.saturating_sub(10);
                            update_packet_detail(state, engine);
                        }
                        ActivePane::Layers => {
                            state.selected_layer = state.selected_layer.saturating_sub(10);
                        }
                        ActivePane::Hex => {
                            state.hex_scroll = state.hex_scroll.saturating_sub(10);
                        }
                    },
                    KeyCode::PageDown => match state.active_pane {
                        ActivePane::Packets => {
                            if !state.packets.is_empty() {
                                state.selected_packet = (state.selected_packet + 10)
                                    .min(state.packets.len().saturating_sub(1));
                                update_packet_detail(state, engine);
                            }
                        }
                        ActivePane::Layers => {
                            if let Some(detail) = &state.current_detail {
                                state.selected_layer = (state.selected_layer + 10)
                                    .min(detail.layers.len().saturating_sub(1));
                            }
                        }
                        ActivePane::Hex => {
                            state.hex_scroll += 10;
                        }
                    },
                    KeyCode::Home | KeyCode::Char('g') => match state.active_pane {
                        ActivePane::Packets => {
                            state.selected_packet = 0;
                            update_packet_detail(state, engine);
                        }
                        ActivePane::Layers => {
                            state.selected_layer = 0;
                        }
                        ActivePane::Hex => {
                            state.hex_scroll = 0;
                        }
                    },
                    KeyCode::End | KeyCode::Char('G') => match state.active_pane {
                        ActivePane::Packets => {
                            if !state.packets.is_empty() {
                                state.selected_packet = state.packets.len().saturating_sub(1);
                                update_packet_detail(state, engine);
                            }
                        }
                        ActivePane::Layers => {
                            if let Some(detail) = &state.current_detail {
                                state.selected_layer = detail.layers.len().saturating_sub(1);
                            }
                        }
                        ActivePane::Hex => {
                            state.hex_scroll = 100;
                        }
                    },
                    _ => {}
                }
            }
        }
    }

    Ok(())
}
