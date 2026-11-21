use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Cell, Paragraph, Row, Table},
    Frame,
};

use crate::packet::{format_hex_dump, PacketDetail, PacketSummary};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivePane {
    Packets,
    Layers,
    Hex,
}

pub struct AppState {
    pub packets: Vec<PacketSummary>,
    pub selected_packet: usize,
    pub current_detail: Option<PacketDetail>,
    pub selected_layer: usize,
    pub hex_scroll: usize,
    pub active_pane: ActivePane,
    pub filter_mode: bool,
    pub filter_input: String,
    pub active_filter: Option<String>,
    pub status_msg: Option<String>,
    pub source_name: String,
}

impl AppState {
    pub fn new(source_name: String) -> Self {
        Self {
            packets: Vec::new(),
            selected_packet: 0,
            current_detail: None,
            selected_layer: 0,
            hex_scroll: 0,
            active_pane: ActivePane::Packets,
            filter_mode: false,
            filter_input: String::new(),
            active_filter: None,
            status_msg: None,
            source_name,
        }
    }

    pub fn next_pane(&mut self) {
        self.active_pane = match self.active_pane {
            ActivePane::Packets => ActivePane::Layers,
            ActivePane::Layers => ActivePane::Hex,
            ActivePane::Hex => ActivePane::Packets,
        };
    }

    pub fn prev_pane(&mut self) {
        self.active_pane = match self.active_pane {
            ActivePane::Packets => ActivePane::Hex,
            ActivePane::Layers => ActivePane::Packets,
            ActivePane::Hex => ActivePane::Layers,
        };
    }
}

pub fn render(frame: &mut Frame, state: &mut AppState) {
    let size = frame.area();

    // Main layout: Header, Filter Bar (optional), 3-pane split (Packets, Details/Hex), Status/Help Footer
    let constraints = if state.filter_mode || state.active_filter.is_some() {
        vec![
            Constraint::Length(3), // Title / stats
            Constraint::Length(3), // Filter bar
            Constraint::Percentage(45), // Packets list
            Constraint::Percentage(45), // Lower panes (Layers + Hex)
            Constraint::Length(1), // Help / status
        ]
    } else {
        vec![
            Constraint::Length(3), // Title / stats
            Constraint::Percentage(48), // Packets list
            Constraint::Percentage(46), // Lower panes (Layers + Hex)
            Constraint::Length(1), // Help / status
        ]
    };

    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(size);

    let mut chunk_idx = 0;

    // 1. Header
    render_header(frame, state, main_chunks[chunk_idx]);
    chunk_idx += 1;

    // 2. Filter Bar (if visible)
    if state.filter_mode || state.active_filter.is_some() {
        render_filter_bar(frame, state, main_chunks[chunk_idx]);
        chunk_idx += 1;
    }

    // 3. Packets Table
    render_packet_table(frame, state, main_chunks[chunk_idx]);
    chunk_idx += 1;

    // 4. Lower Section: Layers (Left) and Hex Dump (Right)
    let lower_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(main_chunks[chunk_idx]);
    chunk_idx += 1;

    render_layer_tree(frame, state, lower_chunks[0]);
    render_hex_dump(frame, state, lower_chunks[1]);

    // 5. Help Footer
    render_footer(frame, state, main_chunks[chunk_idx]);
}

fn render_header(frame: &mut Frame, state: &AppState, area: Rect) {
    let title_spans = vec![
        Span::styled(" MEGALODON ", Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw(" "),
        Span::styled(format!("Source: {} ", state.source_name), Style::default().fg(Color::Yellow)),
        Span::styled(format!("| Total: {} pkts ", state.packets.len()), Style::default().fg(Color::White)),
        if let Some(f) = &state.active_filter {
            Span::styled(format!("| Filter: [{}] ", f), Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))
        } else {
            Span::raw("")
        },
    ];

    let header_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Cyan));

    let paragraph = Paragraph::new(Line::from(title_spans)).block(header_block);
    frame.render_widget(paragraph, area);
}

fn render_filter_bar(frame: &mut Frame, state: &AppState, area: Rect) {
    let border_color = if state.filter_mode { Color::Green } else { Color::DarkGray };
    let prompt = if state.filter_mode {
        format!("Display Filter: {}█", state.filter_input)
    } else {
        format!("Display Filter: {} (Press '/' to edit, 'c' to clear)", state.active_filter.as_deref().unwrap_or(""))
    };

    let p = Paragraph::new(prompt)
        .style(Style::default().fg(if state.filter_mode { Color::White } else { Color::Gray }))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .title(" Filter ")
                .border_style(Style::default().fg(border_color)),
        );
    frame.render_widget(p, area);
}

fn protocol_color(proto: &str) -> Color {
    match proto.to_uppercase().as_str() {
        "TCP" => Color::Rgb(120, 180, 255),
        "UDP" | "DNS" | "MDNS" => Color::Rgb(80, 230, 230),
        "HTTP" | "HTTPS" | "TLS" | "SSL" => Color::Rgb(100, 240, 140),
        "ICMP" | "ARP" => Color::Rgb(245, 215, 80),
        "TELNET" | "SSH" => Color::Rgb(230, 140, 255),
        "RST" | "ERROR" => Color::Rgb(255, 90, 90),
        _ => Color::White,
    }
}

fn render_packet_table(frame: &mut Frame, state: &AppState, area: Rect) {
    let is_active = state.active_pane == ActivePane::Packets;
    let border_style = if is_active {
        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let header_cells = ["No.", "Time", "Source", "Destination", "Proto", "Len", "Info"]
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)));
    let header = Row::new(header_cells).height(1).bottom_margin(0);

    let rows_count = area.height.saturating_sub(3) as usize;
    let total_pkts = state.packets.len();

    // Scroll calculations so selected packet is visible
    let start_idx = if total_pkts == 0 || rows_count == 0 {
        0
    } else if state.selected_packet >= rows_count {
        state.selected_packet - rows_count + 1
    } else {
        0
    };
    let end_idx = (start_idx + rows_count).min(total_pkts);

    let mut rows = Vec::new();
    for (i, p) in state.packets.iter().enumerate().skip(start_idx).take(end_idx - start_idx) {
        let is_selected = i == state.selected_packet;
        let color = protocol_color(&p.protocol);

        let row_style = if is_selected {
            Style::default().bg(Color::Rgb(40, 50, 75)).fg(Color::White).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(color)
        };

        let prefix = if is_selected { "> " } else { "  " };

        let cells = vec![
            Cell::from(format!("{}{}", prefix, p.number)),
            Cell::from(p.time.clone()),
            Cell::from(p.source.clone()),
            Cell::from(p.destination.clone()),
            Cell::from(p.protocol.clone()),
            Cell::from(p.length.clone()),
            Cell::from(p.info.clone()),
        ];

        rows.push(Row::new(cells).style(row_style));
    }

    let widths = [
        Constraint::Length(8),
        Constraint::Length(12),
        Constraint::Length(22),
        Constraint::Length(22),
        Constraint::Length(8),
        Constraint::Length(7),
        Constraint::Min(20),
    ];

    let title = format!(" Packets [{}/{}] ", if total_pkts > 0 { state.selected_packet + 1 } else { 0 }, total_pkts);
    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .title(title)
                .border_style(border_style),
        );

    frame.render_widget(table, area);
}

fn render_layer_tree(frame: &mut Frame, state: &AppState, area: Rect) {
    let is_active = state.active_pane == ActivePane::Layers;
    let border_style = if is_active {
        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let title = " Protocol Tree ";
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .title(title)
        .border_style(border_style);

    let inner_height = area.height.saturating_sub(2) as usize;

    let mut lines = Vec::new();
    if let Some(detail) = &state.current_detail {
        let total_layers = detail.layers.len();
        let start_idx = if total_layers == 0 || inner_height == 0 {
            0
        } else if state.selected_layer >= inner_height {
            state.selected_layer - inner_height + 1
        } else {
            0
        };
        let end_idx = (start_idx + inner_height).min(total_layers);

        for (i, layer) in detail.layers.iter().enumerate().skip(start_idx).take(end_idx - start_idx) {
            let is_selected = is_active && i == state.selected_layer;

            let (style, prefix) = if layer.is_header {
                (
                    Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                    "[-] ",
                )
            } else {
                (
                    Style::default().fg(Color::Rgb(200, 200, 210)),
                    "    ",
                )
            };

            let row_style = if is_selected {
                Style::default().bg(Color::Rgb(50, 60, 90)).fg(Color::White).add_modifier(Modifier::BOLD)
            } else {
                style
            };

            let line_text = format!("{}{}", prefix, layer.title);
            lines.push(Line::from(vec![Span::styled(line_text, row_style)]));
        }
    } else {
        lines.push(Line::from(Span::styled("No packet selected", Style::default().fg(Color::DarkGray))));
    }

    let p = Paragraph::new(lines).block(block);
    frame.render_widget(p, area);
}

fn render_hex_dump(frame: &mut Frame, state: &AppState, area: Rect) {
    let is_active = state.active_pane == ActivePane::Hex;
    let border_style = if is_active {
        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let title = " Hex Dump ";
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .title(title)
        .border_style(border_style);

    let inner_height = area.height.saturating_sub(2) as usize;

    let mut lines = Vec::new();
    if let Some(detail) = &state.current_detail {
        let rows = format_hex_dump(&detail.raw_bytes);
        let total_rows = rows.len();

        let start_idx = state.hex_scroll.min(total_rows.saturating_sub(1));
        let end_idx = (start_idx + inner_height).min(total_rows);

        for (offset, hex, ascii) in rows.into_iter().skip(start_idx).take(end_idx - start_idx) {
            let line = Line::from(vec![
                Span::styled(format!("{}:  ", offset), Style::default().fg(Color::DarkGray)),
                Span::styled(format!("{}  ", hex), Style::default().fg(Color::Cyan)),
                Span::styled(format!("|{}|", ascii), Style::default().fg(Color::Green)),
            ]);
            lines.push(line);
        }
    } else {
        lines.push(Line::from(Span::styled("No packet data", Style::default().fg(Color::DarkGray))));
    }

    let p = Paragraph::new(lines).block(block);
    frame.render_widget(p, area);
}

fn render_footer(frame: &mut Frame, state: &AppState, area: Rect) {
    let help_spans = if let Some(msg) = &state.status_msg {
        vec![
            Span::styled(" MSG: ", Style::default().bg(Color::Red).fg(Color::White).add_modifier(Modifier::BOLD)),
            Span::raw(" "),
            Span::styled(msg, Style::default().fg(Color::Yellow)),
        ]
    } else {
        vec![
            Span::styled(" [Tab] ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw("Switch Pane  "),
            Span::styled(" [j/k] ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw("Navigate  "),
            Span::styled(" [/] ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw("Filter  "),
            Span::styled(" [c] ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw("Clear Filter  "),
            Span::styled(" [PgUp/PgDn] ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw("Jump  "),
            Span::styled(" [q] ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw("Quit"),
        ]
    };

    let p = Paragraph::new(Line::from(help_spans));
    frame.render_widget(p, area);
}
