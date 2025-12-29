use crate::cli::ProgressMode;
use crate::schema::{Event, EventListener, EventType};
use std::cell::RefCell;
use std::io::{self, Write};
use std::rc::Rc;

pub struct ProgressConfig {
    pub mode: ProgressMode,
    pub is_tty: bool,
}

impl ProgressConfig {
    fn enabled(&self) -> bool {
        match self.mode {
            ProgressMode::Never => false,
            ProgressMode::Always => true,
            ProgressMode::Auto => self.is_tty,
        }
    }
}

pub struct ProgressDriver {
    inner: Option<Rc<RefCell<ProgressRenderer>>>,
}

impl ProgressDriver {
    pub fn new(config: ProgressConfig) -> Self {
        if config.enabled() {
            let renderer = ProgressRenderer::new(config.is_tty);
            Self {
                inner: Some(Rc::new(RefCell::new(renderer))),
            }
        } else {
            Self { inner: None }
        }
    }

    pub fn listener(&self) -> Option<EventListener> {
        self.inner.as_ref().map(|inner| {
            let inner = inner.clone();
            Box::new(move |event: &Event| {
                if let Ok(mut renderer) = inner.try_borrow_mut() {
                    renderer.handle_event(event);
                }
            }) as EventListener
        })
    }

    pub fn finish(&self) {
        if let Some(inner) = &self.inner
            && let Ok(mut renderer) = inner.try_borrow_mut()
        {
            renderer.finish();
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.inner.is_some()
    }
}

struct ProgressRenderer {
    is_tty: bool,
    spinner_index: usize,
    last_message: Option<String>,
    last_progress: Option<u8>,
    rendered: bool,
}

impl ProgressRenderer {
    fn new(is_tty: bool) -> Self {
        Self {
            is_tty,
            spinner_index: 0,
            last_message: None,
            last_progress: None,
            rendered: false,
        }
    }

    fn handle_event(&mut self, event: &Event) {
        if let Some(update) = ProgressUpdate::from_event(event) {
            self.last_message = Some(update.message);
            if update.progress.is_some() {
                self.last_progress = update.progress;
            }
            self.render();
        }
    }

    fn render(&mut self) {
        let message = self
            .last_message
            .as_deref()
            .unwrap_or("Working on tasks...");
        let spinner = SPINNER_FRAMES[self.spinner_index % SPINNER_FRAMES.len()];
        self.spinner_index = (self.spinner_index + 1) % SPINNER_FRAMES.len();

        let mut line = format!("{spinner} {message}");
        if let Some(progress) = self.last_progress {
            line.push_str(&format!(" [{progress}%]"));
        }

        let mut stderr = io::stderr();
        if self.is_tty {
            let _ = write!(stderr, "\r\x1b[2K{line}");
            let _ = stderr.flush();
        } else {
            let _ = writeln!(stderr, "{line}");
        }
        self.rendered = true;
    }

    fn finish(&mut self) {
        if !self.rendered {
            return;
        }
        let message = self
            .last_message
            .as_deref()
            .unwrap_or("Done processing tasks");
        let mut stderr = io::stderr();
        if self.is_tty {
            let _ = write!(stderr, "\r\x1b[2K[done] {message}");
        } else {
            let _ = write!(stderr, "[done] {message}");
        }
        if let Some(progress) = self.last_progress {
            let _ = write!(stderr, " [{progress}%]");
        }
        let _ = writeln!(stderr);
        let _ = stderr.flush();
        self.rendered = false;
    }
}

struct ProgressUpdate {
    message: String,
    progress: Option<u8>,
}

impl ProgressUpdate {
    fn new(message: impl Into<String>, progress: Option<u8>) -> Self {
        Self {
            message: message.into(),
            progress: progress.map(|p| p.min(100)),
        }
    }

    fn from_event(event: &Event) -> Option<Self> {
        match event.event_type {
            EventType::ResolveStart => Some(Self::new("Resolving dependencies", Some(5))),
            EventType::ResolveComplete => Some(Self::new(
                event.message.as_deref().unwrap_or("Resolved dependencies"),
                event.progress.or(Some(30)),
            )),
            EventType::DownloadStart | EventType::DownloadProgress => Some(Self::new(
                event.message.as_deref().unwrap_or("Downloading artifacts"),
                event.progress.or(Some(50)),
            )),
            EventType::DownloadComplete => Some(Self::new(
                event.message.as_deref().unwrap_or("Downloaded artifacts"),
                event.progress.or(Some(70)),
            )),
            EventType::InstallStart => Some(Self::new(
                event.message.as_deref().unwrap_or("Installing packages"),
                event.progress.or(Some(80)),
            )),
            EventType::InstallComplete => {
                Some(Self::new("Install complete", event.progress.or(Some(100))))
            }
            EventType::ExtractStart => Some(Self::new("Extracting artifacts", Some(60))),
            EventType::ExtractComplete => Some(Self::new("Extracted artifacts", Some(65))),
            EventType::ScriptStart => Some(Self::new("Running script", Some(40))),
            EventType::ScriptEnd => Some(Self::new("Script finished", Some(100))),
            EventType::TestStart => Some(Self::new("Running tests", Some(30))),
            EventType::TestComplete => Some(Self::new("Tests finished", Some(100))),
            EventType::Progress => Some(Self::new(
                event.message.as_deref().unwrap_or("Working..."),
                event.progress,
            )),
            EventType::CommandEnd => Some(Self::new("Finished", Some(100))),
            _ => None,
        }
    }
}

const SPINNER_FRAMES: &[&str] = &["-", "\\", "|", "/"];
