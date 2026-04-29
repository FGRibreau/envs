//! `EnvsAppDelegate` — main thread NSObject subclass that owns NSWindow,
//! NSStatusItem, and the active list of pending requests.
//!
//! Built via `declare_class!` macro from objc2 0.5. Action methods are
//! exposed as Objective-C selectors so NSButton/NSStatusItem can target them.

#![cfg(target_os = "macos")]

use envs_proto::{Binding, GrantScope, HelperReply, ProfileTarget, PromptRequest};
use objc2::declare_class;
use objc2::msg_send;
use objc2::msg_send_id;
use objc2::mutability;
use objc2::rc::Retained;
use objc2::{sel, ClassType, DeclaredClass};
use objc2_app_kit::{
    NSApplication, NSButton, NSStackView, NSStatusBar, NSStatusItem, NSVariableStatusItemLength,
    NSWindow, NSWindowStyleMask,
};
use objc2_foundation::{
    MainThreadMarker, NSEdgeInsets, NSObject, NSPoint, NSRect, NSSize, NSString, NSTimer,
};
use std::cell::RefCell;
use std::sync::Arc;
use std::sync::Mutex;

/// Per-tab UI state: the request, user's checkbox/scope/duration choices,
/// and the controls so we can read their state when the user clicks Authorize.
pub struct TabState {
    pub request: PromptRequest,
    /// User's binding choices (env_var → enabled).
    pub binding_checked: Vec<bool>,
    /// Available bindings (computed from suggestions + current_profile).
    pub bindings: Vec<Binding>,
    /// Scope choice: 0 = Any, 1 = ExactArgv.
    pub scope_choice: usize,
    /// Duration choice index into [60, 300, 1800, 3600] seconds.
    pub duration_choice: usize,
    /// Save-as-profile target: 0 = Project (if available), 1 = Global.
    pub save_target_choice: usize,
}

const DURATION_CHOICES: &[(&str, u64)] = &[
    ("1 minute", 60),
    ("5 minutes", 300),
    ("30 minutes", 1800),
    ("1 hour", 3600),
];

/// Shared state: events from background thread to drain on each NSTimer tick,
/// and replies from the main thread to write to stdout.
pub struct SharedQueues {
    pub incoming: Mutex<std::collections::VecDeque<envs_proto::HelperEvent>>,
    pub outgoing: Mutex<std::collections::VecDeque<HelperReply>>,
}

impl SharedQueues {
    pub fn new() -> Self {
        Self {
            incoming: Mutex::new(std::collections::VecDeque::new()),
            outgoing: Mutex::new(std::collections::VecDeque::new()),
        }
    }
}

/// Ivars stored on the AppDelegate Objective-C instance.
/// All mutation goes through interior mutability since `declare_class!` only
/// gives `&self` access in method handlers.
pub struct Ivars {
    pub queues: Arc<SharedQueues>,
    pub window: RefCell<Option<Retained<NSWindow>>>,
    pub status_item: RefCell<Option<Retained<NSStatusItem>>>,
    pub tabs: RefCell<Vec<TabState>>,
    pub active_tab: RefCell<usize>,
    /// Container for the currently rendered tab's content view (so we can swap).
    pub content_holder: RefCell<Option<Retained<NSStackView>>>,
    /// References to interactive controls of the current tab, indexed in this order:
    ///   [0..N] = binding checkboxes (one per binding)
    ///   [N] = scope NSPopUpButton (Any/ExactArgv)
    ///   [N+1] = duration NSPopUpButton (1m/5m/30m/1h)
    ///   [N+2] = save-target NSPopUpButton (Project/Global)
    /// Cleared and rebuilt each time we switch tabs.
    pub current_controls: RefCell<Vec<Retained<NSObject>>>,
}

declare_class!(
    pub struct EnvsAppDelegate;

    unsafe impl ClassType for EnvsAppDelegate {
        type Super = NSObject;
        type Mutability = mutability::MainThreadOnly;
        const NAME: &'static str = "EnvsAppDelegate";
    }

    impl DeclaredClass for EnvsAppDelegate {
        type Ivars = Ivars;
    }

    unsafe impl EnvsAppDelegate {
        /// NSTimer callback: drains the incoming event queue, dispatches each
        /// event. Runs on the main thread (NSTimer is scheduled on the main
        /// run loop).
        #[method(drainEvents:)]
        fn drain_events(&self, _timer: *mut NSObject) {
            let events: Vec<envs_proto::HelperEvent> = {
                let mut q = self.ivars().queues.incoming.lock().expect("queue lock");
                q.drain(..).collect()
            };
            for ev in events {
                self.handle_event(ev);
            }
        }

        /// User clicked the NSStatusItem button: toggle window visibility.
        #[method(statusItemClicked:)]
        fn status_item_clicked(&self, _sender: *mut NSObject) {
            self.toggle_window();
        }

        /// User clicked the "Authorize via TouchID" button: read current tab
        /// controls, run LAContext, send Authorized or Cancelled reply.
        #[method(authorizeClicked:)]
        fn authorize_clicked(&self, _sender: *mut NSButton) {
            self.handle_authorize();
        }

        /// User clicked "Cancel": send Cancelled reply for current tab.
        #[method(cancelClicked:)]
        fn cancel_clicked(&self, _sender: *mut NSButton) {
            self.handle_cancel();
        }

        /// User clicked a tab in the side list: switch active tab.
        #[method(tabClicked:)]
        fn tab_clicked(&self, sender: *mut NSButton) {
            self.handle_tab_click(sender);
        }
    }
);

impl EnvsAppDelegate {
    /// Construct a new instance. Must be called on the main thread.
    pub fn new(mtm: MainThreadMarker, queues: Arc<SharedQueues>) -> Retained<Self> {
        let ivars = Ivars {
            queues,
            window: RefCell::new(None),
            status_item: RefCell::new(None),
            tabs: RefCell::new(Vec::new()),
            active_tab: RefCell::new(0),
            content_holder: RefCell::new(None),
            current_controls: RefCell::new(Vec::new()),
        };
        let alloc = mtm.alloc::<Self>();
        let obj = alloc.set_ivars(ivars);
        unsafe { msg_send_id![super(obj), init] }
    }

    pub fn install_status_item(&self, mtm: MainThreadMarker) {
        let bar = unsafe { NSStatusBar::systemStatusBar() };
        let item = unsafe { bar.statusItemWithLength(NSVariableStatusItemLength) };
        // Wire the button's action to selector statusItemClicked:
        if let Some(button) = unsafe { item.button(mtm) } {
            unsafe {
                button.setTitle(&NSString::from_str("envs"));
                button.setTarget(Some(self));
                button.setAction(Some(sel!(statusItemClicked:)));
            }
        }
        *self.ivars().status_item.borrow_mut() = Some(item);
    }

    pub fn install_window(&self, mtm: MainThreadMarker) {
        let frame = NSRect::new(NSPoint::new(200.0, 200.0), NSSize::new(720.0, 480.0));
        let style = NSWindowStyleMask::Titled
            | NSWindowStyleMask::Closable
            | NSWindowStyleMask::Miniaturizable
            | NSWindowStyleMask::Resizable;
        let win = unsafe {
            NSWindow::initWithContentRect_styleMask_backing_defer(
                mtm.alloc::<NSWindow>(),
                frame,
                style,
                objc2_app_kit::NSBackingStoreType::NSBackingStoreBuffered,
                false,
            )
        };
        unsafe {
            win.setTitle(&NSString::from_str("envs — authorize secret access"));
            win.setReleasedWhenClosed(false);
        }
        *self.ivars().window.borrow_mut() = Some(win);
    }

    pub fn schedule_drain_timer(&self, mtm: MainThreadMarker) {
        // 50ms drain interval — fast enough for snappy UI, light enough on CPU
        let _ = mtm; // unused but reminds us that NSTimer must be scheduled on main run loop
        let _: () = unsafe {
            let _timer = NSTimer::scheduledTimerWithTimeInterval_target_selector_userInfo_repeats(
                0.05,
                self,
                sel!(drainEvents:),
                None,
                true,
            );
        };
    }

    fn handle_event(&self, event: envs_proto::HelperEvent) {
        use envs_proto::HelperEvent;
        match event {
            HelperEvent::NewRequest(req) => {
                let bindings = bindings_from_request(&req);
                if bindings.is_empty() {
                    self.send_reply(HelperReply::Cancelled {
                        request_id: req.request_id,
                    });
                    return;
                }
                let binding_checked = vec![true; bindings.len()];
                let scope_choice = if is_system_binary(&req.canon_path) {
                    1
                } else {
                    0
                };
                let save_target_choice = if req.project_root.is_some() { 0 } else { 1 };
                let tab = TabState {
                    request: req,
                    bindings,
                    binding_checked,
                    scope_choice,
                    duration_choice: 1, // 5 minutes
                    save_target_choice,
                };
                self.ivars().tabs.borrow_mut().push(tab);
                self.refresh_status_title();
                self.rebuild_window_content();
                self.show_window();
            }
            HelperEvent::CancelRequest { request_id } => {
                let mut tabs = self.ivars().tabs.borrow_mut();
                tabs.retain(|t| t.request.request_id != request_id);
                drop(tabs);
                self.refresh_status_title();
                self.rebuild_window_content();
                if self.ivars().tabs.borrow().is_empty() {
                    self.hide_window();
                }
            }
            HelperEvent::PendingCountChanged { count: _ } => {
                // The status title reflects our own tab list, not external count.
                // This event is informational only at the helper level.
                self.refresh_status_title();
            }
            HelperEvent::Shutdown => {
                let mtm = MainThreadMarker::from(self);
                let app = NSApplication::sharedApplication(mtm);
                unsafe { app.terminate(None) };
            }
        }
    }

    fn refresh_status_title(&self) {
        let n = self.ivars().tabs.borrow().len();
        let title = if n == 0 {
            String::from("envs")
        } else {
            format!("envs ({n})")
        };
        let item = self.ivars().status_item.borrow();
        if let Some(item) = item.as_deref() {
            let mtm = MainThreadMarker::from(self);
            if let Some(btn) = unsafe { item.button(mtm) } {
                let s = NSString::from_str(&title);
                unsafe { btn.setTitle(&s) };
            }
        }
    }

    fn show_window(&self) {
        let win = self.ivars().window.borrow();
        if let Some(win) = win.as_deref() {
            win.makeKeyAndOrderFront(None);
            let mtm = MainThreadMarker::from(self);
            let app = NSApplication::sharedApplication(mtm);
            // macOS 14+ replacement for `activateIgnoringOtherApps:` (deprecated).
            // objc2-app-kit 0.2.2 doesn't expose the new `activate` selector via the
            // bindings, so we send it via raw msg_send. The new method takes no args
            // and behaves like ignoringOtherApps:YES.
            unsafe {
                let _: () = msg_send![&*app, activate];
            }
        }
    }

    fn hide_window(&self) {
        let win = self.ivars().window.borrow();
        if let Some(win) = win.as_deref() {
            unsafe { win.orderOut(None) };
        }
    }

    fn toggle_window(&self) {
        let visible = {
            let win = self.ivars().window.borrow();
            win.as_deref()
                .map(|w| unsafe { w.isVisible() })
                .unwrap_or(false)
        };
        if visible {
            self.hide_window();
        } else if !self.ivars().tabs.borrow().is_empty() {
            self.show_window();
        }
    }

    fn rebuild_window_content(&self) {
        // Layout (Lulu-style "side tabs"):
        //
        //   ┌────────────────┬─────────────────────────────────────────┐
        //   │ ● flarectl     │ Authorize flarectl zone list            │
        //   │   wrangler     │ Path: /opt/homebrew/bin/flarectl        │
        //   │   curl         │ Project: ~/www/image-charts             │
        //   │                │                                         │
        //   │                │ Inject env vars:                        │
        //   │                │   ☑ CF_API_TOKEN ← rbw://...            │
        //   │                │   ☑ CF_ACCOUNT_ID ← rbw://...           │
        //   │                │ Scope:    [Any flarectl ▼]              │
        //   │                │ Duration: [5 min ▼]                     │
        //   │                │ Save as:  [Project ▼]                   │
        //   │                │                                         │
        //   │                │            [Cancel] [Authorize TouchID] │
        //   └────────────────┴─────────────────────────────────────────┘
        //
        // Implemented as a horizontal NSStackView with two children:
        //   - left: vertical NSStackView of tab NSButtons (always visible,
        //     even when only 1 tab — gives a stable visual frame)
        //   - right: vertical NSStackView with the active tab's form
        //
        // We chose NSStackView vertical over NSTableView because NSTableView
        // requires implementing NSTableViewDataSource + NSTableViewDelegate
        // protocols on a separate NSObject (≈+200 LOC, marginal UX benefit
        // since our "rows" are just clickable buttons, not selectable cells
        // with custom rendering).
        let mtm = MainThreadMarker::from(self);
        let tabs = self.ivars().tabs.borrow();
        if tabs.is_empty() {
            return;
        }
        let active_idx = (*self.ivars().active_tab.borrow()).min(tabs.len() - 1);
        *self.ivars().active_tab.borrow_mut() = active_idx;
        let tab = &tabs[active_idx];

        let win = self.ivars().window.borrow();
        let Some(win) = win.as_deref() else { return };

        // Outer horizontal split: [tabs panel | content panel]
        let outer = unsafe { NSStackView::new(mtm) };
        unsafe {
            outer.setOrientation(objc2_app_kit::NSUserInterfaceLayoutOrientation::Horizontal);
            outer.setSpacing(0.0);
            outer.setAlignment(objc2_app_kit::NSLayoutAttribute::Top);
        }

        // Left side: tabs list (vertical NSStackView of buttons)
        let tabs_panel = unsafe { NSStackView::new(mtm) };
        unsafe {
            tabs_panel.setOrientation(objc2_app_kit::NSUserInterfaceLayoutOrientation::Vertical);
            tabs_panel.setSpacing(2.0);
            tabs_panel.setEdgeInsets(NSEdgeInsets {
                top: 12.0,
                left: 8.0,
                bottom: 12.0,
                right: 8.0,
            });
            tabs_panel.setAlignment(objc2_app_kit::NSLayoutAttribute::Leading);
        }
        for (i, t) in tabs.iter().enumerate() {
            let title = format!(
                "{}{}",
                if i == active_idx { "● " } else { "  " },
                t.request.binary_name
            );
            let btn = unsafe {
                NSButton::buttonWithTitle_target_action(
                    &NSString::from_str(&title),
                    Some(self),
                    Some(sel!(tabClicked:)),
                    mtm,
                )
            };
            unsafe {
                btn.setTag(i as isize);
            }
            unsafe { tabs_panel.addArrangedSubview(&btn) };
        }
        unsafe { outer.addArrangedSubview(&tabs_panel) };

        // Right side: content panel (vertical NSStackView with form). Rest of
        // the function adds its arranged subviews here. We bind it as `root`
        // to minimize the diff with the previous v0.6 layout.
        let root = unsafe { NSStackView::new(mtm) };
        unsafe {
            root.setOrientation(objc2_app_kit::NSUserInterfaceLayoutOrientation::Vertical);
            root.setSpacing(8.0);
            root.setEdgeInsets(NSEdgeInsets {
                top: 12.0,
                left: 16.0,
                bottom: 12.0,
                right: 12.0,
            });
            root.setAlignment(objc2_app_kit::NSLayoutAttribute::Leading);
        }
        unsafe { outer.addArrangedSubview(&root) };

        // Title
        let title_text = NSString::from_str(&format!(
            "Authorize {} {}",
            tab.request.binary_name,
            tab.request
                .argv
                .iter()
                .skip(1)
                .cloned()
                .collect::<Vec<_>>()
                .join(" ")
        ));
        let title_field = unsafe { objc2_app_kit::NSTextField::labelWithString(&title_text, mtm) };
        unsafe {
            let font = objc2_app_kit::NSFont::boldSystemFontOfSize(14.0);
            title_field.setFont(Some(&font));
        }
        unsafe { root.addArrangedSubview(&title_field) };

        // Path/Project info
        let info_lines = vec![
            format!("Path: {}", tab.request.canon_path.display()),
            tab.request
                .project_root
                .as_ref()
                .map(|p| format!("Project: {}", p.display()))
                .unwrap_or_else(|| String::from("Project: (none — global scope)")),
        ];
        for line in info_lines {
            let f = unsafe {
                objc2_app_kit::NSTextField::labelWithString(&NSString::from_str(&line), mtm)
            };
            unsafe { root.addArrangedSubview(&f) };
        }

        // Bindings header
        let h = unsafe {
            objc2_app_kit::NSTextField::labelWithString(
                &NSString::from_str("Inject env vars:"),
                mtm,
            )
        };
        unsafe { root.addArrangedSubview(&h) };

        // One NSButton (checkbox style) per binding
        let mut control_refs: Vec<Retained<NSObject>> = Vec::new();
        for (i, b) in tab.bindings.iter().enumerate() {
            let row = unsafe { NSStackView::new(mtm) };
            unsafe {
                row.setOrientation(objc2_app_kit::NSUserInterfaceLayoutOrientation::Horizontal);
                row.setSpacing(6.0);
            }
            let label = format!("{}  ←  {}", b.env, b.source);
            let cb = unsafe {
                NSButton::checkboxWithTitle_target_action(
                    &NSString::from_str(&label),
                    None,
                    None,
                    mtm,
                )
            };
            // NSControlStateValue is a type alias for isize; 1=on, 0=off
            let state: objc2_app_kit::NSControlStateValue =
                if tab.binding_checked[i] { 1 } else { 0 };
            unsafe { cb.setState(state) };
            unsafe { row.addArrangedSubview(&cb) };
            control_refs.push(unsafe { Retained::cast(cb) });
            unsafe { root.addArrangedSubview(&row) };
        }

        // Scope NSPopUpButton
        let scope_label = unsafe {
            objc2_app_kit::NSTextField::labelWithString(&NSString::from_str("Scope:"), mtm)
        };
        unsafe { root.addArrangedSubview(&scope_label) };
        let scope_popup = unsafe { objc2_app_kit::NSPopUpButton::new(mtm) };
        unsafe {
            scope_popup.addItemWithTitle(&NSString::from_str(&format!(
                "Any invocation of {}",
                tab.request.binary_name
            )));
            scope_popup.addItemWithTitle(&NSString::from_str(&format!("Only this exact command",)));
            scope_popup.selectItemAtIndex(tab.scope_choice as isize);
        }
        unsafe { root.addArrangedSubview(&scope_popup) };
        control_refs.push(unsafe { Retained::cast(scope_popup) });

        // Duration NSPopUpButton
        let dur_label = unsafe {
            objc2_app_kit::NSTextField::labelWithString(&NSString::from_str("Duration:"), mtm)
        };
        unsafe { root.addArrangedSubview(&dur_label) };
        let dur_popup = unsafe { objc2_app_kit::NSPopUpButton::new(mtm) };
        for (label, _) in DURATION_CHOICES {
            unsafe { dur_popup.addItemWithTitle(&NSString::from_str(label)) };
        }
        unsafe { dur_popup.selectItemAtIndex(tab.duration_choice as isize) };
        unsafe { root.addArrangedSubview(&dur_popup) };
        control_refs.push(unsafe { Retained::cast(dur_popup) });

        // Save-as-profile NSPopUpButton
        let save_label = unsafe {
            objc2_app_kit::NSTextField::labelWithString(
                &NSString::from_str("Save as profile:"),
                mtm,
            )
        };
        unsafe { root.addArrangedSubview(&save_label) };
        let save_popup = unsafe { objc2_app_kit::NSPopUpButton::new(mtm) };
        let project_label = tab
            .request
            .project_root
            .as_ref()
            .map(|p| format!("Project ({})", p.display()))
            .unwrap_or_else(|| String::from("Project (n/a — no .envs/ detected)"));
        unsafe {
            save_popup.addItemWithTitle(&NSString::from_str(&project_label));
            save_popup.addItemWithTitle(&NSString::from_str("Global (~/.envs/profiles/)"));
            save_popup.selectItemAtIndex(tab.save_target_choice as isize);
        }
        unsafe { root.addArrangedSubview(&save_popup) };
        control_refs.push(unsafe { Retained::cast(save_popup) });

        // Buttons row: Cancel + Authorize
        let buttons_row = unsafe { NSStackView::new(mtm) };
        unsafe {
            buttons_row.setOrientation(objc2_app_kit::NSUserInterfaceLayoutOrientation::Horizontal);
            buttons_row.setSpacing(8.0);
        }
        let cancel_btn = unsafe {
            NSButton::buttonWithTitle_target_action(
                &NSString::from_str("Cancel"),
                Some(self),
                Some(sel!(cancelClicked:)),
                mtm,
            )
        };
        let authorize_btn = unsafe {
            NSButton::buttonWithTitle_target_action(
                &NSString::from_str("Authorize via TouchID"),
                Some(self),
                Some(sel!(authorizeClicked:)),
                mtm,
            )
        };
        unsafe {
            authorize_btn.setKeyEquivalent(&NSString::from_str("\r"));
            buttons_row.addArrangedSubview(&cancel_btn);
            buttons_row.addArrangedSubview(&authorize_btn);
            root.addArrangedSubview(&buttons_row);
        }

        // Set the OUTER horizontal split as window contentView (it contains
        // both the tabs panel on the left and the form panel on the right).
        win.setContentView(Some(&outer));
        *self.ivars().content_holder.borrow_mut() = Some(outer);
        *self.ivars().current_controls.borrow_mut() = control_refs;
    }

    fn handle_tab_click(&self, sender: *mut NSButton) {
        if sender.is_null() {
            return;
        }
        let tag = unsafe { (*sender).tag() };
        let tabs_len = self.ivars().tabs.borrow().len();
        if tag >= 0 && (tag as usize) < tabs_len {
            *self.ivars().active_tab.borrow_mut() = tag as usize;
            self.rebuild_window_content();
        }
    }

    /// Read the current tab's controls into the TabState before producing reply.
    fn read_current_controls(&self) {
        let active = *self.ivars().active_tab.borrow();
        let controls = self.ivars().current_controls.borrow();
        let mut tabs = self.ivars().tabs.borrow_mut();
        let Some(tab) = tabs.get_mut(active) else {
            return;
        };
        let n_bindings = tab.bindings.len();
        if controls.len() < n_bindings + 3 {
            return;
        }
        // Read checkboxes
        for (i, ctrl) in controls.iter().take(n_bindings).enumerate() {
            // Cast to NSButton, get state
            let btn: &NSButton = unsafe { &*(ctrl.as_ref() as *const NSObject as *const NSButton) };
            let state = unsafe { btn.state() };
            tab.binding_checked[i] = state != 0;
        }
        // Read scope popup
        let scope: &objc2_app_kit::NSPopUpButton = unsafe {
            &*(controls[n_bindings].as_ref() as *const NSObject
                as *const objc2_app_kit::NSPopUpButton)
        };
        let scope_idx = unsafe { scope.indexOfSelectedItem() };
        if scope_idx >= 0 {
            tab.scope_choice = scope_idx as usize;
        }
        // Read duration popup
        let dur: &objc2_app_kit::NSPopUpButton = unsafe {
            &*(controls[n_bindings + 1].as_ref() as *const NSObject
                as *const objc2_app_kit::NSPopUpButton)
        };
        let dur_idx = unsafe { dur.indexOfSelectedItem() };
        if dur_idx >= 0 {
            tab.duration_choice = dur_idx as usize;
        }
        // Read save target popup
        let save: &objc2_app_kit::NSPopUpButton = unsafe {
            &*(controls[n_bindings + 2].as_ref() as *const NSObject
                as *const objc2_app_kit::NSPopUpButton)
        };
        let save_idx = unsafe { save.indexOfSelectedItem() };
        if save_idx >= 0 {
            tab.save_target_choice = save_idx as usize;
        }
    }

    fn handle_authorize(&self) {
        self.read_current_controls();
        let active = *self.ivars().active_tab.borrow();
        let tab_snapshot = {
            let tabs = self.ivars().tabs.borrow();
            tabs.get(active).map(|t| {
                (
                    t.request.request_id.clone(),
                    t.request.argv.clone(),
                    t.request.canon_path.clone(),
                    t.request.project_root.clone(),
                    t.binding_checked.clone(),
                    t.bindings.clone(),
                    t.scope_choice,
                    t.duration_choice,
                    t.save_target_choice,
                )
            })
        };
        let Some((
            request_id,
            argv,
            canon_path,
            project_root,
            binding_checked,
            bindings,
            scope_choice,
            duration_choice,
            save_target_choice,
        )) = tab_snapshot
        else {
            return;
        };

        // Filter bindings by checkbox state
        let selected: Vec<Binding> = bindings
            .iter()
            .zip(binding_checked.iter())
            .filter(|(_, &checked)| checked)
            .map(|(b, _)| b.clone())
            .collect();
        if selected.is_empty() {
            // User unchecked everything → treat as cancel for this tab
            self.complete_tab(active, HelperReply::Cancelled { request_id });
            return;
        }

        // Run TouchID. This blocks the main thread (LAContext.evaluatePolicy
        // returns asynchronously but our wrapper blocks via channel).
        let reason = format!(
            "Authorize {} to receive {} for {}",
            canon_path
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default(),
            selected
                .iter()
                .map(|b| b.env.as_str())
                .collect::<Vec<_>>()
                .join(", "),
            DURATION_CHOICES[duration_choice].0
        );
        let touchid_ok = match crate::auth::prompt_biometric(&reason) {
            Ok(ok) => ok,
            Err(e) => {
                self.complete_tab(
                    active,
                    HelperReply::Error {
                        request_id,
                        message: e,
                    },
                );
                return;
            }
        };
        if !touchid_ok {
            self.complete_tab(active, HelperReply::Cancelled { request_id });
            return;
        }

        let scope = if scope_choice == 1 {
            GrantScope::ExactArgv { argv }
        } else {
            GrantScope::Any
        };
        let ttl_secs = DURATION_CHOICES[duration_choice].1;
        let save_as_profile = match save_target_choice {
            0 if project_root.is_some() => Some(ProfileTarget::Project),
            _ => Some(ProfileTarget::Global),
        };

        self.complete_tab(
            active,
            HelperReply::Authorized {
                request_id,
                bindings: selected,
                scope,
                ttl_secs,
                save_as_profile,
            },
        );
    }

    fn handle_cancel(&self) {
        let active = *self.ivars().active_tab.borrow();
        let request_id = {
            let tabs = self.ivars().tabs.borrow();
            tabs.get(active).map(|t| t.request.request_id.clone())
        };
        if let Some(id) = request_id {
            self.complete_tab(active, HelperReply::Cancelled { request_id: id });
        }
    }

    fn complete_tab(&self, idx: usize, reply: HelperReply) {
        self.send_reply(reply);
        self.ivars().tabs.borrow_mut().remove(idx);
        // Reset active to 0
        *self.ivars().active_tab.borrow_mut() = 0;
        let now_empty = self.ivars().tabs.borrow().is_empty();
        self.refresh_status_title();
        if now_empty {
            self.hide_window();
        } else {
            self.rebuild_window_content();
        }
    }

    fn send_reply(&self, reply: HelperReply) {
        if let Ok(mut q) = self.ivars().queues.outgoing.lock() {
            q.push_back(reply);
        }
    }
}

fn bindings_from_request(req: &PromptRequest) -> Vec<Binding> {
    if !req.suggested_bindings.is_empty() {
        req.suggested_bindings
            .iter()
            .map(|s| Binding {
                env: s.env.clone(),
                source: s.source.clone(),
            })
            .collect()
    } else if let Some(profile) = &req.current_profile {
        profile.bindings.clone()
    } else {
        Vec::new()
    }
}

fn is_system_binary(path: &std::path::Path) -> bool {
    let s = path.to_string_lossy();
    ["/usr/bin/", "/bin/", "/sbin/", "/usr/sbin/", "/System/"]
        .iter()
        .any(|p| s.starts_with(p))
}

// Mark Sel as Send so it can be referenced statically in declare_class macro
unsafe impl Send for SharedQueues {}
unsafe impl Sync for SharedQueues {}
