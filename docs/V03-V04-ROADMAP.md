# v0.3 → v0.4 roadmap

## v0.3 ship status (this session)

| # | Feature | Status |
|---|---|---|
| 23 | Dogfood findings ISSUE-001 to ISSUE-007 (friendly error display, system-binary-aware helper, consistent daemon-down, error code mapping, message consistency) | ✅ Shipped |
| 24 | AppKit popup complet (NSWindow + tabs + checkboxes + radio + picker) | 📋 v0.4 (scope deferred — architecture below) |
| 25 | NSStatusBar menubar item with `(N pending)` badge | 📋 v0.4 (scope deferred — architecture below) |
| 26 | Codesign + notarize script (`scripts/codesign.sh`) + RELEASE.md | ✅ Shipped |

## Why #24 and #25 were deferred

Both features need an **NSApplication run loop on the main thread**. The current `envs-prompt` is a `#[tokio::main]` async app that owns the main thread for the tokio runtime, and reads stdin in a tokio task. AppKit's NSWindow event handling, NSStatusItem click handling, and NSAlert.runModal all require the main thread to be running NSApplication's CFRunLoop. Mixing tokio and AppKit on the same main thread requires significant refactor — not a one-session piece.

## v0.4 architecture (planned)

### Threading model

```
Main thread:                  Background thread (tokio runtime):
NSApplication.run() ←────┐   ┌──→ stdin reader
                         │   │     reads HelperEvent JSON
NSStatusItem (menubar) ──┤   │     sends to (main thread) via dispatch_main_async
                         │   │
NSWindow (popup)         │   └──→ HTTP client to envsd (poll /status)
NSAlert (confirmation) ──┤        sends pending_count update to main
                         │
LAContext.evaluatePolicy ┘
```

The `dispatch_main_async` (or its objc2 equivalent) is the bridge: background tokio threads send closures to be executed on the main thread, where AppKit lives.

### Implementation plan

#### Phase 4-A: refactor envs-prompt to NSApplication (~3-4 days)

1. Replace `#[tokio::main]` with manual main:
   ```rust
   fn main() {
       // 1. Initialize tokio Runtime (NOT current_thread, so it has its own threads)
       let runtime = tokio::runtime::Builder::new_multi_thread().build()?;

       // 2. Spawn stdin reader on tokio
       let (event_tx, event_rx) = tokio::sync::mpsc::channel::<HelperEvent>(32);
       runtime.spawn(stdin_reader(event_tx));

       // 3. Set up dispatch_main bridge: background thread polls event_rx,
       //    forwards each event to main thread via NSObject performSelectorOnMainThread.

       // 4. Initialize NSApplication on main thread, run() forever.
       unsafe {
           let app = NSApplication::shared();
           app.run();
       }
   }
   ```

2. Create `Delegate` NSObject (objc2 `declare_class!`) that holds:
   - NSStatusItem ref
   - Map<String, PromptRequest> for active tabs
   - Channel to send replies

3. Wire up button click handlers via `IBAction`-style methods (objc2 `extern_methods!`).

#### Phase 4-B: NSWindow popup with tabs (~2-3 days)

4. Build NSWindow with content view = NSStackView (horizontal):
   - Left: NSTableView with one row per pending request (click selects active tab)
   - Right: NSStackView (vertical) with the active request's form:
     - List of bindings as NSCheckButton (toggle to include/exclude)
     - "Add custom binding" button → opens NSPopover with text input + NSPopUpButton (vault item picker)
     - Scope: NSMatrix with 2 NSCells (radio): `Any <bin>` / `Only <bin> <argv>`
     - Duration: NSPopUpButton with [1m, 5m, 15m, 30m, 1h, 4h, 8h, 24h]
     - Save as profile: NSMatrix with 2 NSCells: `Project (<.envs/...>)` / `Global`
     - Bottom row: NSButton "Cancel" + NSButton "Authorize via TouchID" (primary)

5. The "Authorize" button click handler:
   - Disable button, show NSProgressIndicator
   - Spawn LAContext.evaluatePolicy on background thread
   - On success: build HelperReply::Authorized, send via channel back to daemon
   - On failure: re-enable button, show NSAlert error
   - Animate tab disappear (NSStackView animation), close window if last tab

6. Tab animation: NSStackView with `setVisibilityPriority` + animator proxy + `[NSAnimationContext runAnimationGroup:]`.

#### Phase 4-C: NSStatusItem menubar (~1 day)

7. NSStatusBar.systemStatusBar.statusItemWithLength: NSVariableStatusItemLength
8. Set image + title: empty when 0 pending, `[N]` when N > 0
9. Add menu (NSMenu) with items:
   - `(N pending)` (disabled label)
   - `Show pending requests` → bring NSWindow to front
   - separator
   - `Active rules: M` (disabled label, polls envsd /status periodically)
   - `Open envsd logs...` → opens audit.jsonl in Finder
   - separator
   - `Quit envs-prompt` → graceful shutdown

10. Update logic: timer fires every 1s on main thread, sends Status request to envsd via UDS, parses pending_count + rules_count, updates NSStatusItem.

### Risks & open questions

1. **objc2 `declare_class!` ergonomics**: defining a custom NSObject subclass with action methods, properties, and ivars requires careful unsafe code. Each method needs `extern "C"` and explicit argument types.

2. **AppKit thread-safety**: only the main thread can mutate NSWindow/NSView/NSControl. The tokio→main bridge MUST use `dispatch_main_async` or `NSObject performSelector:onThread:withObject:waitUntilDone:`.

3. **LAContext from NSAlert click**: blocking the main thread on LAContext is bad UX (UI freezes). Need to spawn LAContext on a background thread, hide the alert, show a NSProgressIndicator, then process the reply asynchronously.

4. **Multi-tab UX**: when a 2nd request arrives while the popup is open, animation must add the tab without disrupting in-progress data entry. Use NSStackView's animator.

5. **Drag/resize**: NSWindow needs to be resizable + remember its frame between sessions. Use NSWindow.setFrameAutosaveName.

### Estimate

- Phase 4-A (refactor): 3-4 days
- Phase 4-B (popup): 2-3 days
- Phase 4-C (menubar): 1 day
- Polish, animations, error states: 2 days
- **Total: 8-10 days of focused macOS-native dev**

Not feasible in a single session alongside other tasks. Phase 4 is its own milestone.

## What works in v0.3 (without #24/#25)

- Helper UI uses **LAContext direct prompt** (system-managed TouchID dialog)
- Bindings/scope/duration/profile-target are determined by stub helper logic:
  - Bindings: from registry → --help parsing → LLM (opt-in)
  - Scope: `ExactArgv` for system binaries, `Any` for user binaries
  - Duration: 5 min default
  - Save as profile: project-local if `.envs/` detected, global otherwise
- The user sees a system biometric dialog with a description string explaining what's being authorized (`"Authorize flarectl to receive CF_API_TOKEN, CF_ACCOUNT_ID in image-charts for 5 minutes"`)
- No menubar yet — the user has to run `envs audit show` or `envs rules list` manually to see active grants

This is a functional v0.3 that ships the security model end-to-end. The popup just isn't editable yet (user can't deselect a binding, change scope, change duration). v0.4 adds the rich UI.
