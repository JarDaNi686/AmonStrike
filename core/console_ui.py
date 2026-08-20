"""
AmonStrike — Real-Time Console Visualization
Split terminal view:
  LEFT  panel: Live scan progress + tool outputs
  RIGHT panel: Growing findings list (color coded by severity)
  BOTTOM panel: ASCII attack graph updating live

Like watching a hacker movie — but it is real.
"""

import os
import sys
import time
import threading
import curses
import json
import textwrap
from datetime import datetime
from collections import deque

# ── Severity colors (curses color pair IDs) ───────────────────
COLOR_CRITICAL = 1
COLOR_HIGH     = 2
COLOR_MEDIUM   = 3
COLOR_LOW      = 4
COLOR_INFO     = 5
COLOR_DIM      = 6
COLOR_WHITE    = 7
COLOR_GREEN    = 8
COLOR_CYAN     = 9
COLOR_YELLOW   = 10
COLOR_HEADER   = 11
COLOR_BORDER   = 12


class ConsoleUI:
    """
    Real-time split-pane terminal UI for AmonStrike.
    Thread-safe — updated from multiple scanner threads.
    """

    def __init__(self):
        self.running      = True
        self.lock         = threading.Lock()

        # Log buffer — left panel
        self.log_lines    = deque(maxlen=500)

        # Findings buffer — right panel
        self.findings     = deque(maxlen=200)

        # Graph nodes — bottom panel
        self.graph_nodes  = {}   # id → {type, value, children}
        self.scan_stats   = {
            "target":       "",
            "nodes":        0,
            "findings":     0,
            "dead_ends":    0,
            "tools_used":   set(),
            "start_time":   time.time(),
            "current_tool": "",
            "current_phase": "Initializing",
            "critical":     0,
            "high":         0,
            "medium":       0,
            "low":          0,
            "info":         0,
        }

        # Scroll positions
        self.log_scroll     = 0
        self.finding_scroll = 0

        # Screen dimensions (updated on resize)
        self.height = 0
        self.width  = 0

    # ── Public API (thread-safe) ──────────────────────────────

    def log(self, msg, level="*", tool=None):
        """Add a log line to the left panel."""
        ts = datetime.now().strftime("%H:%M:%S")
        with self.lock:
            self.log_lines.append({
                "ts":    ts,
                "msg":   msg,
                "level": level,
                "tool":  tool or "",
            })
            if tool:
                self.scan_stats["current_tool"] = tool

    def add_finding(self, title, severity, module="", url=""):
        """Add a finding to the right panel."""
        with self.lock:
            self.findings.append({
                "title":    title,
                "severity": severity.upper(),
                "module":   module,
                "url":      url,
                "time":     datetime.now().strftime("%H:%M:%S"),
            })
            sev = severity.upper()
            if sev == "CRITICAL": self.scan_stats["critical"] += 1
            elif sev == "HIGH":   self.scan_stats["high"] += 1
            elif sev == "MEDIUM": self.scan_stats["medium"] += 1
            elif sev == "LOW":    self.scan_stats["low"] += 1
            else:                 self.scan_stats["info"] += 1
            self.scan_stats["findings"] += 1

    def update_stats(self, **kwargs):
        """Update scan statistics."""
        with self.lock:
            for k, v in kwargs.items():
                if k in self.scan_stats:
                    if k == "tools_used" and isinstance(v, str):
                        self.scan_stats["tools_used"].add(v)
                    else:
                        self.scan_stats[k] = v

    def add_graph_node(self, node_id, node_type, value, parent_id=None):
        """Add a node to the attack graph."""
        with self.lock:
            self.graph_nodes[node_id] = {
                "type":   node_type,
                "value":  value[:40],
                "parent": parent_id,
            }
            self.scan_stats["nodes"] += 1

    def stop(self):
        """Stop the UI."""
        self.running = False

    # ── Curses rendering ──────────────────────────────────────

    def _init_colors(self):
        """Initialize color pairs."""
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(COLOR_CRITICAL, curses.COLOR_RED,     -1)
        curses.init_pair(COLOR_HIGH,     curses.COLOR_RED,     -1)
        curses.init_pair(COLOR_MEDIUM,   curses.COLOR_YELLOW,  -1)
        curses.init_pair(COLOR_LOW,      curses.COLOR_GREEN,   -1)
        curses.init_pair(COLOR_INFO,     curses.COLOR_CYAN,    -1)
        curses.init_pair(COLOR_DIM,      curses.COLOR_WHITE,   -1)
        curses.init_pair(COLOR_WHITE,    curses.COLOR_WHITE,   -1)
        curses.init_pair(COLOR_GREEN,    curses.COLOR_GREEN,   -1)
        curses.init_pair(COLOR_CYAN,     curses.COLOR_CYAN,    -1)
        curses.init_pair(COLOR_YELLOW,   curses.COLOR_YELLOW,  -1)
        curses.init_pair(COLOR_HEADER,   curses.COLOR_BLACK,   curses.COLOR_RED)
        curses.init_pair(COLOR_BORDER,   curses.COLOR_RED,     -1)

    def _severity_color(self, severity):
        """Map severity to color pair."""
        return {
            "CRITICAL": curses.color_pair(COLOR_CRITICAL) | curses.A_BOLD,
            "HIGH":     curses.color_pair(COLOR_HIGH) | curses.A_BOLD,
            "MEDIUM":   curses.color_pair(COLOR_MEDIUM),
            "LOW":      curses.color_pair(COLOR_LOW),
            "INFO":     curses.color_pair(COLOR_INFO),
        }.get(severity, curses.color_pair(COLOR_DIM))

    def _level_color(self, level):
        """Map log level to color."""
        return {
            "+": curses.color_pair(COLOR_GREEN)  | curses.A_BOLD,
            "!": curses.color_pair(COLOR_CRITICAL) | curses.A_BOLD,
            "~": curses.color_pair(COLOR_YELLOW),
            "i": curses.color_pair(COLOR_CYAN),
            "*": curses.color_pair(COLOR_DIM),
        }.get(level, curses.color_pair(COLOR_DIM))

    def _safe_addstr(self, win, y, x, text, attr=None):
        """Add string safely — ignore out-of-bounds."""
        try:
            h, w = win.getmaxyx()
            if y < 0 or y >= h or x < 0 or x >= w:
                return
            max_len = w - x - 1
            if max_len <= 0:
                return
            text = str(text)[:max_len]
            if attr is not None:
                win.addstr(y, x, text, attr)
            else:
                win.addstr(y, x, text)
        except curses.error:
            pass

    def _draw_border(self, win, title=""):
        """Draw a bordered box with optional title."""
        try:
            h, w = win.getmaxyx()
            win.border(
                curses.ACS_VLINE, curses.ACS_VLINE,
                curses.ACS_HLINE, curses.ACS_HLINE,
                curses.ACS_ULCORNER, curses.ACS_URCORNER,
                curses.ACS_LLCORNER, curses.ACS_LRCORNER
            )
            if title:
                self._safe_addstr(win, 0, 2,
                    f" {title} ",
                    curses.color_pair(COLOR_HEADER) | curses.A_BOLD)
        except curses.error:
            pass

    def _draw_header(self, stdscr):
        """Draw the top header bar."""
        h, w = stdscr.getmaxyx()
        elapsed = int(time.time() - self.scan_stats["start_time"])
        m, s = divmod(elapsed, 60)

        with self.lock:
            target  = self.scan_stats["target"][:30]
            phase   = self.scan_stats["current_phase"][:20]
            nodes   = self.scan_stats["nodes"]
            finds   = self.scan_stats["findings"]
            crit    = self.scan_stats["critical"]
            high    = self.scan_stats["high"]
            med     = self.scan_stats["medium"]
            tool    = self.scan_stats["current_tool"][:15]

        # Header background
        try:
            stdscr.attron(curses.color_pair(COLOR_HEADER) | curses.A_BOLD)
            stdscr.addstr(0, 0, " " * (w - 1))
            stdscr.attroff(curses.color_pair(COLOR_HEADER) | curses.A_BOLD)
        except curses.error:
            pass

        # Header content
        left  = f" ⚡ AMONSTRIKE  │  {target}  │  {phase}"
        right = f"CRIT:{crit} HIGH:{high} MED:{med} │ Nodes:{nodes} Finds:{finds} │ {m:02d}:{s:02d} "
        self._safe_addstr(stdscr, 0, 0, left,
            curses.color_pair(COLOR_HEADER) | curses.A_BOLD)
        self._safe_addstr(stdscr, 0, max(0, w - len(right) - 1), right,
            curses.color_pair(COLOR_HEADER) | curses.A_BOLD)

    def _draw_log_panel(self, win):
        """Draw the left log panel."""
        h, w = win.getmaxyx()
        self._draw_border(win, "⟫ SCAN PROGRESS")

        with self.lock:
            lines = list(self.log_lines)

        # Show last N lines that fit
        visible_h = h - 2
        start = max(0, len(lines) - visible_h - self.log_scroll)
        visible = lines[start:start + visible_h]

        for i, entry in enumerate(visible):
            y = i + 1
            if y >= h - 1:
                break

            ts    = entry["ts"]
            level = entry["level"]
            msg   = entry["msg"]
            tool  = entry["tool"]

            # Timestamp
            self._safe_addstr(win, y, 1,
                f"{ts} ", curses.color_pair(COLOR_DIM))

            # Level indicator
            level_str = f"[{level}]"
            self._safe_addstr(win, y, 10,
                level_str, self._level_color(level))

            # Tool name if present
            x_offset = 14
            if tool:
                tool_str = f"[{tool}] "
                self._safe_addstr(win, y, x_offset,
                    tool_str, curses.color_pair(COLOR_CYAN))
                x_offset += len(tool_str)

            # Message
            max_msg = w - x_offset - 2
            msg_truncated = msg[:max_msg] if max_msg > 0 else ""
            self._safe_addstr(win, y, x_offset,
                msg_truncated, curses.color_pair(COLOR_DIM))

        # Scroll hint
        if self.log_scroll > 0:
            self._safe_addstr(win, h - 1, w - 15,
                f"↑ scroll:{self.log_scroll}",
                curses.color_pair(COLOR_YELLOW))

    def _draw_findings_panel(self, win):
        """Draw the right findings panel."""
        h, w = win.getmaxyx()
        self._draw_border(win, "⟫ FINDINGS")

        with self.lock:
            finds = list(self.findings)

        visible_h = h - 2
        start = max(0, len(finds) - visible_h - self.finding_scroll)
        visible = finds[start:start + visible_h]

        for i, f in enumerate(visible):
            y = i + 1
            if y >= h - 1:
                break

            sev   = f["severity"]
            title = f["title"]
            mod   = f["module"]
            ts    = f["time"]

            # Severity badge
            sev_str = f"[{sev[:4]:4s}]"
            self._safe_addstr(win, y, 1,
                sev_str, self._severity_color(sev))

            # Module
            mod_str = f" {mod[:6]:6s} "
            self._safe_addstr(win, y, 8,
                mod_str, curses.color_pair(COLOR_CYAN))

            # Title (truncated)
            max_title = w - 17
            title_str = title[:max_title] if max_title > 0 else ""
            self._safe_addstr(win, y, 16,
                title_str, curses.color_pair(COLOR_WHITE))

        # Counter summary
        with self.lock:
            c = self.scan_stats["critical"]
            h2 = self.scan_stats["high"]
            m  = self.scan_stats["medium"]
            l  = self.scan_stats["low"]
            inf = self.scan_stats["info"]

        summary = f" C:{c} H:{h2} M:{m} L:{l} I:{inf} "
        self._safe_addstr(win, h - 1, 1, summary,
            curses.color_pair(COLOR_BORDER) | curses.A_BOLD)

    def _draw_graph_panel(self, win):
        """Draw the bottom ASCII attack graph."""
        h, w = win.getmaxyx()
        self._draw_border(win, "⟫ ATTACK GRAPH")

        with self.lock:
            nodes  = dict(self.graph_nodes)
            target = self.scan_stats["target"]
            tool   = self.scan_stats["current_tool"]
            phase  = self.scan_stats["current_phase"]
            d_ends = self.scan_stats["dead_ends"]
            tools  = list(self.scan_stats["tools_used"])[:5]

        if not nodes and not target:
            self._safe_addstr(win, 1, 2,
                "Waiting for scan to start...",
                curses.color_pair(COLOR_DIM))
            return

        # Draw ASCII graph
        # Target node at center-left
        cx = 3
        cy = 1

        # Target
        t_str = f"[TARGET: {target[:20]}]"
        self._safe_addstr(win, cy, cx, t_str,
            curses.color_pair(COLOR_CRITICAL) | curses.A_BOLD)

        # Count node types
        type_counts = {}
        for n in nodes.values():
            nt = n["type"]
            type_counts[nt] = type_counts.get(nt, 0) + 1

        # Draw node type summary as graph
        node_types = list(type_counts.items())[:6]
        for i, (ntype, count) in enumerate(node_types):
            row = cy + i
            if row >= h - 1:
                break
            bar_len = min(count, w // 4)
            bar = "█" * bar_len
            line = f"  ├─ {ntype:<15} {bar} ({count})"
            color = {
                "web_service": COLOR_GREEN,
                "open_port":   COLOR_YELLOW,
                "directory":   COLOR_CYAN,
                "vulnerability": COLOR_CRITICAL,
                "subdomain":   COLOR_INFO,
            }.get(ntype, COLOR_DIM)
            self._safe_addstr(win, row + 1, cx, line,
                curses.color_pair(color))

        # Current status on right side
        status_x = w // 2
        if tool:
            self._safe_addstr(win, 1, status_x,
                f"▶ Running: {tool}",
                curses.color_pair(COLOR_GREEN) | curses.A_BOLD)
        if phase:
            self._safe_addstr(win, 2, status_x,
                f"◉ Phase:   {phase}",
                curses.color_pair(COLOR_CYAN))
        if d_ends:
            self._safe_addstr(win, 3, status_x,
                f"↺ Dead-ends escaped: {d_ends}",
                curses.color_pair(COLOR_YELLOW))
        if tools:
            self._safe_addstr(win, 4, status_x,
                f"⚙ Tools: {', '.join(tools)}",
                curses.color_pair(COLOR_DIM))

        # Animated spinner
        spinners = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        spin = spinners[int(time.time() * 5) % len(spinners)]
        self._safe_addstr(win, h - 1, w - 4, spin,
            curses.color_pair(COLOR_GREEN) | curses.A_BOLD)

    def _draw_status_bar(self, stdscr):
        """Draw bottom status bar with keyboard shortcuts."""
        h, w = stdscr.getmaxyx()
        shortcuts = " [q]Quit  [↑↓]Scroll Log  [PgUp/PgDn]Scroll Findings  [c]Clear Log  [s]Save "
        try:
            stdscr.attron(curses.color_pair(COLOR_HEADER))
            stdscr.addstr(h - 1, 0, shortcuts[:w - 1].ljust(w - 1))
            stdscr.attroff(curses.color_pair(COLOR_HEADER))
        except curses.error:
            pass

    def _handle_key(self, key):
        """Handle keyboard input."""
        if key == ord('q') or key == ord('Q'):
            self.running = False
        elif key == curses.KEY_UP:
            self.log_scroll = min(self.log_scroll + 1,
                                  max(0, len(self.log_lines) - 10))
        elif key == curses.KEY_DOWN:
            self.log_scroll = max(0, self.log_scroll - 1)
        elif key == curses.KEY_PPAGE:
            self.finding_scroll = min(self.finding_scroll + 5,
                                      max(0, len(self.findings) - 5))
        elif key == curses.KEY_NPAGE:
            self.finding_scroll = max(0, self.finding_scroll - 5)
        elif key == ord('c') or key == ord('C'):
            with self.lock:
                self.log_lines.clear()
        elif key == ord('s') or key == ord('S'):
            self._save_session()

    def _save_session(self):
        """Save current findings to JSON."""
        try:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            path = f"/tmp/amonstrike_session_{ts}.json"
            with open(path, "w") as f:
                json.dump({
                    "stats":    {k: list(v) if isinstance(v, set) else v
                                for k, v in self.scan_stats.items()},
                    "findings": list(self.findings),
                    "nodes":    self.graph_nodes,
                }, f, indent=2)
            self.log(f"Session saved to {path}", "+")
        except Exception as e:
            self.log(f"Save failed: {e}", "!")

    def render(self, stdscr):
        """Main rendering loop."""
        self._init_colors()
        curses.curs_set(0)
        stdscr.nodelay(True)
        stdscr.timeout(100)  # 100ms refresh

        while self.running:
            try:
                self.height, self.width = stdscr.getmaxyx()
                h, w = self.height, self.width

                if h < 20 or w < 60:
                    stdscr.clear()
                    self._safe_addstr(stdscr, h // 2, w // 2 - 15,
                        "Terminal too small — resize to 60x20+",
                        curses.color_pair(COLOR_CRITICAL))
                    stdscr.refresh()
                    time.sleep(0.1)
                    key = stdscr.getch()
                    if key == ord('q'):
                        break
                    continue

                stdscr.erase()

                # Layout:
                # Row 0:          Header bar
                # Rows 1..h-7:    Left panel (log) | Right panel (findings)
                # Rows h-7..h-2:  Bottom panel (graph)
                # Row h-1:        Status bar

                content_h  = h - 8   # space for log/findings panels
                bottom_h   = 6       # graph panel height
                split_w    = w // 2  # left/right split

                # Draw header
                self._draw_header(stdscr)

                # Left panel — log
                if content_h > 2 and split_w > 10:
                    log_win = stdscr.subwin(content_h, split_w, 1, 0)
                    self._draw_log_panel(log_win)

                # Right panel — findings
                if content_h > 2 and w - split_w > 10:
                    find_win = stdscr.subwin(
                        content_h, w - split_w, 1, split_w)
                    self._draw_findings_panel(find_win)

                # Bottom panel — attack graph
                graph_y = 1 + content_h
                if graph_y + bottom_h < h - 1 and w > 20:
                    graph_win = stdscr.subwin(bottom_h, w, graph_y, 0)
                    self._draw_graph_panel(graph_win)

                # Status bar
                self._draw_status_bar(stdscr)

                stdscr.refresh()

            except curses.error:
                pass

            # Handle keyboard
            key = stdscr.getch()
            if key != -1:
                self._handle_key(key)

            time.sleep(0.05)

    def run(self):
        """Start the curses UI in main thread."""
        curses.wrapper(self.render)

    def run_in_thread(self):
        """Start UI in background thread."""
        t = threading.Thread(target=self.run, daemon=True)
        t.start()
        return t


# ── Regression Tests ──────────────────────────────────────────

def run_regression_tests():
    """Test ConsoleUI without actually rendering."""
    print("\n=== CONSOLE UI REGRESSION TESTS ===")
    passed = 0
    failed = 0
    ui = ConsoleUI()

    tests = [
        # 1. Log add
        ("Log line added to buffer",
         lambda: (ui.log("test message", "+") or True)
                 and len(ui.log_lines) == 1),

        # 2. Log maxlen
        ("Log buffer maxlen respected",
         lambda: (
             [ui.log(f"line {i}") for i in range(600)]
             and len(ui.log_lines) <= 500
         )),

        # 3. Finding add
        ("Finding added correctly",
         lambda: (ui.add_finding("Test vuln", "HIGH", "sqli", "http://x.com") or True)
                 and len(ui.findings) >= 1),

        # 4. Severity counts
        ("Severity counts increment",
         lambda: (
             ui.add_finding("Crit", "CRITICAL") or True,
             ui.scan_stats["critical"] >= 1
         )[1]),

        # 5. Stats update
        ("Stats update works",
         lambda: (ui.update_stats(target="http://test.com") or True)
                 and ui.scan_stats["target"] == "http://test.com"),

        # 6. Graph node add
        ("Graph node added",
         lambda: (ui.add_graph_node("n1", "domain", "test.com") or True)
                 and "n1" in ui.graph_nodes),

        # 7. Node count increments
        ("Node count increments",
         lambda: ui.scan_stats["nodes"] >= 1),

        # 8. Tools set
        ("Tools_used is a set",
         lambda: isinstance(ui.scan_stats["tools_used"], set)),

        # 9. Log with tool name
        ("Log with tool name stored",
         lambda: (ui.log("running nmap", tool="nmap") or True)
                 and ui.scan_stats["current_tool"] == "nmap"),

        # 10. Stop flag
        ("Stop sets running False",
         lambda: (ui.stop() or True) and not ui.running),

        # 11. Thread safety — concurrent log writes
        ("Thread-safe log writes",
         lambda: _test_thread_safety(ui)),

        # 12. Finding maxlen
        ("Finding buffer maxlen respected",
         lambda: (
             ui2 := ConsoleUI(),
             [ui2.add_finding(f"f{i}", "INFO") for i in range(300)],
             len(ui2.findings) <= 200
         )[2]),

        # 13. Save session doesn't crash
        ("Save session runs without error",
         lambda: (ui._save_session() or True)),
    ]

    for name, fn in tests:
        try:
            result = fn()
            if result:
                passed += 1
                print(f"  ✓ {name}")
            else:
                failed += 1
                print(f"  ✗ {name} — returned False")
        except Exception as e:
            failed += 1
            print(f"  ✗ {name} — {e}")

    print(f"\n  Passed: {passed}  Failed: {failed}")
    return passed, failed


def run_stress_tests():
    """Stress tests for ConsoleUI."""
    print("\n=== CONSOLE UI STRESS TESTS ===")
    passed = 0
    failed = 0
    ui = ConsoleUI()

    tests = [
        # 1. Mass log writes
        ("Mass log (10000 entries)",
         lambda: (
             [ui.log(f"msg {i}", level=["*","+","!","~","i"][i%5])
              for i in range(10000)]
             and len(ui.log_lines) <= 500  # maxlen enforced
         )),

        # 2. Mass findings
        ("Mass findings (1000)",
         lambda: (
             [ui.add_finding(f"vuln {i}",
              ["CRITICAL","HIGH","MEDIUM","LOW","INFO"][i%5])
              for i in range(1000)]
             and len(ui.findings) <= 200  # maxlen enforced
         )),

        # 3. Mass graph nodes
        ("Mass graph nodes (500)",
         lambda: (
             [ui.add_graph_node(f"node_{i}", "directory", f"/path/{i}")
              for i in range(500)]
             and len(ui.graph_nodes) == 500
         )),

        # 4. Severity counts accuracy
        ("Severity counts accurate after mass findings",
         lambda: (
             ui2 := ConsoleUI(),
             [ui2.add_finding(f"c{i}", "CRITICAL") for i in range(10)],
             [ui2.add_finding(f"h{i}", "HIGH") for i in range(20)],
             ui2.scan_stats["critical"] == 10
             and ui2.scan_stats["high"] == 20
         )[3]),

        # 5. Long target name
        ("Long target URL handled",
         lambda: (
             ui.update_stats(target="http://" + "a" * 1000) or True
         ) and True),

        # 6. Special characters in findings
        ("Special chars in findings",
         lambda: (
             ui.add_finding(
                 "SQL Injection: ' OR '1'='1",
                 "CRITICAL", "sqli",
                 "http://test.com/?id=1' OR '1'='1"
             ) or True
         ) and True),

        # 7. Rapid stats updates
        ("Rapid stats updates",
         lambda: (
             [ui.update_stats(current_tool=f"tool_{i}") for i in range(1000)]
             or True
         ) and True),

        # 8. Concurrent findings (thread safety)
        ("Thread-safe finding writes",
         lambda: _test_findings_thread_safety()),

        # 9. Elapsed time calculation
        ("Elapsed time calculation",
         lambda: (
             ui3 := ConsoleUI(),
             time.sleep(0.1),
             (time.time() - ui3.scan_stats["start_time"]) > 0
         )[2]),

        # 10. Stop idempotent
        ("Stop is idempotent",
         lambda: (
             ui4 := ConsoleUI(),
             ui4.stop(),
             ui4.stop(),
             not ui4.running
         )[3]),
    ]

    for name, fn in tests:
        try:
            result = fn()
            if result:
                passed += 1
                print(f"  ✓ {name}")
            else:
                failed += 1
                print(f"  ✗ {name} — returned False")
        except Exception as e:
            failed += 1
            print(f"  ✗ {name} — {e}")

    print(f"\n  Passed: {passed}  Failed: {failed}")
    return passed, failed


def _test_thread_safety(ui):
    """Concurrent log writes from 10 threads."""
    import threading
    errors = []

    def writer(tid):
        try:
            for i in range(100):
                ui.log(f"thread {tid} msg {i}", level="*")
        except Exception as e:
            errors.append(str(e))

    threads = [threading.Thread(target=writer, args=(t,)) for t in range(10)]
    for t in threads: t.start()
    for t in threads: t.join()
    return len(errors) == 0


def _test_findings_thread_safety():
    """Concurrent finding writes from 10 threads."""
    import threading
    ui = ConsoleUI()
    errors = []

    def writer(tid):
        try:
            for i in range(50):
                ui.add_finding(
                    f"thread {tid} finding {i}",
                    ["CRITICAL","HIGH","MEDIUM","LOW","INFO"][i%5]
                )
        except Exception as e:
            errors.append(str(e))

    threads = [threading.Thread(target=writer, args=(t,)) for t in range(10)]
    for t in threads: t.start()
    for t in threads: t.join()
    return len(errors) == 0


# ── Demo mode ─────────────────────────────────────────────────

def demo():
    """Run a demo of the console UI with simulated scan data."""
    import random

    ui = ConsoleUI()
    ui.update_stats(target="http://192.168.178.149/dvwa")

    def simulate_scan():
        """Simulate a scan feeding data to the UI."""
        phases = [
            ("Passive Recon",   ["Checking robots.txt", "Fetching sitemap", "SSL certificate check", "DNS lookup"]),
            ("Port Scanning",   ["Running nmap", "Port 80 open", "Port 443 open", "Port 3306 open — MySQL"]),
            ("Web Enumeration", ["Running ffuf", "Found /admin/", "Found /backup/", "Found /api/v1/"]),
            ("Vulnerability",   ["Running nuclei", "Testing SQLi", "Testing XSS", "Testing CORS"]),
            ("Deep Analysis",   ["Analyzing JS files", "Extracting API endpoints", "Testing auth bypass"]),
        ]

        tools = ["nmap", "ffuf", "sqlmap", "nuclei", "whatweb", "wafw00f", "gobuster"]

        sample_findings = [
            ("SQL Injection in login form",         "CRITICAL", "sqli"),
            ("Reflected XSS in search parameter",   "HIGH",     "xss"),
            ("Missing Content-Security-Policy",     "MEDIUM",   "headers"),
            ("Cookie missing HttpOnly flag",        "MEDIUM",   "cookies"),
            ("Directory listing enabled: /backup/", "HIGH",     "dirs"),
            ("Default credentials work: admin/admin","CRITICAL", "auth"),
            ("CORS allows arbitrary origins",       "HIGH",     "cors"),
            ("Server version disclosure (Apache)",  "LOW",      "recon"),
            ("No rate limiting on login endpoint",  "HIGH",     "auth"),
            ("JWT token uses HS256 weak algorithm", "LOW",      "auth"),
            (".env file exposed",                   "CRITICAL", "recon"),
            ("GraphQL introspection enabled",       "MEDIUM",   "api"),
        ]

        node_types = ["domain","subdomain","open_port","web_service",
                      "directory","form","api_endpoint","js_file","vulnerability"]

        node_id = 0
        for phase_name, phase_logs in phases:
            ui.update_stats(current_phase=phase_name)
            ui.log(f"=== Phase: {phase_name} ===", "+")
            time.sleep(0.5)

            tool = random.choice(tools)
            ui.update_stats(current_tool=tool, tools_used=tool)

            for log_msg in phase_logs:
                ui.log(log_msg, random.choice(["*", "i", "~"]), tool=tool)
                time.sleep(0.3)

                # Add graph nodes
                node_id += 1
                ntype = random.choice(node_types)
                ui.add_graph_node(f"n{node_id}", ntype,
                    f"{ntype}_{node_id}")

                # Occasionally add a finding
                if random.random() < 0.3 and sample_findings:
                    f = random.choice(sample_findings)
                    ui.add_finding(f[0], f[1], f[2],
                        f"http://192.168.178.149/dvwa/{f[2]}")
                    ui.log(f"Found: {f[0]}", "!", tool=tool)

            time.sleep(0.5)

        # Dead-end simulation
        ui.update_stats(dead_ends=3)
        ui.log("Dead-end detected — trying Wayback Machine", "~")
        time.sleep(0.5)
        ui.log("Dead-end escaped — found 12 historical endpoints", "+")
        time.sleep(0.5)

        ui.update_stats(current_phase="Complete")
        ui.log("Scan complete — generating report", "+")
        time.sleep(2)
        ui.stop()

    # Start simulated scan in background
    scan_thread = threading.Thread(target=simulate_scan, daemon=True)
    scan_thread.start()

    # Run UI (blocking)
    ui.run()


if __name__ == "__main__":
    if "--test" in sys.argv:
        rp, rf = run_regression_tests()
        sp, sf = run_stress_tests()
        print(f"\nTOTAL: {rp+sp} passed  {rf+sf} failed")
        sys.exit(0 if rf + sf == 0 else 1)
    else:
        # Run demo
        demo()
