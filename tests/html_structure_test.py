#!/usr/bin/env python3
import re
import sys

from html.parser import HTMLParser
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INDEX = ROOT / "public/index.html"
VOID_ELEMENTS = {
    "area",
    "base",
    "br",
    "col",
    "embed",
    "hr",
    "img",
    "input",
    "link",
    "meta",
    "param",
    "source",
    "track",
    "wbr",
}

PASS = 0
FAIL = 0


def check(condition, label):
    global PASS
    global FAIL
    if condition:
        PASS += 1
        print(f"PASS  {label}")
    else:
        FAIL += 1
        print(f"FAIL  {label}")


class DocumentValidator(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack = []
        self.errors = []
        self.ids = set()
        self.doctypes = 0
        self.starts = {"html": 0, "head": 0, "body": 0}
        self.ends = {"html": 0, "head": 0, "body": 0}
        self.viewport_values = []
        self.body_closed = False

    def handle_decl(self, declaration):
        if declaration.lower() == "doctype html":
            self.doctypes += 1

    def _start(self, tag, attributes, push):
        attrs = dict(attributes)
        if self.body_closed:
            self.errors.append(f"element <{tag}> appears after </body>")
        if tag in self.starts:
            self.starts[tag] += 1
        if tag == "html" and self.stack:
            self.errors.append("<html> must be the document root")
        elif tag in ("head", "body") and self.stack != ["html"]:
            self.errors.append(f"<{tag}> must be a direct child of <html>")
        elif tag not in ("html", "head", "body") and self.stack == ["html"]:
            self.errors.append(f"<{tag}> appears outside <head> or <body>")
        element_id = attrs.get("id")
        if element_id:
            if element_id in self.ids:
                self.errors.append(f"duplicate id: {element_id}")
            self.ids.add(element_id)
        if tag == "meta" and attrs.get("name", "").lower() == "viewport":
            if not self.stack or self.stack[-1] != "head":
                self.errors.append("viewport metadata must be inside <head>")
            self.viewport_values.append(attrs.get("content"))
        if push:
            self.stack.append(tag)

    def handle_starttag(self, tag, attributes):
        self._start(tag, attributes, tag not in VOID_ELEMENTS)

    def handle_startendtag(self, tag, attributes):
        self._start(tag, attributes, False)

    def handle_endtag(self, tag):
        if not self.stack or self.stack[-1] != tag:
            parent = self.stack[-1] if self.stack else "document"
            self.errors.append(f"unexpected </{tag}> while inside {parent}")
            return
        self.stack.pop()
        if tag in self.ends:
            self.ends[tag] += 1
        if tag == "body":
            self.body_closed = True

    def handle_data(self, data):
        if data.strip() and self.stack in ([], ["html"]):
            self.errors.append("text appears outside <head> or <body>")


source = INDEX.read_text(encoding="utf-8")
validator = DocumentValidator()
validator.feed(source)
validator.close()

check(
    validator.doctypes == 1,
    "document has exactly one HTML5 doctype",
)
check(
    validator.starts == {"html": 1, "head": 1, "body": 1}
    and validator.ends == {"html": 1, "head": 1, "body": 1},
    "html, head, and body each open and close exactly once",
)
check(
    not validator.stack,
    "all non-void elements close in strict source order",
)
check(
    not validator.errors,
    "all elements are inside head/body and every id is unique",
)
check(
    validator.viewport_values == ["width=device-width, initial-scale=1"],
    "one standard responsive viewport declaration is inside head",
)

head_close = re.search(r"</head\s*>", source, re.IGNORECASE)
body_open = re.search(r"<body(?:\s[^>]*)?>", source, re.IGNORECASE)
check(
    head_close is not None
    and body_open is not None
    and head_close.end() <= body_open.start()
    and not source[head_close.end():body_open.start()].strip(),
    "body opens immediately after head closes",
)

auth_screen = re.search(r"<div id=\"authScreen\"[^>]*>", source)
check(
    auth_screen is not None and "active" not in auth_screen.group(0),
    "the auth screen ships inactive so reloads never flash the login form",
)
check(
    all(element_id in validator.ids for element_id in (
        "authRecoveryPane",
        "authResendPane",
        "authVerifyPane",
        "authResetPane",
        "authContextResend",
        "authRecoveryStatus",
        "authResendStatus",
        "authResetFields",
        "authResetHint",
        "authResetStatus",
        "profileEmailIndicator",
        "profileEmailStatus",
    )),
    "both account modes ship their capability-controlled auth and profile surfaces",
)

account_profile = source.find('id="accountProfileBtn"')
history_button = source.find('id="notifHistoryBtn"')
admin_button = source.find('id="openAdminPanelBtn"')
logout_button = source.find('id="logoutBtn"')
check(
    -1 < account_profile < history_button < admin_button < logout_button,
    "Notifications is between Profile and Administration in the account menu",
)
check(
    all(element_id in validator.ids for element_id in (
        "notifHistoryOverlay",
        "notifHistoryList",
        "notifHistoryMarkSeenBtn",
        "notifHistoryBadge",
    ))
    and "Mark all seen" in source,
    "notification history ships its explicit seen controls and exact-count badge",
)
check(
    source.find('id="changePwdOverlay"')
    < source.find('id="notifHistoryOverlay"')
    < source.find('id="notification-container"'),
    "the history overlay stays inside the validated body before toast infrastructure",
)

body_close = re.search(r"</body\s*>", source, re.IGNORECASE)
html_close = re.search(r"</html\s*>", source, re.IGNORECASE)
check(
    body_close is not None
    and html_close is not None
    and body_close.end() <= html_close.start()
    and not source[body_close.end():html_close.start()].strip(),
    "only whitespace separates the closing body and html tags",
)

print(f"\n==== {PASS} passed, {FAIL} failed ====")
sys.exit(1 if FAIL else 0)
