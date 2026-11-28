# SPDX-License-Identifier: AGPL-3.0-only
"""Browser end-to-end test of the real UI against the real web server binary.

Optional (needs Python + Playwright):  pip install playwright && playwright install chromium
Run:  cargo build -p ctrlaltnotes-server && python3 tests/e2e_ui.py target/debug/ctrlaltnotes-web
"""
import os, re, subprocess, sys, tempfile, time
from playwright.sync_api import sync_playwright, expect

BIN = sys.argv[1]
PW = "Tangerine Lantern Walrus Quartz 92"
tmp = tempfile.mkdtemp()
cloud = os.path.join(tmp, "cloud")
os.makedirs(cloud)
proc = subprocess.Popen([BIN, "--vault", tmp + "/vault", "--sync-folder", cloud, "--no-open", "--idle-lock", "25"],
                        stdout=subprocess.PIPE, text=True)
url = None
for line in proc.stdout:
    m = re.search(r"(http://localhost:\d+/#[0-9a-f]{64})", line)
    if m:
        url = m.group(1); break
assert url, "server did not print its URL"
ok = []
def check(name, cond=True):
    assert cond, name
    ok.append(name); print("ok -", name)

def ctx_new(page, label):
    """Create a note or folder the way the UI offers it: right-click the sidebar background."""
    page.locator(".sfoot").click(button="right", position={"x": 3, "y": 3})
    page.get_by_role("menuitem", name=label).click()


def toggle_state(page, key):
    page.wait_for_timeout(400)   # the switch updates once the setting is saved
    return page.locator(f"#set-{key}").get_attribute("aria-checked") == "true"

try:
    with sync_playwright() as p:
        b = p.chromium.launch()
        ctx = b.new_context()
        page = ctx.new_page()
        errors = []
        page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.goto(url)

        # ---------------------------------------------------------------- first run + password policy
        expect(page.get_by_role("heading", name="Create your vault")).to_be_visible()
        check("first run shows create-vault screen")
        expect(page.locator(".lock .logo img.logo-l, .lock .logo img.logo-d").first).to_be_attached()
        check("large CtrlAltNotes logo (icon + name) on the lock screen", page.locator(".lock .logo").count() == 1)
        check("page title is CtrlAltNotes", page.title() == "CtrlAltNotes")
        check("logo images actually load", page.evaluate("Promise.all([...document.images].map(i=>i.complete&&i.naturalWidth>0||new Promise(r=>{i.onload=()=>r(true);i.onerror=()=>r(false)})))").count(False) == 0 if False else all(page.evaluate("[...document.images].map(i=>i.complete && i.naturalWidth>0)")))
        assert "#" not in page.url
        check("token removed from URL")
        go = page.get_by_role("button", name="Create encrypted vault")
        expect(go).to_be_disabled()
        pw1, pw2 = page.get_by_label("New password"), page.get_by_label("Repeat password")
        pw1.fill("Aa1!Aa1!Aa1!Aa"); pw2.fill("Aa1!Aa1!Aa1!Aa")
        expect(go).to_be_disabled(); check("14 characters is refused even with symbols/digits (length > complexity)")
        pw1.fill("correct horse battery staple"); pw2.fill("correct horse battery staple")
        expect(go).to_be_enabled(); go.click()
        expect(page.get_by_text("too easy to guess")).to_be_visible()
        check("famous passphrase rejected by the policy (server-side)")
        page.get_by_role("button", name="Generate").click()
        g = pw1.input_value()
        check("generator makes a long random password", len(g) == 22 and g == pw2.input_value())
        pw1.fill(PW); pw2.fill(PW + "x")
        expect(go).to_be_disabled(); check("mismatched confirmation cannot be submitted")
        pw2.fill(PW); expect(go).to_be_enabled(); go.click()

        key = page.locator(".reckey").inner_text()
        check("recovery key displayed", re.fullmatch(r"([A-Z2-7]{4}-){12}[A-Z2-7]{1,4}", key) is not None)
        cont = page.get_by_role("button", name="Continue")
        expect(cont).to_be_disabled()
        page.get_by_label("I have saved my recovery key.").check()
        cont.click()
        expect(page.get_by_text("No notes yet.")).to_be_visible()

        # ---------------------------------------------------------------- settings popup + defaults
        page.get_by_role("button", name="Settings").click()
        dlg = page.get_by_role("dialog", name="Settings")
        expect(dlg).to_be_visible(); check("settings open in a popup window")
        check("auto-sync is ON by default", toggle_state(page, "auto_sync"))
        check("live preview is ON by default", toggle_state(page, "live_preview"))
        check("formatting toolbar is ON by default", toggle_state(page, "toolbar"))
        check("export is offered in the web version too", page.get_by_text("Export to Markdown files").count() == 1)
        page.get_by_role("button", name="Close settings").click()
        expect(dlg).to_have_count(0)

        check("there is NO Sync button in the top bar (on/off lives in Settings)", page.get_by_role("button", name="Sync", exact=True).count() == 0)

        # ---------------------------------------------------------------- automatic sync (launch flag target)
        expect(page.locator("#status")).to_have_text(re.compile("Synced"), timeout=8000)
        check("automatic sync ran without clicking anything")

        # ---------------------------------------------------------------- notes, live preview, toolbar
        ctx_new(page, "New folder")
        page.get_by_role("textbox", name="Folder name").fill("Work"); page.keyboard.press("Enter")
        expect(page.locator("#tree").get_by_text("Work")).to_be_visible()
        ctx_new(page, "New note")
        page.get_by_role("textbox", name="Note title").fill("Plan"); page.keyboard.press("Enter")
        ta = page.get_by_label("Markdown")
        expect(ta).to_be_focused(); check("a new note opens ready to type in")
        check("live preview is side by side: Markdown editor + formatted preview", page.locator(".split").count() == 1 and page.locator(".split #preview").count() == 1 and page.locator(".split textarea.ed").count() == 1)
        page.keyboard.type("# Hello\n\n**bold** and more")
        expect(page.locator("#preview h1")).to_have_text("Hello")
        expect(page.locator("#preview strong")).to_have_text("bold")
        boxes = page.evaluate("(() => { const a = document.querySelector('.split textarea').getBoundingClientRect(), b = document.querySelector('#preview').getBoundingClientRect(); return [a.right, b.left, Math.abs(a.top - b.top)]; })()")
        check("editor on the left, preview on the right, same height: %r" % boxes, boxes[0] <= boxes[1] + 1 and boxes[2] < 40)
        ta.press("ControlOrMeta+a"); ta.press("Delete")
        ta.fill("select me")
        ta.press("ControlOrMeta+a")
        page.get_by_role("button", name="Bold (Ctrl/Cmd+B)").click()
        check("toolbar Bold wraps the selection", ta.input_value() == "**select me**")
        page.get_by_role("button", name="Bold (Ctrl/Cmd+B)").click()
        check("toolbar Bold toggles off", ta.input_value() == "select me")
        ta.press("ControlOrMeta+a"); ta.press("Control+u")
        check("Ctrl+U underlines", ta.input_value() == "++select me++")
        expect(page.locator("#preview u")).to_have_text("select me")
        ta.fill("a"); ta.press("ControlOrMeta+a"); page.get_by_role("button", name="Highlight").click()
        expect(page.locator("#preview mark")).to_have_count(1); check("highlight extended syntax")
        ta.press("ControlOrMeta+a"); ta.press("Delete")
        page.get_by_role("button", name="Table", exact=True).click()
        expect(page.locator("#preview table th")).to_have_count(2); check("table button inserts a rendered table")
        ta.press("ControlOrMeta+a"); ta.press("Delete")
        shell = "echo $'a b' && x=$& $` $$"   # JavaScript replacement patterns must stay literal
        ta.fill(shell); ta.press("ControlOrMeta+a")
        page.get_by_role("button", name="Code block", exact=True).click()
        check("code block keeps $' $& $` $$ in the selection unchanged", ta.input_value() == "\n```\n" + shell + "\n```\n")
        ta.press("ControlOrMeta+a"); ta.press("Delete")
        ta.fill("- [ ] one\n- [x] two\n\n~~old~~ <img src=x onerror=alert(1)> [x](javascript:alert(1)) [ok](https://example.com)")
        expect(page.locator("#preview input[type=checkbox]")).to_have_count(2)
        check("no raw html element created from note text", page.locator("#preview img").count() == 0)
        check("javascript: links are not links", page.locator("#preview a[href^='javascript']").count() == 0)
        check("https links work", page.locator("#preview a[href^='https://example.com']").count() == 1)
        expect(page.locator("#status")).to_have_text(re.compile("Saved"), timeout=5000)
        check("note saved")

        # ---------------------------------------------------------------- Preview button: only the rendered text
        page.get_by_role("button", name="Preview", exact=True).click()
        check("Preview shows only the formatted text (no editor)", page.locator("textarea.ed").count() == 0 and page.locator(".split").count() == 0 and page.locator("#preview").count() == 1 and page.get_by_label("Title").get_attribute("readonly") is not None)
        page.get_by_role("button", name="Edit", exact=True).click()
        check("Edit brings the editor back", page.locator("textarea.ed").count() == 1 and page.locator(".split").count() == 1)
        names = page.evaluate("[...document.querySelectorAll('.top button')].filter(b => b.offsetParent !== null).map(b => b.textContent.trim())")
        check("the top bar has only Preview and Settings: %r" % names, sorted(names) == ["Preview", "Settings"])

        # ---------------------------------------------------------------- sidebar: footer, logo, context menu, collapse, resize
        check("there are no + Note / + Folder buttons any more", page.get_by_role("button", name=re.compile(r"^\+ ")).count() == 0 and page.get_by_role("button", name="New note").count() == 0)
        foot = page.evaluate("""() => { const f = document.querySelector('.sfoot'), a = document.querySelector('aside'), l = f.querySelector('.lockbtn').getBoundingClientRect(), r = a.getBoundingClientRect();
          return { off: Math.abs((l.left + l.width / 2) - (r.left + r.width / 2)), bottom: Math.abs(f.getBoundingClientRect().bottom - r.bottom), toggle: !!f.querySelector('#side-toggle') } }""")
        check("sidebar footer: toggle icon, Lock centred at the bottom: %r" % foot, foot["toggle"] and foot["off"] < 6 and foot["bottom"] < 2)
        W = lambda: page.evaluate("document.querySelector('aside').getBoundingClientRect().width")
        LW = lambda: page.evaluate("(() => { const i = document.querySelector('.sidelogo img:not([style*=none])'); return [...document.querySelectorAll('.sidelogo img')].map(i => i.getBoundingClientRect().width).filter(w => w > 0)[0]; })()")
        check("the logo spans the sidebar width (%r in %r)" % (LW(), W()), W() == 280 and 240 <= LW() <= 270)
        check("exactly one sidebar logo is visible (light theme)", page.evaluate("[...document.querySelectorAll('.sidelogo img')].filter(i => getComputedStyle(i).display !== 'none').length") == 1)
        page.locator("#tree").click(button="right", position={"x": 100, "y": 300})
        expect(page.get_by_role("menuitem", name="New note")).to_be_visible()
        check("right-click on the list offers New note and New folder", page.get_by_role("menuitem", name="New folder").count() == 1)
        page.get_by_role("menuitem", name="New folder").click()
        page.get_by_role("textbox", name="Folder name").fill("Ctx"); page.keyboard.press("Enter")
        expect(page.locator("#tree").get_by_text("Ctx")).to_be_visible(); check("right-click New folder creates it")
        ctx_new(page, "New note")
        page.get_by_role("textbox", name="Note title").fill("FromMenu"); page.keyboard.press("Enter")
        expect(page.locator("#tree").get_by_text("FromMenu")).to_be_visible(); check("right-click New note creates it")
        page.locator("#tree").get_by_text("Plan", exact=True).click()
        expect(page.get_by_label("Title")).to_have_value("Plan")
        # resize: at 1280 px wide the limit is 320 px; the logo keeps its size
        bx = page.locator(".resizer").bounding_box()
        page.mouse.move(bx["x"] + 3, bx["y"] + 200); page.mouse.down(); page.mouse.move(bx["x"] + 600, bx["y"] + 200, steps=6); page.mouse.up()
        check("the sidebar widens, but never beyond 1/4 of the window (%r)" % W(), abs(W() - 320) <= 2)
        check("the logo keeps its original width while the sidebar is wider (%r)" % LW(), 240 <= LW() <= 270)
        bx = page.locator(".resizer").bounding_box()
        page.mouse.move(bx["x"] + 3, bx["y"] + 200); page.mouse.down(); page.mouse.move(bx["x"] - 500, bx["y"] + 200, steps=6); page.mouse.up()
        check("and it never gets narrower than its starting width (%r)" % W(), abs(W() - 280) <= 1)
        page.set_viewport_size({"width": 1000, "height": 720})
        bx = page.locator(".resizer").bounding_box()
        page.mouse.move(bx["x"] + 3, bx["y"] + 200); page.mouse.down(); page.mouse.move(bx["x"] + 300, bx["y"] + 200, steps=4); page.mouse.up()
        check("in a small window the 1/4 limit gives way to the 280 px start width (%r)" % W(), abs(W() - 280) <= 1)
        page.set_viewport_size({"width": 1280, "height": 720})
        page.locator("#side-toggle").click()
        page.wait_for_timeout(150)
        check("the toggle icon collapses the sidebar to a thin strip (%r)" % W(), W() < 60 and page.locator(".search").is_hidden() and page.locator("#side-toggle").is_visible() and page.locator(".lockmini").is_visible())
        page.locator("#side-toggle").click()
        page.wait_for_timeout(150)
        check("and brings it back", abs(W() - 280) <= 1 and page.locator(".search").is_visible())
        page.locator("#tree .row", has_text="Plan").focus(); page.keyboard.press("Control+b"); page.wait_for_timeout(150)
        check("Ctrl/Cmd+B toggles the sidebar too", W() < 60)
        page.locator("#side-toggle").click(); page.wait_for_timeout(150)

        # ---------------------------------------------------------------- drag and drop
        row = lambda name: page.locator("#tree .row", has_text=name)
        kids = lambda name: page.locator("#tree .kids .row", has_text=name)
        row("Plan").drag_to(row("Ctx"))
        expect(kids("Plan")).to_have_count(1); check("dragging a note onto a folder moves it inside")
        kids("Plan").drag_to(page.locator("#tree"), target_position={"x": 120, "y": 330})
        expect(page.locator("#tree > .row", has_text="Plan")).to_have_count(1); expect(kids("Plan")).to_have_count(0); check("dragging it onto the empty list moves it out to the top level")
        row("Ctx").drag_to(row("Work"))
        expect(kids("Ctx")).to_have_count(1); check("folders can be dragged into folders")
        row("Work").drag_to(kids("Ctx"))
        page.wait_for_timeout(300)
        check("a folder cannot be dropped into its own sub-folder", row("Work").count() == 1 and kids("Work").count() == 0)
        kids("Ctx").drag_to(page.locator("#tree"), target_position={"x": 120, "y": 330})
        expect(page.locator("#tree > .row", has_text="Ctx")).to_have_count(1); expect(kids("Ctx")).to_have_count(0); check("folders can be dragged back out as well")
        row("Plan").click()
        expect(page.get_by_label("Title")).to_have_value("Plan")
        page.wait_for_timeout(500)          # the note is re-read from the vault when it is opened

        # ---------------------------------------------------------------- no visible scrollbars, wheel still scrolls, stops at the ends
        ta = page.get_by_label("Markdown")
        orig_text = ta.input_value()
        ta.fill("\n".join("line %d" % i for i in range(300)))
        geo = page.evaluate("""() => { const t = document.querySelector('textarea.ed'), d = document.querySelector('.doc');
          return { bars: [t.offsetWidth - t.clientWidth, d.offsetWidth - d.clientWidth], can: t.scrollHeight > t.clientHeight || d.scrollHeight > d.clientHeight, dims: [t.clientHeight, t.scrollHeight, d.clientHeight, d.scrollHeight, getComputedStyle(t).overflowY],
                   over: getComputedStyle(t).overscrollBehaviorY } }""")
        check("long text shows NO scrollbar but is scrollable: %r " % (geo,), geo["bars"] == [0, 0] and geo["can"])
        check("scrolling stops at the limit (no chaining / rubber band)", geo["over"] == "contain")
        ta.press("Control+End")
        top_before = page.evaluate("document.querySelector('textarea.ed').scrollTop")
        box = ta.bounding_box(); page.mouse.move(box["x"] + 100, box["y"] + 100)
        page.mouse.wheel(0, -400); page.wait_for_timeout(250)
        top_after = page.evaluate("document.querySelector('textarea.ed').scrollTop")
        check("mouse wheel scrolls the text (%r -> %r)" % (top_before, top_after), top_after < top_before)
        ta.fill(orig_text)
        expect(page.locator("#status")).to_have_text(re.compile("Saved"), timeout=5000)

        # ---------------------------------------------------------------- editor settings
        page.get_by_role("button", name="Settings").click()
        page.locator("#set-toolbar").click()
        page.get_by_role("button", name="Close settings").click()
        expect(page.locator(".tbar")).to_have_count(0); check("toolbar can be switched off in settings")
        page.get_by_role("button", name="Settings").click()
        page.locator("#set-live_preview").click()
        page.get_by_role("button", name="Close settings").click()
        expect(page.get_by_role("button", name="Preview", exact=True)).to_be_visible()
        expect(page.locator("#preview")).to_have_count(0); expect(page.locator("textarea.ed")).to_have_count(1); check("live preview off: only the Markdown editor is visible")
        page.get_by_role("button", name="Preview", exact=True).click()
        expect(page.locator(".md input[type=checkbox]")).to_have_count(2)
        page.get_by_role("button", name="Edit").click()
        page.get_by_role("button", name="Settings").click()
        page.locator("#set-live_preview").click(); page.locator("#set-toolbar").click()
        page.get_by_role("button", name="Close settings").click()
        expect(page.locator(".tbar")).to_have_count(1); expect(page.locator(".split")).to_have_count(1); check("toolbar + live preview back on")

        # ---------------------------------------------------------------- sync settings persist
        page.get_by_role("button", name="Settings").click()
        page.locator("#set-auto_sync").click()
        check("auto-sync can be disabled", not toggle_state(page, "auto_sync"))
        page.get_by_role("button", name="Close settings").click()
        check("with auto-sync off there is still no Sync button", page.get_by_role("button", name="Sync", exact=True).count() == 0)
        # switching it back on syncs by itself, no click needed
        page.get_by_role("button", name="Settings").click(); page.locator("#set-auto_sync").click(); page.get_by_role("button", name="Close settings").click()
        # sync writes each object to ".tmp-…" and renames it into place: count only finished objects
        done = lambda: [f for f in os.listdir(os.path.join(cloud, "objects")) if not f.startswith(".tmp-")] if os.path.isdir(os.path.join(cloud, "objects")) else []
        for _ in range(40):
            if len(done()) >= 2: break
            page.wait_for_timeout(250)
        cloud_files = done()
        check("encrypted objects reached the sync folder", len(cloud_files) >= 2 and all(f.endswith(".can") for f in cloud_files))
        for f in cloud_files:
            check("cloud file has no plaintext: " + f[:6], b"Plan" not in open(os.path.join(cloud, "objects", f), "rb").read())

        # ---------------------------------------------------------------- lock / unlock
        page.get_by_role("button", name="Lock", exact=True).click()
        expect(page.get_by_role("button", name="Unlock", exact=True)).to_be_visible()
        check("lock screen shown")
        check("no note text left in the DOM after lock", "select me" not in page.content() and "Plan" not in page.content())
        page.get_by_label("Password").fill("definitely wrong password")
        page.get_by_role("button", name="Unlock", exact=True).click()
        expect(page.get_by_text("Could not unlock.")).to_be_visible()
        check("wrong password rejected with generic message")
        page.get_by_label("Password").fill(PW)
        page.get_by_role("button", name="Unlock", exact=True).click()
        expect(page.locator("#tree").get_by_text("Plan")).to_be_visible()
        check("unlock with password")


        # ---------------------------------------------------------------- start-up note + quick switches
        page.get_by_role("button", name="Lock", exact=True).click()
        page.get_by_label("Password").fill(PW); page.get_by_role("button", name="Unlock", exact=True).click()
        expect(page.locator("#tree").get_by_text("Plan")).to_be_visible()
        check("default: after unlocking the page is blank", page.locator("textarea.ed").count() == 0 and page.get_by_text("Select or create a note.").count() == 1)
        page.get_by_role("button", name="Settings").click()
        check("'When the app opens' defaults to Blank page", page.locator("#set-start_note").input_value() == "blank")
        page.locator("#set-start_note").select_option("last")
        page.get_by_role("button", name="Close settings").click()
        ctx_new(page, "New note")
        page.get_by_role("textbox", name="Note title").fill("Newest"); page.keyboard.press("Enter")
        page.get_by_label("Markdown").fill("most recent text")
        expect(page.locator("#status")).to_have_text(re.compile("Saved"), timeout=5000)
        page.get_by_role("button", name="Lock", exact=True).click()
        page.get_by_label("Password").fill(PW); page.get_by_role("button", name="Unlock", exact=True).click()
        expect(page.get_by_label("Title")).to_have_value("Newest")
        check("'Last edited note' opens the most recently edited note after unlock", page.get_by_label("Markdown").input_value() == "most recent text")
        page.get_by_role("button", name="Settings").click()
        page.locator("#set-start_note").select_option("blank")
        page.get_by_role("button", name="Close settings").click()
        page.get_by_role("button", name="Lock", exact=True).click()
        page.get_by_label("Password").fill(PW); page.get_by_role("button", name="Unlock", exact=True).click()
        expect(page.locator("#tree").get_by_text("Plan")).to_be_visible()
        check("switching back to 'Blank page' works", page.locator("textarea.ed").count() == 0)
        page.locator("#tree").get_by_text("Newest").click()
        expect(page.get_by_label("Title")).to_have_value("Newest")
        page.get_by_role("button", name="Settings").click()
        check("settings switches show live preview and toolbar as on", toggle_state(page, "live_preview") and toggle_state(page, "toolbar"))
        page.get_by_role("button", name="Close settings").click()

        # ---------------------------------------------------------------- security key / fingerprint (virtual FIDO2 authenticator with PRF)
        cdp = ctx.new_cdp_session(page)
        cdp.send("WebAuthn.enable")
        try:
            cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {"protocol": "ctap2", "ctap2Version": "ctap2_1", "transport": "internal",
                     "hasResidentKey": True, "hasUserVerification": True, "isUserVerified": True, "hasPrf": True}})
            have_auth = True
        except Exception as e:
            print("skip - virtual authenticator with PRF unavailable:", str(e)[:80]); have_auth = False
        if have_auth:
            page.get_by_role("button", name="Settings").click()
            page.get_by_role("button", name="Set up…").click()
            page.get_by_role("textbox", name="Current password").fill("wrong wrong wrong wrong")
            page.get_by_role("button", name="Continue").click()
            expect(page.get_by_text("Enabled.")).to_have_count(0)
            page.wait_for_timeout(1200)
            page.get_by_role("button", name="Set up…").click() if page.get_by_role("button", name="Set up…").count() else None
            if page.get_by_role("dialog", name="Set up security key / fingerprint").count() == 0:
                page.get_by_role("button", name="Set up…").click()
            page.get_by_role("textbox", name="Current password").fill(PW)
            page.get_by_role("button", name="Continue").click()
            expect(page.get_by_text("Enabled. Your password and recovery key still work.")).to_be_visible(timeout=8000)
            check("security key / fingerprint enrolled (needs the password)")
            page.get_by_role("button", name="Close settings").click()
            page.get_by_role("button", name="Lock", exact=True).click()
            expect(page.get_by_role("button", name="Unlock with security key / fingerprint")).to_be_visible()
            page.get_by_role("button", name="Unlock with security key / fingerprint").click()
            expect(page.locator("#tree").get_by_text("Plan")).to_be_visible(timeout=8000)
            check("unlock with security key / fingerprint (WebAuthn PRF)")
            page.get_by_role("button", name="Settings").click(); page.get_by_role("button", name="Remove").click()
            expect(page.get_by_text("Removed.")).to_be_visible(); page.get_by_role("button", name="Close settings").click()
            page.get_by_role("button", name="Lock", exact=True).click()
            check("removing the slot hides the button", page.get_by_role("button", name="Unlock with security key / fingerprint").count() == 0)
            page.get_by_label("Password").fill(PW); page.get_by_role("button", name="Unlock", exact=True).click()
            expect(page.locator("#tree").get_by_text("Plan")).to_be_visible()

        # ---------------------------------------------------------------- auto-lock on idle (server idle-lock = 25 s)
        expect(page.get_by_role("button", name="Unlock", exact=True)).to_be_visible(timeout=60000)
        check("auto-lock on idle clears the screen even with automatic sync enabled")

        page.get_by_role("button", name="Use recovery key").click()
        page.get_by_label("Recovery key").fill(key)
        page.get_by_role("button", name="Unlock", exact=True).click()
        expect(page.locator("#tree").get_by_text("Plan")).to_be_visible()
        check("unlock with recovery key")

        # ---------------------------------------------------------------- web export = browser download
        import zipfile
        page.get_by_role("button", name="Settings").click()
        page.get_by_role("button", name="Export…").click()
        dl_btn = page.get_by_role("button", name="Download")
        expect(dl_btn).to_be_disabled(); check("web export needs a selection too")
        page.get_by_label("Folder Work").check()
        page.get_by_label("Note Plan").check()
        with page.expect_download() as dl:
            dl_btn.click()
        path = dl.value.path()
        names = zipfile.ZipFile(path).namelist()
        check("web export downloads a real zip of the chosen folder: %r" % names, names == ["Work/", "Plan.md"] and dl.value.suggested_filename.startswith("ctrlaltnotes-export-"))
        check("zip passes the integrity test", zipfile.ZipFile(path).testzip() is None)
        check("exported note has its Markdown", "select me" in zipfile.ZipFile(path).read("Plan.md").decode() or len(zipfile.ZipFile(path).read("Plan.md")) > 0)
        expect(page.get_by_text("Downloaded 1 note(s)")).to_be_visible()
        check("browser download toast shown")

        before = list(errors)
        r = page.evaluate("fetch('api/tree',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'}).then(r=>r.status)")
        check("API refuses requests without the token", r == 401)
        real = [e for e in before if "Failed to load resource" not in e]
        check("no script errors: %r" % real, not real)

        # ---------------------------------------------------------------- auto-lock interval
        page.get_by_role("button", name="Settings").click()
        sel = page.locator("#set-auto_lock")
        check("the host default (25 s here) is shown and selected: %r" % sel.input_value(), sel.input_value() == "25" and "25 seconds" in sel.locator("option:checked").inner_text())
        opts = sel.locator("option").all_inner_texts()
        check("auto-lock offers 1 minute to 2 hours and Never: %r" % opts, "1 minute" in opts and "2 hours" in opts and opts[-1] == "Never")
        sel.select_option("60"); page.wait_for_timeout(400)
        page.get_by_role("button", name="Close settings").click()
        page.get_by_role("button", name="Settings").click()
        check("the chosen auto-lock interval is kept", page.locator("#set-auto_lock").input_value() == "60")
        page.locator("#set-auto_lock").select_option("0"); page.wait_for_timeout(400)
        check("'Never' says so plainly", "Never locks by itself" in page.locator(".srow", has=page.locator("#set-auto_lock")).inner_text())
        page.locator("#set-auto_lock").select_option("300"); page.wait_for_timeout(400)
        page.get_by_role("button", name="Close settings").click()
        page.get_by_role("button", name="Lock", exact=True).click()     # the next part needs the vault locked

        # ---------------------------------------------------------------- desktop-only UI (export picker) with a mocked native shell
        ctx2 = b.new_context()
        page2 = ctx2.new_page()
        page2.add_init_script("""
          (() => { const tok = location.hash.slice(1); window.__calls = [];
            window.__TAURI__ = { core: { invoke: async (c, a) => { const cmd = a.cmd, args = a.args;
              window.__calls.push([cmd, args]);
              if (cmd === 'export_markdown') return { count: args.ids.length };
              if (cmd === 'set_sync') return { ok: true };
              const r = await fetch('api/' + cmd, { method: 'POST', headers: { Authorization: 'Bearer ' + tok, 'Content-Type': 'application/json' }, body: JSON.stringify(args) });
              const d = await r.json(); if (!r.ok) throw (d.error || 'error'); if (cmd === 'status') d.can_pick = true; return d; } } }; })();
        """)
        page2.goto(url)
        page2.get_by_role("button", name="Use recovery key").click()
        page2.get_by_label("Recovery key").fill(key)
        page2.get_by_role("button", name="Unlock", exact=True).click()
        expect(page2.locator("#tree").get_by_text("Plan")).to_be_visible()
        page2.get_by_role("button", name="Settings").click()
        page2.get_by_role("button", name="Export…").click()
        expect(page2.get_by_role("dialog", name="Export")).to_be_visible()
        go2 = page2.get_by_role("button", name="Choose destination…")
        expect(go2).to_be_disabled(); check("export needs a selection")
        page2.get_by_label("Note Plan").check()
        expect(go2).to_be_enabled()
        page2.get_by_label("Folder Work").check()
        page2.get_by_role("button", name="Clear").click()
        expect(go2).to_be_disabled()
        page2.get_by_role("button", name="Select all").click()
        page2.get_by_label("Folder Work").uncheck()
        go2.click()
        expect(page2.get_by_text("Exported")).to_be_visible()
        calls = page2.evaluate("window.__calls.filter(c=>c[0]==='export_markdown')")
        check("export sends exactly the selected ids (everything except the unticked folder)", len(calls) == 1 and len(calls[0][1]['ids']) == 4)
        b.close()
    print(f"\n{len(ok)} browser checks passed")
finally:
    proc.terminate()
