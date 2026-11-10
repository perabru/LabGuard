"""Capture and check the Sites layout on an isolated graphical CI display.

Example: xvfb-run -a -s "-screen 0 1600x1000x24" python
packaging/validate_sites_gui.py --output-dir artifacts/sites-gui

Uses only DemoTransport, a temporary local profile and disabled updates.
Pillow, already in requirements-build.txt, is required for the screenshots.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def descendants(widget):
    for child in widget.winfo_children():
        yield child
        yield from descendants(child)


def controls_for(app):
    from labguard.ui import ActionButton

    controls = {"table": app.domains_table,
                "block": app.domain_block_selected_button,
                "release": app.domain_remove_button,
                "add_and_block": app.domain_add_button}
    children = list(descendants(app._pages["sites"]))
    for name, variable in (("search", app.site_search),
                           ("category_filter", app.site_category),
                           ("state_filter", app.site_state),
                           ("selection_note", app.site_selection_text)):
        matches = [child for child in children if "textvariable" in child.keys()
                   and str(child.cget("textvariable")) == str(variable)]
        if len(matches) != 1:
            raise RuntimeError(f"Expected one visible control for {name}; found {len(matches)}")
        controls[name] = matches[0]
    for child in children:
        if isinstance(child, ActionButton) and child not in controls.values():
            controls[f"button_{len(controls)}"] = child
    return controls


def geometry(widget, app):
    left = widget.winfo_rootx() - app.winfo_rootx()
    top = widget.winfo_rooty() - app.winfo_rooty()
    width, height = widget.winfo_width(), widget.winfo_height()
    result = {"x": left, "y": top, "width": width, "height": height,
              "mapped": bool(widget.winfo_ismapped()),
              "inside_window": (left >= 0 and top >= 0
                                and left + width <= app.winfo_width()
                                and top + height <= app.winfo_height()),
              "clipped_by_parent": False}
    parent = widget.master
    while parent is not None and parent is not app:
        x = widget.winfo_rootx() - parent.winfo_rootx()
        y = widget.winfo_rooty() - parent.winfo_rooty()
        if x < 0 or y < 0 or x + width > parent.winfo_width() or y + height > parent.winfo_height():
            result["clipped_by_parent"] = True
        parent = parent.master
    for option in ("text", "state"):
        try:
            result[option] = str(widget.cget(option))
        except Exception:
            pass
    return result


def capture_layout(app, output_dir, width, height):
    from PIL import ImageGrab

    app.geometry(f"{width}x{height}+0+0")
    app.update()
    app.domains_table.selection_set("poki.com")
    app.domains_table.focus("poki.com")
    app.domains_table.see("poki.com")
    app._refresh_mutation_controls()
    app.update()
    app.update_idletasks()
    filename = f"sites-{width}x{height}.png"
    left, top = app.winfo_rootx(), app.winfo_rooty()
    ImageGrab.grab(bbox=(left, top, left + app.winfo_width(), top + app.winfo_height()),
                   xdisplay=os.environ.get("DISPLAY")).save(output_dir / filename)
    result = {"requested_size": [width, height],
              "actual_size": [app.winfo_width(), app.winfo_height()],
              "screenshot": filename,
              "controls": {name: geometry(widget, app) for name, widget in controls_for(app).items()},
              "selected": list(app.domains_table.selection()),
              "selected_domain_bounds": list(app.domains_table.bbox("poki.com", "domain")),
              "site_count": app.site_count.get(),
              "selection_text": app.site_selection_text.get(),
              "errors": []}
    if result["actual_size"] != result["requested_size"]:
        result["errors"].append("The window did not reach the requested size")
    for name, control in result["controls"].items():
        if (not control["mapped"] or not control["inside_window"] or control["clipped_by_parent"]
                or control["width"] <= 1 or control["height"] <= 1):
            result["errors"].append(f"Control is hidden or outside its visible bounds: {name}")
    bounds = result["selected_domain_bounds"]
    table = result["controls"]["table"]
    if (result["selected"] != ["poki.com"] or len(bounds) != 4
            or bounds[2] <= 0 or bounds[3] <= 0 or bounds[0] < 0 or bounds[1] < 0
            or bounds[0] + bounds[2] > table["width"] or bounds[1] + bounds[3] > table["height"]):
        result["errors"].append("The selected poki.com domain is not visible inside the table")
    return result


def run(output_dir, report):
    from labguard.demo import DemoTransport
    from labguard.simple_gui import App

    with tempfile.TemporaryDirectory(prefix="labguard-sites-qa-") as profile:
        with patch("pathlib.Path.home", return_value=Path(profile)):
            app = None
            try:
                app = App(DemoTransport(), updates_enabled=False)
                app.after_cancel(app._initial_id)
                app._initial_id = None
                if app.winfo_screenwidth() < 1240 or app.winfo_screenheight() < 820:
                    raise RuntimeError("The CI display must be at least 1240x820; use Xvfb 1600x1000x24")
                app._apply_snapshot(app.transport.request("snapshot"))
                app.show_page("sites")
                for width, height in ((1240, 820), (1000, 700)):
                    report["layouts"].append(capture_layout(app, output_dir, width, height))
            finally:
                if app is not None:
                    try:
                        app.close()
                    finally:
                        try:
                            app.destroy()
                        except Exception:
                            pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True,
                        help="Directory for the two PNG screenshots and layout-report.json")
    args = parser.parse_args()
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    report = {"transport": "demo", "updates_enabled": False, "layouts": [], "passed": False}
    try:
        run(output_dir, report)
        report["passed"] = len(report["layouts"]) == 2 and not any(row["errors"] for row in report["layouts"])
    except Exception as error:
        report["error"] = f"{type(error).__name__}: {error}"
    (output_dir / "layout-report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
