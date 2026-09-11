"""Turns a ScanResult into plain-language advice (HTML for a QTextBrowser)."""
from __future__ import annotations

import html
import os

from ..model import CATEGORIES, Risk, ScanResult, human_size
from ..settings import Settings


def _card(title: str, body: str, tone: str = "info") -> str:
    colors = {"good": "#2e7d32", "warn": "#b26a00", "info": "#1565c0", "bad": "#c62828", "muted": "#616161"}
    c = colors.get(tone, colors["info"])
    return (f'<div style="margin:0 0 10px 0;padding:8px 10px;border-left:4px solid {c};'
            f'background:rgba(127,127,127,0.08);border-radius:4px;">'
            f'<div style="font-weight:600;color:{c};margin-bottom:3px;">{html.escape(title)}</div>'
            f'<div>{body}</div></div>')


def build_suggestions(result: ScanResult | None, settings: Settings) -> str:
    if result is None:
        return ("<p style='color:#888'>Pick a drive or folder and press <b>Scan</b>.<br><br>"
                "SmartCleaner never deletes anything by itself. After the scan it shows what it found, "
                "pre-selects only the items that are safe to remove, and explains the rest so you can decide.</p>"
                + _card("Computer feeling slow right now?",
                        "<b>Memory &amp; caches</b> in the toolbar frees RAM and VRAM without touching any file: "
                        "it trims programs' working sets, purges cached pages, restarts the graphics driver to "
                        "reclaim leaked VRAM, and flushes DNS, thumbnail, Store and font caches.", "info"))

    by_cat = result.by_category()
    esc = html.escape
    parts: list[str] = []

    # disk state
    if result.disk_total:
        pct_free = result.disk_free / result.disk_total * 100
        tone = "bad" if pct_free < 10 else "warn" if pct_free < 20 else "good"
        parts.append(_card(
            f"{esc(result.root)} - {human_size(result.disk_free)} free of {human_size(result.disk_total)} ({pct_free:.0f}% free)",
            f"Scanned {result.stats.files_seen:,} files ({human_size(result.stats.bytes_seen)}) in "
            f"{result.stats.seconds:.0f}s.", tone))

    safe = [f for f in result.findings if f.risk == Risk.SAFE]
    safe_bytes = sum(f.size for f in safe)
    suggested = [f for f in result.findings if f.risk == Risk.REVIEW and f.suggested]
    sug_bytes = sum(f.size for f in suggested)

    if safe:
        cats = sorted({CATEGORIES[f.category].title for f in safe})
        parts.append(_card(
            f"Safe to clean now: {human_size(safe_bytes)}",
            f"{len(safe):,} items in {esc(', '.join(cats))}. These are pre-selected. "
            f"Press <b>Move to Recycle Bin</b> to reclaim the space.", "good"))
    else:
        parts.append(_card("Nothing obviously safe to remove", "This location is already tidy.", "good"))

    if suggested:
        parts.append(_card(
            f"Recommended after a quick look: {human_size(sug_bytes)}",
            f"{len(suggested):,} items - duplicate copies, installers you already ran, stale project "
            f"dependencies. Use <b>Select safe + suggested</b> to include them, then glance through the list.",
            "warn"))

    dupes = [f for f in by_cat.get("dupes", []) if f.risk == Risk.REVIEW]
    if dupes:
        groups = len({f.group for f in dupes})
        parts.append(_card(
            f"Duplicates: {human_size(sum(f.size for f in dupes))} wasted in {groups:,} groups",
            "Files with byte-identical content. The copy marked <b>KEEP</b> is the one in the most sensible "
            "place (not Downloads, not named 'Copy'). Use <i>Keep this one instead</i> in Details if you disagree.",
            "warn"))

    inst = by_cat.get("installers", [])
    if inst:
        parts.append(_card(
            f"Old installers: {human_size(sum(f.size for f in inst))}",
            f"{len(inst):,} setup files older than {settings.installer_age_days} days in Downloads. "
            "If the programs are installed, the installers are no longer needed.", "warn"))

    dev = by_cat.get("dev", [])
    if dev:
        stale = [f for f in dev if f.suggested]
        parts.append(_card(
            f"Developer leftovers: {human_size(sum(f.size for f in dev))}",
            f"{len(dev):,} folders such as node_modules, virtual envs and build outputs. "
            f"{len(stale):,} belong to projects idle for {settings.stale_project_days}+ days and are suggested; "
            "everything is restorable with the project's install/build command.", "info"))

    large = sorted(by_cat.get("large", []), key=lambda f: -f.size)
    if large:
        rows = "".join(
            f"<li>{human_size(f.size)} - {esc(os.path.basename(f.path))}"
            f"{' <i>(' + esc(f.reason.split('. ', 1)[1]) + ')</i>' if '. ' in f.reason else ''}</li>"
            for f in large[:6])
        parts.append(_card(
            f"Where the space goes: {len(large):,} large files, {human_size(sum(f.size for f in large))}",
            f"<ul style='margin:4px 0 0 16px;padding:0'>{rows}</ul>"
            + ("<div style='margin-top:4px'>…and more in the <b>Large files</b> category.</div>" if len(large) > 6 else ""),
            "info"))

    win = by_cat.get("windows", [])
    if win:
        parts.append(_card(
            f"Windows leftovers: {human_size(sum(f.size for f in win))}",
            "Previous installation / update caches. These need Administrator rights and are best removed with "
            "<b>Settings &gt; System &gt; Storage &gt; Cleanup recommendations</b>, but you can try here too.", "info"))

    dbg = by_cat.get("debug", [])
    if dbg:
        big = max(dbg, key=lambda f: f.size)
        parts.append(_card(
            f"Debug & diagnostic files: {human_size(sum(f.size for f in dbg))}",
            f"{len(dbg):,} crash dumps, error reports and traces. Windows and apps write these when something "
            f"crashes; they only matter if you are sending one to a developer right now."
            + (f" Biggest: {esc(os.path.basename(big.path))} ({human_size(big.size)})." if big.size > 50 << 20 else ""),
            "good"))

    hib = [f for f in result.findings if os.path.basename(f.path).lower() == "hiberfil.sys"]
    if hib:
        parts.append(_card(
            f"Hibernation file: {human_size(hib[0].size)}",
            "If you never use Hibernate, run <code>powercfg /h off</code> in an Administrator prompt to "
            "reclaim it (this also turns off Fast Startup).", "muted"))

    if result.stats.denied_paths:
        parts.append(_card(
            f"{len(result.stats.denied_paths):,} folders could not be read",
            ("Restart SmartCleaner as Administrator to include system temp folders and other users' data."
             if not result.stats.is_admin else "Some folders are locked even for Administrators; that is normal.")
            + "<br><span style='color:#888'>" + "<br>".join(esc(p) for p in result.stats.denied_paths[:5]) + "</span>",
            "muted"))

    parts.append(_card(
        "RAM, VRAM and live caches",
        "Disk space is only half of it. <b>Memory &amp; caches</b> in the toolbar trims RAM, purges the standby "
        "list, frees leaked VRAM and flushes DNS / thumbnail / Store caches - nothing on disk is deleted.", "muted"))

    parts.append(
        "<p style='color:#888;font-size:90%;margin-top:6px'>Items marked <b>Protected</b> or <b>Keep</b> cannot be "
        "deleted from here. Nothing is removed until you press a clean button, and by default everything goes to the "
        "Recycle Bin so you can undo.</p>")
    return "".join(parts)
