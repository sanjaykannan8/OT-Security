import { CaretDown, Check } from "@phosphor-icons/react";
import { type KeyboardEvent, type ReactNode, useCallback, useEffect, useId, useLayoutEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";

export interface Option {
  value: string;
  label: string;
}

/** Where the popup sits, measured from the trigger. One of top/bottom is set, never both. */
interface Placement {
  top?: number;
  bottom?: number;
  left: number;
  width: number;
}

const TYPEAHEAD_MS = 700;
const ITEM_H = 33;

/**
 * Filter dropdown: an ARIA select-only combobox.
 *
 * Written by hand rather than taken from a component library because of two constraints
 * that ruled out both alternatives:
 *
 *  - A native `<select>` lets the browser draw the option list, but the list is clipped by
 *    the table's sticky header, which is what it replaced.
 *  - Base UI's Select positions its popup through an inline `style` attribute, and the API
 *    serves `style-src 'self'` with no `unsafe-inline`, so the browser strips it and the
 *    popup never positions.
 *
 * The popup here is portalled to `document.body` and positioned through React's `style`
 * prop, which writes via CSSOM and so is unaffected by that CSP. Focus stays on the
 * trigger and `aria-activedescendant` tracks the active option, per the ARIA pattern.
 */
export function FilterSelect({
  value,
  onChange,
  options,
  label,
  icon,
  width,
}: {
  value: string;
  onChange: (value: string) => void;
  options: Option[];
  label: string;
  icon?: ReactNode;
  width?: number;
}) {
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const [pos, setPos] = useState<Placement | null>(null);
  const trigger = useRef<HTMLButtonElement | null>(null);
  const list = useRef<HTMLUListElement | null>(null);
  const typed = useRef({ text: "", at: 0 });
  const listId = useId().replace(/[^a-zA-Z0-9]/g, "");

  const selectedIndex = Math.max(
    0,
    options.findIndex((o) => o.value === value),
  );
  const selected = options[selectedIndex];

  /** Prefer below the trigger; flip above when there is more room there. */
  const place = useCallback(() => {
    const el = trigger.current;
    if (!el) return;
    const r = el.getBoundingClientRect();
    const below = window.innerHeight - r.bottom;
    const needed = Math.min(300, options.length * ITEM_H + 10);
    const flip = below < needed && r.top > below;
    const width = Math.max(r.width, 152);
    setPos({
      ...(flip ? { bottom: window.innerHeight - r.top + 6 } : { top: r.bottom + 6 }),
      // Keep the popup on screen when the trigger sits near the right edge.
      left: Math.max(8, Math.min(r.left, window.innerWidth - width - 8)),
      width,
    });
  }, [options.length]);

  const close = useCallback((refocus = true) => {
    setOpen(false);
    if (refocus) trigger.current?.focus();
  }, []);

  const openList = useCallback(() => {
    place();
    setActive(selectedIndex);
    setOpen(true);
  }, [place, selectedIndex]);

  useLayoutEffect(() => {
    if (open) place();
  }, [open, place]);

  useEffect(() => {
    if (!open) return;
    const reposition = () => place();
    // Capture phase: the console's scrolling happens inside .content, not on window.
    window.addEventListener("scroll", reposition, true);
    window.addEventListener("resize", reposition);
    const onDown = (e: Event) => {
      const t = e.target as Node;
      if (!trigger.current?.contains(t) && !list.current?.contains(t)) close(false);
    };
    document.addEventListener("pointerdown", onDown, true);
    return () => {
      window.removeEventListener("scroll", reposition, true);
      window.removeEventListener("resize", reposition);
      document.removeEventListener("pointerdown", onDown, true);
    };
  }, [open, place, close]);

  useEffect(() => {
    if (open) list.current?.querySelector<HTMLElement>(`[data-i="${active}"]`)?.scrollIntoView({ block: "nearest" });
  }, [open, active]);

  const commit = (i: number) => {
    const o = options[i];
    if (o) onChange(o.value);
    close();
  };

  const onKeyDown = (e: KeyboardEvent<HTMLButtonElement>) => {
    if (!open) {
      if (e.key === "ArrowDown" || e.key === "ArrowUp" || e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        openList();
      }
      return;
    }
    switch (e.key) {
      case "Escape":
        e.preventDefault();
        close();
        return;
      case "Enter":
      case " ":
        e.preventDefault();
        commit(active);
        return;
      case "ArrowDown":
        e.preventDefault();
        setActive((i) => Math.min(options.length - 1, i + 1));
        return;
      case "ArrowUp":
        e.preventDefault();
        setActive((i) => Math.max(0, i - 1));
        return;
      case "Home":
        e.preventDefault();
        setActive(0);
        return;
      case "End":
        e.preventDefault();
        setActive(options.length - 1);
        return;
      case "Tab":
        close(false);
        return;
      default:
        if (e.key.length === 1 && /\S/.test(e.key)) {
          const now = Date.now();
          typed.current.text = now - typed.current.at < TYPEAHEAD_MS ? typed.current.text + e.key : e.key;
          typed.current.at = now;
          const q = typed.current.text.toLowerCase();
          const hit = options.findIndex((o) => o.label.toLowerCase().startsWith(q));
          if (hit >= 0) setActive(hit);
        }
    }
  };

  return (
    <>
      <button
        ref={trigger}
        type="button"
        className="sel"
        style={width ? { width } : undefined}
        role="combobox"
        aria-label={label}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-controls={open ? listId : undefined}
        aria-activedescendant={open ? `${listId}-${active}` : undefined}
        onClick={() => (open ? close() : openList())}
        onKeyDown={onKeyDown}
      >
        {icon}
        <span className="sel-value">{selected?.label}</span>
        <CaretDown className="sel-caret" size={12} weight="bold" aria-hidden="true" />
      </button>

      {open &&
        pos &&
        createPortal(
          <ul
            id={listId}
            ref={list}
            role="listbox"
            aria-label={label}
            className="sel-popup"
            style={{ top: pos.top, bottom: pos.bottom, left: pos.left, minWidth: pos.width }}
          >
            {options.map((o, i) => (
              <li
                key={o.value || "any"}
                id={`${listId}-${i}`}
                data-i={i}
                role="option"
                aria-selected={o.value === value}
                className={`sel-item${i === active ? " is-active" : ""}${o.value === value ? " is-selected" : ""}`}
                onPointerEnter={() => setActive(i)}
                onClick={() => commit(i)}
              >
                <span>{o.label}</span>
                {o.value === value && <Check className="sel-ind" size={13} weight="bold" aria-hidden="true" />}
              </li>
            ))}
          </ul>,
          document.body,
        )}
    </>
  );
}
