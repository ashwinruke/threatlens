import { useEffect, useState } from "react";

// Light, dark, or follow the computer. The choice is remembered in this browser;
// index.html applies it before the page first draws.
const KEY = "threatlens-theme";
const OPTIONS = [
  { value: "light", label: "Light theme", icon: (
    <><circle cx="8" cy="8" r="3" /><path d="M8 1.5v1.5M8 13v1.5M1.5 8H3M13 8h1.5M3.4 3.4l1 1M11.6 11.6l1 1M3.4 12.6l1-1M11.6 4.4l1-1" /></>
  ) },
  { value: "system", label: "Match my computer", icon: (
    <><rect x="1.75" y="2.75" width="12.5" height="8.5" rx="1.25" /><path d="M5.5 14h5M8 11.25V14" /></>
  ) },
  { value: "dark", label: "Dark theme", icon: <path d="M13.5 9.6A5.5 5.5 0 0 1 6.4 2.5a5.5 5.5 0 1 0 7.1 7.1Z" /> },
];

function read() {
  try {
    const saved = localStorage.getItem(KEY);
    return saved === "light" || saved === "dark" ? saved : "system";
  } catch {
    return "system";
  }
}

export default function ThemeSwitch() {
  const [theme, setTheme] = useState(read);

  useEffect(() => {
    const root = document.documentElement;
    if (theme === "system") delete root.dataset.theme;
    else root.dataset.theme = theme;
    try {
      if (theme === "system") localStorage.removeItem(KEY);
      else localStorage.setItem(KEY, theme);
    } catch {
      /* private browsing: the choice lasts until the tab closes */
    }
  }, [theme]);

  return (
    <div className="theme-switch" role="radiogroup" aria-label="Theme">
      {OPTIONS.map((option) => (
        <button key={option.value} type="button" role="radio" aria-checked={theme === option.value}
          aria-label={option.label} title={option.label}
          className={`theme-switch__option ${theme === option.value ? "is-active" : ""}`}
          onClick={() => setTheme(option.value)}>
          <svg viewBox="0 0 16 16" width="15" height="15" fill="none" stroke="currentColor" strokeWidth="1.4"
            strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{option.icon}</svg>
        </button>
      ))}
    </div>
  );
}
