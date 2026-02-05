import "@testing-library/jest-dom/vitest";
import { afterEach, beforeEach, vi } from "vitest";
import { init, register, waitLocale } from "svelte-i18n";
import { _testResetState } from "../lib/auth.svelte.ts";

register("en", () => import("../locales/en.json"));

init({
  fallbackLocale: "en",
  initialLocale: "en",
});

Object.defineProperty(window, "matchMedia", {
  writable: true,
  configurable: true,
  value: vi.fn((query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: vi.fn(),
    removeListener: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  })),
});

let locationHash = "";

Object.defineProperty(window, "location", {
  value: {
    get hash() {
      return locationHash;
    },
    set hash(value: string) {
      locationHash = value.startsWith("#") ? value : `#${value}`;
    },
    href: "http://localhost:3000/",
    origin: "http://localhost:3000",
    pathname: "/",
    search: "",
    assign: vi.fn(),
    replace: vi.fn(),
    reload: vi.fn(),
  },
  writable: true,
  configurable: true,
});

beforeEach(async () => {
  vi.clearAllMocks();
  locationHash = "";
  _testResetState();
  await waitLocale();
});

afterEach(() => {
  vi.restoreAllMocks();
});
