const APP_BASE = "/app";

function getAppPath(): string {
  const pathname = globalThis.location.pathname;
  if (pathname.startsWith(APP_BASE)) {
    const path = pathname.slice(APP_BASE.length) || "/";
    return path.startsWith("/") ? path : "/" + path;
  }
  return "/";
}

let currentPath = $state(getAppPath());

globalThis.addEventListener("popstate", () => {
  currentPath = getAppPath();
});

export function navigate(path: string, replace = false) {
  const fullPath = APP_BASE + (path.startsWith("/") ? path : "/" + path);
  if (replace) {
    globalThis.history.replaceState(null, "", fullPath);
  } else {
    globalThis.history.pushState(null, "", fullPath);
  }
  currentPath = path.startsWith("/") ? path : "/" + path;
}

export function getCurrentPath() {
  return currentPath;
}

export function getFullUrl(path: string): string {
  return APP_BASE + (path.startsWith("/") ? path : "/" + path);
}
