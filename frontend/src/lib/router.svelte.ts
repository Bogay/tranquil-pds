let currentPath = $state(
  getPathWithoutQuery(globalThis.location.hash.slice(1) || "/"),
);

function getPathWithoutQuery(hash: string): string {
  const queryIndex = hash.indexOf("?");
  return queryIndex === -1 ? hash : hash.slice(0, queryIndex);
}

globalThis.addEventListener("hashchange", () => {
  currentPath = getPathWithoutQuery(globalThis.location.hash.slice(1) || "/");
});

export function navigate(path: string) {
  currentPath = path;
  globalThis.location.hash = path;
}

export function getCurrentPath() {
  return currentPath;
}
