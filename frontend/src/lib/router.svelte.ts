let currentPath = $state(window.location.hash.slice(1) || '/')
window.addEventListener('hashchange', () => {
  currentPath = window.location.hash.slice(1) || '/'
})
export function navigate(path: string) {
  window.location.hash = path
}
export function getCurrentPath() {
  return currentPath
}
