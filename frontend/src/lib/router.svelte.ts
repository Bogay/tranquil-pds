let currentPath = $state(getPathWithoutQuery(window.location.hash.slice(1) || '/'))

function getPathWithoutQuery(hash: string): string {
  const queryIndex = hash.indexOf('?')
  return queryIndex === -1 ? hash : hash.slice(0, queryIndex)
}

window.addEventListener('hashchange', () => {
  currentPath = getPathWithoutQuery(window.location.hash.slice(1) || '/')
})

export function navigate(path: string) {
  window.location.hash = path
}

export function getCurrentPath() {
  return currentPath
}
