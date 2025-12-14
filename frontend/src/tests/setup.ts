import '@testing-library/jest-dom/vitest'
import { vi, beforeEach, afterEach } from 'vitest'
import { _testReset } from '../lib/auth.svelte'
let locationHash = ''
Object.defineProperty(window, 'location', {
  value: {
    get hash() { return locationHash },
    set hash(value: string) {
      locationHash = value.startsWith('#') ? value : `#${value}`
    },
    href: 'http://localhost:3000/',
    origin: 'http://localhost:3000',
    pathname: '/',
    search: '',
    assign: vi.fn(),
    replace: vi.fn(),
    reload: vi.fn(),
  },
  writable: true,
  configurable: true,
})
beforeEach(() => {
  vi.clearAllMocks()
  localStorage.clear()
  sessionStorage.clear()
  locationHash = ''
  _testReset()
})
afterEach(() => {
  vi.restoreAllMocks()
})
