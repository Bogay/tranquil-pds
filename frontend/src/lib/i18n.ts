import { register, init, getLocaleFromNavigator, locale, _ } from 'svelte-i18n'

const LOCALE_STORAGE_KEY = 'tranquil-pds-locale'

const SUPPORTED_LOCALES = ['en', 'zh', 'ja', 'ko'] as const
export type SupportedLocale = typeof SUPPORTED_LOCALES[number]

export const localeNames: Record<SupportedLocale, string> = {
  en: 'English',
  zh: '中文',
  ja: '日本語',
  ko: '한국어'
}

register('en', () => import('../locales/en.json'))
register('zh', () => import('../locales/zh.json'))
register('ja', () => import('../locales/ja.json'))
register('ko', () => import('../locales/ko.json'))

function getInitialLocale(): string {
  const stored = localStorage.getItem(LOCALE_STORAGE_KEY)
  if (stored && SUPPORTED_LOCALES.includes(stored as SupportedLocale)) {
    return stored
  }

  const browserLocale = getLocaleFromNavigator()
  if (browserLocale) {
    const lang = browserLocale.split('-')[0]
    if (SUPPORTED_LOCALES.includes(lang as SupportedLocale)) {
      return lang
    }
  }

  return 'en'
}

export function initI18n() {
  init({
    fallbackLocale: 'en',
    initialLocale: getInitialLocale()
  })
}

export function setLocale(newLocale: SupportedLocale) {
  locale.set(newLocale)
  localStorage.setItem(LOCALE_STORAGE_KEY, newLocale)
  document.documentElement.lang = newLocale
}

export function getSupportedLocales(): SupportedLocale[] {
  return [...SUPPORTED_LOCALES]
}

export { locale, _ }
