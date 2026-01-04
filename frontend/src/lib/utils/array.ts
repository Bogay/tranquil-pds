import type { Option } from './option'

export function first<T>(arr: readonly T[]): Option<T> {
  return arr[0] ?? null
}

export function last<T>(arr: readonly T[]): Option<T> {
  return arr[arr.length - 1] ?? null
}

export function at<T>(arr: readonly T[], index: number): Option<T> {
  if (index < 0) index = arr.length + index
  return arr[index] ?? null
}

export function find<T>(arr: readonly T[], predicate: (t: T) => boolean): Option<T> {
  return arr.find(predicate) ?? null
}

export function findMap<T, U>(arr: readonly T[], fn: (t: T) => Option<U>): Option<U> {
  for (const item of arr) {
    const result = fn(item)
    if (result != null) return result
  }
  return null
}

export function findIndex<T>(arr: readonly T[], predicate: (t: T) => boolean): Option<number> {
  const index = arr.findIndex(predicate)
  return index >= 0 ? index : null
}

export function partition<T>(
  arr: readonly T[],
  predicate: (t: T) => boolean
): [T[], T[]] {
  const pass: T[] = []
  const fail: T[] = []
  for (const item of arr) {
    if (predicate(item)) {
      pass.push(item)
    } else {
      fail.push(item)
    }
  }
  return [pass, fail]
}

export function groupBy<T, K extends string | number>(
  arr: readonly T[],
  keyFn: (t: T) => K
): Record<K, T[]> {
  const result = {} as Record<K, T[]>
  for (const item of arr) {
    const key = keyFn(item)
    if (!result[key]) {
      result[key] = []
    }
    result[key].push(item)
  }
  return result
}

export function unique<T>(arr: readonly T[]): T[] {
  return [...new Set(arr)]
}

export function uniqueBy<T, K>(arr: readonly T[], keyFn: (t: T) => K): T[] {
  const seen = new Set<K>()
  const result: T[] = []
  for (const item of arr) {
    const key = keyFn(item)
    if (!seen.has(key)) {
      seen.add(key)
      result.push(item)
    }
  }
  return result
}

export function sortBy<T>(arr: readonly T[], keyFn: (t: T) => number | string): T[] {
  return [...arr].sort((a, b) => {
    const ka = keyFn(a)
    const kb = keyFn(b)
    if (ka < kb) return -1
    if (ka > kb) return 1
    return 0
  })
}

export function sortByDesc<T>(arr: readonly T[], keyFn: (t: T) => number | string): T[] {
  return [...arr].sort((a, b) => {
    const ka = keyFn(a)
    const kb = keyFn(b)
    if (ka > kb) return -1
    if (ka < kb) return 1
    return 0
  })
}

export function chunk<T>(arr: readonly T[], size: number): T[][] {
  const result: T[][] = []
  for (let i = 0; i < arr.length; i += size) {
    result.push(arr.slice(i, i + size))
  }
  return result
}

export function zip<T, U>(a: readonly T[], b: readonly U[]): [T, U][] {
  const length = Math.min(a.length, b.length)
  const result: [T, U][] = []
  for (let i = 0; i < length; i++) {
    result.push([a[i], b[i]])
  }
  return result
}

export function zipWith<T, U, R>(
  a: readonly T[],
  b: readonly U[],
  fn: (t: T, u: U) => R
): R[] {
  const length = Math.min(a.length, b.length)
  const result: R[] = []
  for (let i = 0; i < length; i++) {
    result.push(fn(a[i], b[i]))
  }
  return result
}

export function intersperse<T>(arr: readonly T[], separator: T): T[] {
  if (arr.length <= 1) return [...arr]
  const result: T[] = [arr[0]]
  for (let i = 1; i < arr.length; i++) {
    result.push(separator, arr[i])
  }
  return result
}

export function range(start: number, end: number): number[] {
  const result: number[] = []
  for (let i = start; i < end; i++) {
    result.push(i)
  }
  return result
}

export function isEmpty<T>(arr: readonly T[]): boolean {
  return arr.length === 0
}

export function isNonEmpty<T>(arr: readonly T[]): arr is [T, ...T[]] {
  return arr.length > 0
}

export function sum(arr: readonly number[]): number {
  return arr.reduce((acc, n) => acc + n, 0)
}

export function sumBy<T>(arr: readonly T[], fn: (t: T) => number): number {
  return arr.reduce((acc, t) => acc + fn(t), 0)
}

export function maxBy<T>(arr: readonly T[], fn: (t: T) => number): Option<T> {
  if (arr.length === 0) return null
  let max = arr[0]
  let maxValue = fn(max)
  for (let i = 1; i < arr.length; i++) {
    const value = fn(arr[i])
    if (value > maxValue) {
      max = arr[i]
      maxValue = value
    }
  }
  return max
}

export function minBy<T>(arr: readonly T[], fn: (t: T) => number): Option<T> {
  if (arr.length === 0) return null
  let min = arr[0]
  let minValue = fn(min)
  for (let i = 1; i < arr.length; i++) {
    const value = fn(arr[i])
    if (value < minValue) {
      min = arr[i]
      minValue = value
    }
  }
  return min
}
