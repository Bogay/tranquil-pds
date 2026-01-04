export type Option<T> = T | null | undefined

export function isSome<T>(opt: Option<T>): opt is T {
  return opt != null
}

export function isNone<T>(opt: Option<T>): opt is null | undefined {
  return opt == null
}

export function map<T, U>(opt: Option<T>, fn: (t: T) => U): Option<U> {
  return isSome(opt) ? fn(opt) : null
}

export function flatMap<T, U>(opt: Option<T>, fn: (t: T) => Option<U>): Option<U> {
  return isSome(opt) ? fn(opt) : null
}

export function filter<T>(opt: Option<T>, predicate: (t: T) => boolean): Option<T> {
  return isSome(opt) && predicate(opt) ? opt : null
}

export function getOrElse<T>(opt: Option<T>, defaultValue: T): T {
  return isSome(opt) ? opt : defaultValue
}

export function getOrElseLazy<T>(opt: Option<T>, fn: () => T): T {
  return isSome(opt) ? opt : fn()
}

export function getOrThrow<T>(opt: Option<T>, error?: string | Error): T {
  if (isSome(opt)) return opt
  if (error instanceof Error) throw error
  throw new Error(error ?? 'Expected value but got null/undefined')
}

export function tap<T>(opt: Option<T>, fn: (t: T) => void): Option<T> {
  if (isSome(opt)) fn(opt)
  return opt
}

export function match<T, U>(
  opt: Option<T>,
  handlers: { some: (t: T) => U; none: () => U }
): U {
  return isSome(opt) ? handlers.some(opt) : handlers.none()
}

export function toArray<T>(opt: Option<T>): T[] {
  return isSome(opt) ? [opt] : []
}

export function fromArray<T>(arr: T[]): Option<T> {
  return arr.length > 0 ? arr[0] : null
}

export function zip<T, U>(a: Option<T>, b: Option<U>): Option<[T, U]> {
  return isSome(a) && isSome(b) ? [a, b] : null
}

export function zipWith<T, U, R>(
  a: Option<T>,
  b: Option<U>,
  fn: (t: T, u: U) => R
): Option<R> {
  return isSome(a) && isSome(b) ? fn(a, b) : null
}

export function or<T>(a: Option<T>, b: Option<T>): Option<T> {
  return isSome(a) ? a : b
}

export function orLazy<T>(a: Option<T>, fn: () => Option<T>): Option<T> {
  return isSome(a) ? a : fn()
}

export function and<T, U>(a: Option<T>, b: Option<U>): Option<U> {
  return isSome(a) ? b : null
}
