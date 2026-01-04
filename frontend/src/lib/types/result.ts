export type Result<T, E = Error> =
  | { ok: true; value: T }
  | { ok: false; error: E }

export function ok<T>(value: T): Result<T, never> {
  return { ok: true, value }
}

export function err<E>(error: E): Result<never, E> {
  return { ok: false, error }
}

export function isOk<T, E>(result: Result<T, E>): result is { ok: true; value: T } {
  return result.ok
}

export function isErr<T, E>(result: Result<T, E>): result is { ok: false; error: E } {
  return !result.ok
}

export function map<T, U, E>(result: Result<T, E>, fn: (t: T) => U): Result<U, E> {
  return result.ok ? ok(fn(result.value)) : result
}

export function mapErr<T, E, F>(result: Result<T, E>, fn: (e: E) => F): Result<T, F> {
  return result.ok ? result : err(fn(result.error))
}

export function flatMap<T, U, E>(result: Result<T, E>, fn: (t: T) => Result<U, E>): Result<U, E> {
  return result.ok ? fn(result.value) : result
}

export function unwrap<T, E>(result: Result<T, E>): T {
  if (result.ok) return result.value
  throw result.error instanceof Error ? result.error : new Error(String(result.error))
}

export function unwrapOr<T, E>(result: Result<T, E>, defaultValue: T): T {
  return result.ok ? result.value : defaultValue
}

export function unwrapOrElse<T, E>(result: Result<T, E>, fn: (e: E) => T): T {
  return result.ok ? result.value : fn(result.error)
}

export function match<T, E, U>(
  result: Result<T, E>,
  handlers: { ok: (t: T) => U; err: (e: E) => U }
): U {
  return result.ok ? handlers.ok(result.value) : handlers.err(result.error)
}

export async function tryAsync<T>(fn: () => Promise<T>): Promise<Result<T, Error>> {
  try {
    return ok(await fn())
  } catch (e) {
    return err(e instanceof Error ? e : new Error(String(e)))
  }
}

export async function tryAsyncWith<T, E>(
  fn: () => Promise<T>,
  mapError: (e: unknown) => E
): Promise<Result<T, E>> {
  try {
    return ok(await fn())
  } catch (e) {
    return err(mapError(e))
  }
}

export function fromNullable<T>(value: T | null | undefined): Result<T, null> {
  return value != null ? ok(value) : err(null)
}

export function toNullable<T, E>(result: Result<T, E>): T | null {
  return result.ok ? result.value : null
}

export function collect<T, E>(results: Result<T, E>[]): Result<T[], E> {
  const values: T[] = []
  for (const result of results) {
    if (!result.ok) return result
    values.push(result.value)
  }
  return ok(values)
}

export async function collectAsync<T, E>(
  results: Promise<Result<T, E>>[]
): Promise<Result<T[], E>> {
  const settled = await Promise.all(results)
  return collect(settled)
}
