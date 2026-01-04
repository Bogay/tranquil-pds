import { ok, err, type Result } from '../types/result'

export function debounce<T extends (...args: Parameters<T>) => void>(
  fn: T,
  ms: number
): T & { cancel: () => void } {
  let timeoutId: ReturnType<typeof setTimeout> | null = null

  const debounced = ((...args: Parameters<T>) => {
    if (timeoutId) clearTimeout(timeoutId)
    timeoutId = setTimeout(() => {
      fn(...args)
      timeoutId = null
    }, ms)
  }) as T & { cancel: () => void }

  debounced.cancel = () => {
    if (timeoutId) {
      clearTimeout(timeoutId)
      timeoutId = null
    }
  }

  return debounced
}

export function throttle<T extends (...args: Parameters<T>) => void>(
  fn: T,
  ms: number
): T {
  let lastCall = 0
  let timeoutId: ReturnType<typeof setTimeout> | null = null

  return ((...args: Parameters<T>) => {
    const now = Date.now()
    const remaining = ms - (now - lastCall)

    if (remaining <= 0) {
      if (timeoutId) {
        clearTimeout(timeoutId)
        timeoutId = null
      }
      lastCall = now
      fn(...args)
    } else if (!timeoutId) {
      timeoutId = setTimeout(() => {
        lastCall = Date.now()
        timeoutId = null
        fn(...args)
      }, remaining)
    }
  }) as T
}

export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

export async function retry<T>(
  fn: () => Promise<T>,
  options: {
    attempts?: number
    delay?: number
    backoff?: number
    shouldRetry?: (error: unknown, attempt: number) => boolean
  } = {}
): Promise<T> {
  const {
    attempts = 3,
    delay = 1000,
    backoff = 2,
    shouldRetry = () => true,
  } = options

  let lastError: unknown
  let currentDelay = delay

  for (let attempt = 1; attempt <= attempts; attempt++) {
    try {
      return await fn()
    } catch (error) {
      lastError = error
      if (attempt === attempts || !shouldRetry(error, attempt)) {
        throw error
      }
      await sleep(currentDelay)
      currentDelay *= backoff
    }
  }

  throw lastError
}

export async function retryResult<T, E>(
  fn: () => Promise<Result<T, E>>,
  options: {
    attempts?: number
    delay?: number
    backoff?: number
    shouldRetry?: (error: E, attempt: number) => boolean
  } = {}
): Promise<Result<T, E>> {
  const {
    attempts = 3,
    delay = 1000,
    backoff = 2,
    shouldRetry = () => true,
  } = options

  let lastResult: Result<T, E> | null = null
  let currentDelay = delay

  for (let attempt = 1; attempt <= attempts; attempt++) {
    const result = await fn()
    lastResult = result

    if (result.ok) {
      return result
    }

    if (attempt === attempts || !shouldRetry(result.error, attempt)) {
      return result
    }

    await sleep(currentDelay)
    currentDelay *= backoff
  }

  return lastResult!
}

export function timeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return new Promise((resolve, reject) => {
    const timeoutId = setTimeout(() => {
      reject(new Error(`Timeout after ${ms}ms`))
    }, ms)

    promise
      .then((value) => {
        clearTimeout(timeoutId)
        resolve(value)
      })
      .catch((error) => {
        clearTimeout(timeoutId)
        reject(error)
      })
  })
}

export async function timeoutResult<T>(
  promise: Promise<Result<T, Error>>,
  ms: number
): Promise<Result<T, Error>> {
  try {
    return await timeout(promise, ms)
  } catch (e) {
    return err(e instanceof Error ? e : new Error(String(e)))
  }
}

export async function parallel<T>(
  tasks: (() => Promise<T>)[],
  concurrency: number
): Promise<T[]> {
  const results: T[] = []
  const executing: Promise<void>[] = []

  for (const task of tasks) {
    const p = task().then((result) => {
      results.push(result)
    })

    executing.push(p)

    if (executing.length >= concurrency) {
      await Promise.race(executing)
      executing.splice(
        executing.findIndex((e) => e === p),
        1
      )
    }
  }

  await Promise.all(executing)
  return results
}

export async function mapParallel<T, U>(
  items: T[],
  fn: (item: T, index: number) => Promise<U>,
  concurrency: number
): Promise<U[]> {
  const results: U[] = new Array(items.length)
  const executing: Promise<void>[] = []

  for (let i = 0; i < items.length; i++) {
    const index = i
    const p = fn(items[index], index).then((result) => {
      results[index] = result
    })

    executing.push(p)

    if (executing.length >= concurrency) {
      await Promise.race(executing)
      const doneIndex = executing.findIndex(
        (e) =>
          (e as Promise<void> & { _done?: boolean })._done !== false
      )
      if (doneIndex >= 0) {
        executing.splice(doneIndex, 1)
      }
    }
  }

  await Promise.all(executing)
  return results
}

export function createAbortable<T>(
  fn: (signal: AbortSignal) => Promise<T>
): { promise: Promise<T>; abort: () => void } {
  const controller = new AbortController()
  return {
    promise: fn(controller.signal),
    abort: () => controller.abort(),
  }
}

export interface Deferred<T> {
  promise: Promise<T>
  resolve: (value: T) => void
  reject: (error: unknown) => void
}

export function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void
  let reject!: (error: unknown) => void

  const promise = new Promise<T>((res, rej) => {
    resolve = res
    reject = rej
  })

  return { promise, resolve, reject }
}
