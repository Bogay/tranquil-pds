export function assertNever(x: never, message?: string): never {
  throw new Error(message ?? `Unexpected value: ${JSON.stringify(x)}`);
}

export function exhaustive<T extends string | number | symbol>(
  value: T,
  handlers: Record<T, () => void>,
): void {
  const handler = handlers[value];
  if (handler) {
    handler();
  } else {
    assertNever(value as never, `Unhandled case: ${String(value)}`);
  }
}

export function exhaustiveMap<T extends string | number | symbol, R>(
  value: T,
  handlers: Record<T, () => R>,
): R {
  const handler = handlers[value];
  if (handler) {
    return handler();
  }
  return assertNever(value as never, `Unhandled case: ${String(value)}`);
}

export async function exhaustiveAsync<T extends string | number | symbol>(
  value: T,
  handlers: Record<T, () => Promise<void>>,
): Promise<void> {
  const handler = handlers[value];
  if (handler) {
    await handler();
  } else {
    assertNever(value as never, `Unhandled case: ${String(value)}`);
  }
}

export async function exhaustiveMapAsync<T extends string | number | symbol, R>(
  value: T,
  handlers: Record<T, () => Promise<R>>,
): Promise<R> {
  const handler = handlers[value];
  if (handler) {
    return handler();
  }
  return assertNever(value as never, `Unhandled case: ${String(value)}`);
}
