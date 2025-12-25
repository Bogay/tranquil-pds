import { render, type RenderResult } from "@testing-library/svelte";
import { tick } from "svelte";
import type { ComponentType } from "svelte";

export async function renderAndWait<T extends ComponentType>(
  component: T,
  options?: Parameters<typeof render>[1],
): Promise<RenderResult<T>> {
  const result = render(component, options);
  await tick();
  await new Promise((resolve) => setTimeout(resolve, 0));
  return result;
}

export async function waitForElement(
  queryFn: () => HTMLElement | null,
  timeout = 1000,
): Promise<HTMLElement> {
  const start = Date.now();
  while (Date.now() - start < timeout) {
    const element = queryFn();
    if (element) return element;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error("Element not found within timeout");
}

export async function waitForElementToDisappear(
  queryFn: () => HTMLElement | null,
  timeout = 1000,
): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeout) {
    const element = queryFn();
    if (!element) return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error("Element still present after timeout");
}

export async function waitForText(
  container: HTMLElement,
  text: string | RegExp,
  timeout = 1000,
): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeout) {
    const content = container.textContent || "";
    if (
      typeof text === "string" ? content.includes(text) : text.test(content)
    ) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error(`Text "${text}" not found within timeout`);
}

export function mockLocalStorage(
  initialData: Record<string, string> = {},
): void {
  const store: Record<string, string> = { ...initialData };
  Object.defineProperty(window, "localStorage", {
    value: {
      getItem: (key: string) => store[key] || null,
      setItem: (key: string, value: string) => {
        store[key] = value;
      },
      removeItem: (key: string) => {
        delete store[key];
      },
      clear: () => {
        Object.keys(store).forEach((key) => delete store[key]);
      },
      key: (index: number) => Object.keys(store)[index] || null,
      get length() {
        return Object.keys(store).length;
      },
    },
    writable: true,
  });
}

export function setAuthState(session: {
  did: string;
  handle: string;
  email?: string;
  emailConfirmed?: boolean;
  accessJwt: string;
  refreshJwt: string;
}): void {
  localStorage.setItem("session", JSON.stringify(session));
}

export function clearAuthState(): void {
  localStorage.removeItem("session");
}
