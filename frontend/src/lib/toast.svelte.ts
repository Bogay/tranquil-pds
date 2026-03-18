export type ToastType = "success" | "error" | "warning" | "info";

export interface Toast {
  id: number;
  type: ToastType;
  message: string;
  duration: number;
}

let nextId = 0;
let toasts = $state<Toast[]>([]);

export function getToasts(): readonly Toast[] {
  return toasts;
}

export function showToast(
  type: ToastType,
  message: string,
  duration = 5000,
): number {
  const id = nextId++;
  toasts = [...toasts, { id, type, message, duration }];

  if (duration > 0) {
    setTimeout(() => {
      dismissToast(id);
    }, duration);
  }

  return id;
}

export function dismissToast(id: number): void {
  toasts = toasts.filter((t) => t.id !== id);
}

export function clearAllToasts(): void {
  toasts = [];
}

export function success(message: string, duration?: number): number {
  return showToast("success", message, duration);
}

export function error(message: string, duration?: number): number {
  return showToast("error", message, duration);
}

export function warning(message: string, duration?: number): number {
  return showToast("warning", message, duration);
}

export function info(message: string, duration?: number): number {
  return showToast("info", message, duration);
}

export const toast = {
  show: showToast,
  success,
  error,
  warning,
  info,
  dismiss: dismissToast,
  clear: clearAllToasts,
};
