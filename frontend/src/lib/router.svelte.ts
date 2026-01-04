import {
  routes,
  type Route,
  type RouteParams,
  type RoutesWithParams,
  buildUrl,
  parseRouteParams,
  isValidRoute,
} from "./types/routes";

const APP_BASE = "/app";

type Brand<T, B extends string> = T & { readonly __brand: B };
type AppPath = Brand<string, "AppPath">;

function asAppPath(path: string): AppPath {
  const normalized = path.startsWith("/") ? path : "/" + path;
  return normalized as AppPath;
}

function getAppPath(): AppPath {
  const pathname = globalThis.location.pathname;
  if (pathname.startsWith(APP_BASE)) {
    const path = pathname.slice(APP_BASE.length) || "/";
    return asAppPath(path);
  }
  return asAppPath("/");
}

function getSearchParams(): URLSearchParams {
  return new URLSearchParams(globalThis.location.search);
}

interface RouterState {
  readonly path: AppPath;
  readonly searchParams: URLSearchParams;
}

const state = $state<{ current: RouterState }>({
  current: {
    path: getAppPath(),
    searchParams: getSearchParams(),
  },
});

function updateState(): void {
  state.current = {
    path: getAppPath(),
    searchParams: getSearchParams(),
  };
}

globalThis.addEventListener("popstate", updateState);

export function navigate<R extends Route>(
  route: R,
  options?: {
    params?: R extends RoutesWithParams ? RouteParams[R] : never;
    replace?: boolean;
  },
): void {
  const url = options?.params ? buildUrl(route, options.params) : route;
  const fullPath = APP_BASE + (url.startsWith("/") ? url : "/" + url);

  if (options?.replace) {
    globalThis.history.replaceState(null, "", fullPath);
  } else {
    globalThis.history.pushState(null, "", fullPath);
  }

  updateState();
}

export function navigateTo(path: string, replace = false): void {
  const normalizedPath = path.startsWith("/") ? path : "/" + path;
  const fullPath = APP_BASE + normalizedPath;

  if (replace) {
    globalThis.history.replaceState(null, "", fullPath);
  } else {
    globalThis.history.pushState(null, "", fullPath);
  }

  updateState();
}

export function getCurrentPath(): AppPath {
  return state.current.path;
}

export function getCurrentSearchParams(): URLSearchParams {
  return state.current.searchParams;
}

export function getSearchParam(key: string): string | null {
  return state.current.searchParams.get(key);
}

export function getFullUrl(path: string): string {
  return APP_BASE + (path.startsWith("/") ? path : "/" + path);
}

export function matchRoute(path: AppPath): Route | null {
  const pathWithoutQuery = path.split("?")[0];
  if (isValidRoute(pathWithoutQuery)) {
    return pathWithoutQuery;
  }
  return null;
}

export function isCurrentRoute(route: Route): boolean {
  const pathWithoutQuery = state.current.path.split("?")[0];
  return pathWithoutQuery === route;
}

export function getRouteParams<R extends RoutesWithParams>(
  _route: R,
): RouteParams[R] {
  return parseRouteParams(_route);
}

export type RouteMatch =
  | { readonly matched: true; readonly route: Route; readonly params: URLSearchParams }
  | { readonly matched: false };

export function match(): RouteMatch {
  const route = matchRoute(state.current.path);
  if (route) {
    return {
      matched: true,
      route,
      params: state.current.searchParams,
    };
  }
  return { matched: false };
}

export { routes, type Route, type RouteParams, type RoutesWithParams };
