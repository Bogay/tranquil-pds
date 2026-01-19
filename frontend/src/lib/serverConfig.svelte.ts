import { api } from "./api.ts";

interface ServerConfigState {
  serverName: string | null;
  primaryColor: string | null;
  primaryColorDark: string | null;
  secondaryColor: string | null;
  secondaryColorDark: string | null;
  hasLogo: boolean;
  loading: boolean;
}

const state = $state<ServerConfigState>({
  serverName: null,
  primaryColor: null,
  primaryColorDark: null,
  secondaryColor: null,
  secondaryColorDark: null,
  hasLogo: false,
  loading: true,
});

let initialized = false;
let darkModeQuery: MediaQueryList | null = null;

function isDarkMode(): boolean {
  return darkModeQuery?.matches ?? false;
}

function applyColors() {
  const root = document.documentElement;
  const dark = isDarkMode();

  if (dark) {
    if (state.primaryColorDark) {
      root.style.setProperty("--accent", state.primaryColorDark);
    } else {
      root.style.removeProperty("--accent");
    }
    if (state.secondaryColorDark) {
      root.style.setProperty("--secondary", state.secondaryColorDark);
    } else {
      root.style.removeProperty("--secondary");
    }
  } else {
    if (state.primaryColor) {
      root.style.setProperty("--accent", state.primaryColor);
    } else {
      root.style.removeProperty("--accent");
    }
    if (state.secondaryColor) {
      root.style.setProperty("--secondary", state.secondaryColor);
    } else {
      root.style.removeProperty("--secondary");
    }
  }
}

function setFavicon(hasLogo: boolean) {
  let link = document.querySelector<HTMLLinkElement>("link[rel~='icon']");
  if (hasLogo) {
    if (!link) {
      link = document.createElement("link");
      link.rel = "icon";
      document.head.appendChild(link);
    }
    link.href = "/logo";
  } else if (link) {
    link.remove();
  }
}

export async function initServerConfig(): Promise<void> {
  if (initialized) return;
  initialized = true;

  darkModeQuery = globalThis.matchMedia("(prefers-color-scheme: dark)");
  darkModeQuery.addEventListener("change", applyColors);

  try {
    const config = await api.getServerConfig();
    state.serverName = config.serverName;
    state.primaryColor = config.primaryColor;
    state.primaryColorDark = config.primaryColorDark;
    state.secondaryColor = config.secondaryColor;
    state.secondaryColorDark = config.secondaryColorDark;
    state.hasLogo = !!config.logoCid;
    document.title = config.serverName;
    applyColors();
    setFavicon(state.hasLogo);
  } catch {
    state.serverName = null;
  } finally {
    state.loading = false;
  }
}

export function getServerConfigState() {
  return state;
}

export function setServerName(name: string) {
  state.serverName = name;
  document.title = name;
}

export function setColors(colors: {
  primaryColor?: string | null;
  primaryColorDark?: string | null;
  secondaryColor?: string | null;
  secondaryColorDark?: string | null;
}) {
  if (colors.primaryColor !== undefined) {
    state.primaryColor = colors.primaryColor;
  }
  if (colors.primaryColorDark !== undefined) {
    state.primaryColorDark = colors.primaryColorDark;
  }
  if (colors.secondaryColor !== undefined) {
    state.secondaryColor = colors.secondaryColor;
  }
  if (colors.secondaryColorDark !== undefined) {
    state.secondaryColorDark = colors.secondaryColorDark;
  }
  applyColors();
}

export function setHasLogo(hasLogo: boolean) {
  state.hasLogo = hasLogo;
  setFavicon(hasLogo);
}
