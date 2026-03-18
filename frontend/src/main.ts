import "./styles/base.css";
import "./styles/pages.css";
import "./styles/dashboard.css";
import "./styles/migration.css";
import App from "./App.svelte";
import { mount } from "svelte";

const app = mount(App, {
  target: document.getElementById("app")!,
});

export default app;
