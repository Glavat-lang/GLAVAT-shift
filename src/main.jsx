import React from "react";
import { createRoot } from "react-dom/client";
import App from "./App.jsx";
import "./styles.css";

createRoot(document.getElementById("root")).render(<React.StrictMode><App /></React.StrictMode>);

// Remove the old service worker and its cached application files.
// This prevents visitors from opening an outdated schedule interface.
if ("serviceWorker" in navigator) {
  window.addEventListener("load", async () => {
    try {
      const registrations = await navigator.serviceWorker.getRegistrations();
      await Promise.all(registrations.map(registration => registration.unregister()));
      if ("caches" in window) {
        const keys = await caches.keys();
        await Promise.all(keys.filter(key => key.startsWith("glavat-raspisanie")).map(key => caches.delete(key)));
      }
    } catch (error) {
      console.warn("Не удалось очистить старый кэш приложения:", error);
    }
  });
}
