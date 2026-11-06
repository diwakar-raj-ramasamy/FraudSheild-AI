/**
 * Generates and persists a privacy-preserving random UUID pseudonym for this extension installation.
 * Never collects hardware IDs, MAC addresses, or personal identity.
 */
export async function getInstallationPseudonym(): Promise<string> {
  return new Promise((resolve) => {
    if (typeof chrome === "undefined" || !chrome.storage || !chrome.storage.local) {
      resolve("dev-local-pseudonym-" + Math.random().toString(36).substring(2, 9));
      return;
    }

    chrome.storage.local.get(["fs_installation_pseudonym"], (result) => {
      if (result.fs_installation_pseudonym) {
        resolve(result.fs_installation_pseudonym);
      } else {
        const newPseudonym = "fs-ep-" + crypto.randomUUID();
        chrome.storage.local.set({ fs_installation_pseudonym: newPseudonym }, () => {
          resolve(newPseudonym);
        });
      }
    });
  });
}

