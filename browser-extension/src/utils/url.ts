export function extractDomainFromUrl(url: string): string {
  try {
    const parsed = new URL(url.startsWith("http") ? url : "http://" + url);
    return parsed.hostname.toLowerCase();
  } catch {
    return url.toLowerCase();
  }
}

export function isInternalOrBrowserPage(url: string): boolean {
  if (!url) return true;
  return (
    url.startsWith("chrome://") ||
    url.startsWith("chrome-extension://") ||
    url.startsWith("edge://") ||
    url.startsWith("about:") ||
    url.startsWith("view-source:")
  );
}

