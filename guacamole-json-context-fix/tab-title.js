(function () {
    "use strict";
    var storageKey = "guacamole-rdp-tab-title";
    function currentClientId() {
        var match = window.location.hash.match(/^#\/client\/([^?]+)/);
        return match ? match[1] : null;
    }
    var currentUrl = new URL(window.location.href);
    var requestedTitle = currentUrl.searchParams.get("tabTitle");
    var clientId = currentClientId();
    var stored = null;
    if (requestedTitle) {
        currentUrl.searchParams.delete("tabTitle");
        history.replaceState(null, "", currentUrl.pathname
            + (currentUrl.searchParams.toString() ? "?" + currentUrl.searchParams.toString() : "")
            + currentUrl.hash);
    }
    else if (clientId) {
        try { stored = JSON.parse(sessionStorage.getItem(storageKey) || "null"); }
        catch (error) { stored = null; }
        if (stored && stored.clientId === clientId) requestedTitle = stored.title;
    }
    if (!clientId || !requestedTitle || !/^[A-Z0-9]{1,64}$/.test(requestedTitle)) {
        sessionStorage.removeItem(storageKey);
        return;
    }
    stored = { clientId: clientId, title: requestedTitle };
    sessionStorage.setItem(storageKey, JSON.stringify(stored));
    var observer = null;
    function clientChanged() {
        if (currentClientId() === stored.clientId) return false;
        sessionStorage.removeItem(storageKey);
        if (observer) observer.disconnect();
        window.removeEventListener("hashchange", applyTabTitle);
        return true;
    }
    function applyTabTitle() {
        if (clientChanged()) return;
        if (document.title !== stored.title) document.title = stored.title;
    }
    applyTabTitle();
    var titleElement = document.querySelector("title");
    if (titleElement) {
        observer = new MutationObserver(applyTabTitle);
        observer.observe(titleElement, { childList: true, characterData: true, subtree: true });
    }
    window.addEventListener("hashchange", applyTabTitle);
})();
