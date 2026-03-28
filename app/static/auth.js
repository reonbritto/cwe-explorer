/**
 * Microsoft Entra ID authentication via MSAL.js 2.x
 * Handles login, token acquisition, and logout.
 */

/* global msal */

var msalInstance = null;

var loginRequest = {
    scopes: ["openid", "profile", "User.Read"]
};

/**
 * Initialise MSAL with config fetched from /api/config.
 * Must be called before any other auth function.
 * Idempotent — safe to call multiple times.
 */
async function initAuth() {
    if (msalInstance) return true;

    try {
        var resp = await fetch("/api/config");
        var cfg = await resp.json();

        if (!cfg.client_id || !cfg.tenant_id) {
            console.warn("Entra ID not configured — auth disabled.");
            return false;
        }

        var msalConfig = {
            auth: {
                clientId: cfg.client_id,
                authority: "https://login.microsoftonline.com/common",
                redirectUri: window.location.origin,
            },
            cache: {
                cacheLocation: "localStorage",
                storeAuthStateInCookie: true,
            }
        };

        msalInstance = new msal.PublicClientApplication(msalConfig);

        // Handle redirect promise (runs after Azure redirects back)
        var response = await msalInstance.handleRedirectPromise();
        if (response) {
            msalInstance.setActiveAccount(response.account);
        } else {
            // Fallback: pick up cached account from localStorage
            var accounts = msalInstance.getAllAccounts();
            if (accounts.length > 0) {
                msalInstance.setActiveAccount(accounts[0]);
            }
        }

        return true;
    } catch (err) {
        console.error("Auth init error:", err);
        return false;
    }
}

/**
 * Get an access token silently, or redirect to login if needed.
 * Returns the token string, or null if a redirect was triggered.
 */
async function getToken() {
    if (!msalInstance) return null;

    var accounts = msalInstance.getAllAccounts();
    if (accounts.length === 0) {
        // No user signed in — redirect to Entra ID login
        msalInstance.loginRedirect(loginRequest);
        return null;
    }

    msalInstance.setActiveAccount(accounts[0]);

    try {
        var result = await msalInstance.acquireTokenSilent({
            scopes: loginRequest.scopes,
            account: accounts[0],
        });
        return result.idToken;
    } catch (err) {
        // Silent renewal failed — force interactive login
        console.warn("Silent token failed, redirecting:", err);
        msalInstance.loginRedirect(loginRequest);
        return null;
    }
}

/**
 * Get the currently signed-in user's display name.
 */
function getCurrentUser() {
    if (!msalInstance) return null;
    var accounts = msalInstance.getAllAccounts();
    if (accounts.length === 0) return null;
    return {
        name: accounts[0].name || accounts[0].username,
        email: accounts[0].username,
    };
}

/**
 * Sign the user out and redirect to the login page.
 */
function logout() {
    if (!msalInstance) return;
    msalInstance.logoutRedirect({
        postLogoutRedirectUri: window.location.origin + "/login.html",
    });
}
