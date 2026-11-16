"""Plain-language learning notes for every check.

The UI shows these next to a finding so students can connect the observed
evidence to the underlying control, without inventing anything the scan did
not verify.
"""

from __future__ import annotations

_LEARNING: dict[str, dict[str, str]] = {
    "venom.headers.csp": {
        "what": "Content Security Policy is a response header that tells the browser which "
        "sources of script, style, image and network traffic a page may use.",
        "why": "If an attacker injects a script tag, a strict CSP blocks it. Without a CSP the "
        "browser executes whatever it can parse.",
        "verify": "Look for Content-Security-Policy in the response and confirm it starts from "
        "default-src 'self' with no unsafe-inline or wildcard script sources.",
    },
    "venom.headers.hsts": {
        "what": "Strict-Transport-Security tells browsers to use HTTPS only for this host for a "
        "given period.",
        "why": "Without HSTS the first request can still go over plaintext HTTP, where a network "
        "attacker can intercept or modify it.",
        "verify": "Inspect the HTTPS response for Strict-Transport-Security with max-age of at "
        "least one year.",
    },
    "venom.headers.missing": {
        "what": "Security headers are response directives that tell the browser how to treat the "
        "page: what it may load, how it may be framed and whether it may be cached.",
        "why": "Missing headers do not create a vulnerability on their own, but they remove the "
        "browser-side controls that limit the damage of an injection or a hostile embed.",
        "verify": "Read the response headers and compare them with the OWASP Secure Headers "
        "baseline; this module reports CSP, HSTS and the common hardening headers it observes.",
    },
    "venom.tls.weak": {
        "what": "TLS configuration covers the negotiated protocol version, the cipher suite and "
        "the validity and trust of the presented certificate.",
        "why": "A deprecated protocol, a weak cipher or an untrusted certificate undermines the "
        "confidentiality and authenticity of every request to the site.",
        "verify": "Inspect the TLS evidence attached to the finding: protocol, cipher, certificate "
        "issuer, expiry and chain validation result.",
    },
    "venom.headers.hardening": {
        "what": "Small defensive headers such as X-Content-Type-Options, Referrer-Policy and "
        "Permissions-Policy restrict browser behaviour.",
        "why": "They close gaps like MIME sniffing, referrer leakage and access to sensitive "
        "browser features.",
        "verify": "Check each listed header in the response and add the missing ones.",
    },
    "venom.cookies.flags": {
        "what": "Cookie attributes decide where and how a cookie is sent: Secure restricts it to "
        "HTTPS, HttpOnly hides it from JavaScript, SameSite limits cross-site sends.",
        "why": "A session cookie without HttpOnly can be stolen by XSS; without Secure it can leak "
        "over HTTP; without SameSite it can ride along on cross-site requests.",
        "verify": "Open developer tools, read the Set-Cookie header and confirm all three "
        "attributes on every session cookie.",
    },
    "venom.info.server": {
        "what": "Plaintext HTTP responses travel without encryption; version headers advertise "
        "exact software versions.",
        "why": "Banner information shortlists known CVEs, and plaintext exposes credentials and "
        "session tokens on the wire.",
        "verify": "Fetch the site over HTTP and over HTTPS, compare the Server and X-Powered-By "
        "values and check the TLS certificate.",
    },
    "venom.info.version": {
        "what": "Server and framework version tokens leak in headers such as Server and "
        "X-Powered-By.",
        "why": "An attacker can map the disclosed version to public vulnerabilities instead of "
        "guessing.",
        "verify": "Read the response headers and compare against the vendor's current release.",
    },
    "venom.transport.plaintext": {
        "what": "The site accepted an HTTP request without redirecting to HTTPS.",
        "why": "Everything on that connection, including cookies and passwords, is readable on the "
        "path.",
        "verify": "Request the http:// URL and confirm it redirects to https:// before any "
        "application content is served.",
    },
    "venom.tls.expired": {
        "what": "The certificate is outside its validity window, so browsers cannot trust it.",
        "why": "Users are trained to click through certificate warnings, which makes "
        "impersonation easier.",
        "verify": "Open the certificate details in a browser and compare notAfter with today.",
    },
    "venom.tls.expiring": {
        "what": "The certificate expires soon.",
        "why": "Without automated renewal this becomes an outage or a browser warning.",
        "verify": "Check the renewal automation and monitoring for the certificate.",
    },
    "venom.tls.protocol": {
        "what": "The server negotiated a deprecated TLS version, such as TLS 1.0 or 1.1.",
        "why": "Legacy protocol versions have known weaknesses and are no longer acceptable for "
        "public traffic.",
        "verify": "Confirm the negotiated protocol with a TLS scanner or openssl s_client.",
    },
    "venom.tls.cipher": {
        "what": "The negotiated cipher suite is weak, for example RC4, 3DES or export-grade.",
        "why": "Weak ciphers reduce the confidentiality of in-transit data.",
        "verify": "List the server cipher order and require modern AEAD suites only.",
    },
    "venom.tls.untrusted": {
        "what": "Certificate validation failed for a reason other than expiry.",
        "why": "Without a trusted chain users cannot distinguish the real site from an impostor.",
        "verify": "Check the chain, hostname match and whether the issuing CA is publicly trusted.",
    },
    "venom.clickjacking": {
        "what": "Frame protections stop other sites from embedding this page in an iframe.",
        "why": "Without them an attacker can overlay invisible buttons and trick a logged-in user "
        "into clicking them (clickjacking).",
        "verify": "Confirm X-Frame-Options or a CSP frame-ancestors directive in the response.",
    },
    "venom.cors.misconfig": {
        "what": "CORS decides which origins may read this site's responses from JavaScript.",
        "why": "Reflecting an arbitrary Origin, especially with credentials, lets any website read "
        "authenticated data.",
        "verify": "Send a request with a canary Origin header and read Access-Control-Allow-Origin "
        "and Access-Control-Allow-Credentials.",
    },
    "venom.csrf.token": {
        "what": "Anti-CSRF tokens prove that a state-changing request came from the site's own "
        "form, not from another origin.",
        "why": "Without a token a malicious page can submit forms with the victim's cookies.",
        "verify": "Submit the form twice with different token values and confirm the second is "
        "rejected; check SameSite as a secondary control.",
    },
    "venom.methods": {
        "what": "HTTP method advertisement shows which verbs a URL accepts.",
        "why": "TRACE reflects request contents and is rarely needed; writable methods on public "
        "paths widen the attack surface.",
        "verify": "Send an OPTIONS request and inspect the Allow header.",
    },
    "venom.files.exposed": {
        "what": "Configuration, version control and backup files must never be served by the web "
        "server.",
        "why": "A reachable .git directory can leak full source history, and a .env file leaks "
        "credentials.",
        "verify": "Request the listed path and confirm the signature match; never download or "
        "redistribute secrets.",
    },
    "venom.secrets.js": {
        "what": "JavaScript bundles can embed API keys, tokens and private keys.",
        "why": "Anything shipped to the browser is public; a leaked credential can grant access to "
        "third-party services.",
        "verify": "Confirm the masked value is a live credential, rotate it, then remove it from "
        "the build.",
    },
    "venom.redirect.open": {
        "what": "An open redirect lets an attacker choose where the site sends a visitor next.",
        "why": "It powers convincing phishing links that start on the trusted domain.",
        "verify": "Request the parameter with an external canary host and inspect the Location "
        "header without following it.",
    },
    "venom.auth.pages": {
        "what": "Authentication pages must not transport credentials in URLs or encourage unsafe "
        "browser storage.",
        "why": "Credentials in a URL end up in logs, history and Referer headers.",
        "verify": "Inspect the form method, the field types and the autocomplete attributes.",
    },
    "venom.session": {
        "what": "Cookie Domain and SameSite scope decide which hosts and requests receive the "
        "session cookie.",
        "why": "A session cookie shared with a parent domain is also sent to every sibling "
        "subdomain, so one compromised subdomain can steal the session.",
        "verify": "Read the Domain attribute of the session cookie and compare it with the exact "
        "host.",
    },
    "venom.cache": {
        "what": "Cache-Control decides whether browsers and proxies may store a response.",
        "why": "A cached authenticated page can be replayed from a shared machine or proxy.",
        "verify": "Load a sensitive page while authenticated and confirm Cache-Control contains "
        "no-store or private.",
    },
    "venom.info.errors": {
        "what": "Verbose error pages reveal stack traces, database errors or framework internals.",
        "why": "They hand an attacker file paths, library versions and sometimes query fragments.",
        "verify": "Trigger a handled error and confirm the response is a generic message without "
        "internals.",
    },
    "venom.info.dirlist": {
        "what": "Directory listing turns a web server into a file browser.",
        "why": "It exposes backups, uploads and source files that were never meant to be linked.",
        "verify": "Request the directory path and confirm the server rejects it or returns an "
        "application page.",
    },
    "venom.xss.reflected": {
        "what": "Reflected XSS happens when input from the request is written into the HTML "
        "response without contextual escaping.",
        "why": "An attacker can send a crafted link that runs script in a victim's session on the "
        "trusted origin.",
        "verify": "Resend the canary value and confirm the raw angle brackets appear in the HTML; "
        "then confirm the fix encodes them as entities.",
    },
    "venom.sqli.error": {
        "what": "SQL injection is when request values are concatenated into a database query "
        "instead of being bound as parameters.",
        "why": "The database may execute attacker-controlled syntax, exposing or changing data.",
        "verify": "Send a single quote and look for a driver-specific syntax error; confirm the fix "
        "returns a generic page and logs the error server-side.",
    },
    "venom.sqli.time": {
        "what": "Blind SQL injection confirmed by timing: a payload that asks the database to "
        "sleep is evaluated by the query engine.",
        "why": "Even when no error or data is returned, the timing channel lets an attacker "
        "extract data one bit at a time.",
        "verify": "Compare the baseline response time with repeated sleep payloads; at least two "
        "runs must show the configured delay, and the fix should make timing uniform.",
    },
    "venom.ssti": {
        "what": "Server-side template injection occurs when user input is compiled as part of a "
        "template instead of being passed as a value.",
        "why": "Template expressions can escalate to arbitrary code execution on the server.",
        "verify": "Send a simple arithmetic expression inside the template syntax and check whether "
        "the response contains the computed result instead of the literal text.",
    },
    "venom.lfi.path": {
        "what": "Path traversal lets a request parameter escape the intended directory and read "
        "other files on the host.",
        "why": "Configuration files, private keys and credentials are often readable outside the "
        "web root.",
        "verify": "Send a traversal sequence for a known harmless system file and confirm the "
        "response contains that file's signature; file contents are not stored by VENOMSCAN.",
    },
    "venom.api.docs": {
        "what": "An API specification document (OpenAPI or Swagger) is publicly reachable and "
        "lists the route table, parameters and authentication schemes.",
        "why": "It removes the guesswork from API enumeration and often reveals routes that are "
        "not linked from the UI, including internal or deprecated versions.",
        "verify": "Request the spec path without credentials; if it is public by design, confirm "
        "it contains no internal servers or non-public routes.",
    },
    "venom.api.auth": {
        "what": "The API contract either declares no authentication scheme or advertises a "
        "plaintext server URL.",
        "why": "Clients cannot tell which routes need credentials, and plaintext base URLs put "
        "tokens and request bodies on the wire without encryption.",
        "verify": "Read the spec's security schemes and server list; then confirm each route "
        "rejects unauthenticated requests and only https:// servers are published.",
    },
    "venom.api.sensitive": {
        "what": "A JSON API response contains a credential-shaped value such as a JWT, cloud "
        "access key or private key.",
        "why": "Any client that can read the response may reuse the credential to reach data or "
        "services beyond its intended scope.",
        "verify": "Inspect the masked evidence path in the response; confirm the value is a live "
        "credential and rotate it before removing it from the response body.",
    },
    "venom.api.ratelimit": {
        "what": "A short sequential burst of requests to one API route returned no 429 and no "
        "Retry-After header.",
        "why": "Without throttling, automated enumeration, credential stuffing and scraping are "
        "cheap; a small burst is a signal, not proof, so the finding stays suspected.",
        "verify": "Ask the API owner for the configured threshold, or repeat a bounded burst from "
        "a permitted source and confirm throttling kicks in.",
    },
    "venom.api.spec": {
        "what": "The published API contract describes how authentication is enforced: a global "
        "security requirement, per-operation overrides, the schemes clients must use and the "
        "servers those clients are told to call.",
        "why": "Operations that opt out of authentication, keys transported in query strings and "
        "implicit OAuth grants all leak or weaken credentials before any request is crafted.",
        "verify": "Read the spec's security schemes and each operation's security block; confirm "
        "write operations reject unauthenticated calls and keys travel in headers, not URLs.",
    },
    "venom.api.unauth": {
        "what": "The specification marks a GET operation as requiring authentication, but the "
        "route returned a successful JSON response to a request sent without credentials.",
        "why": "A route that skips its declared auth boundary exposes data to anyone who can "
        "reach the API and enables object enumeration from a public starting point.",
        "verify": "Repeat the same unauthenticated request while logged out; if the data is real, "
        "the server is missing the check. Confirm whether the data is intentionally public "
        "before raising severity.",
    },
    "venom.api.jwt": {
        "what": "JSON Web Tokens carry a header, a readable claim set and a signature. Their "
        "hygiene decides what happens when one leaks: unsigned tokens, missing expiry, external "
        "key URLs and credentials embedded in claims all widen the blast radius.",
        "why": "Stolen tokens are bearer credentials; an attacker who reads one can replay it "
        "until it expires, and an alg=none or attacker-keyed token can be forged outright.",
        "verify": "Decode the masked token evidence: confirm the algorithm is pinned, exp is "
        "short, no jku/x5u points at another host and claims hold identifiers rather than "
        "secrets.",
    },
    "venom.api.graphql": {
        "what": "GraphQL exposes a typed schema through introspection and often ships an "
        "in-browser IDE. Both are development conveniences that reveal queries and mutations.",
        "why": "A public schema shortlists sensitive mutations and inputs, and an exposed IDE "
        "lets anyone run those queries against production data.",
        "verify": "Re-send the introspection query and confirm it is rejected in production; "
        "check that the IDE is disabled or behind authentication.",
    },
    "venom.ssrf": {
        "what": "Server-side request forgery happens when the application fetches a URL taken "
        "from request input instead of a fixed destination.",
        "why": "The server sits inside a trusted network, so a fetch from it can reach internal "
        "admin panels, databases and cloud metadata endpoints that the attacker cannot reach "
        "directly.",
        "verify": "Replace the URL parameter with a listener you control and watch for the "
        "callback; then confirm the fix allowlists destinations and blocks private IP ranges.",
    },
    "venom.xss.dom": {
        "what": "DOM XSS happens when client-side JavaScript reads request input (query string, "
        "hash, storage) and writes it into an HTML sink such as innerHTML or document.write.",
        "why": "The attack never reaches the server, so server-side escaping and most WAF rules "
        "cannot see it; the payload runs in the victim's browser on the trusted origin.",
        "verify": "Watch a real browser load the URL with a harmless marker element; if the DOM "
        "contains the element, the same position would execute a script. Then fix the sink and "
        "confirm the marker appears as text instead.",
    },
    "venom.xxe": {
        "what": "XML external entity injection happens when a parser resolves DOCTYPE entity "
        "declarations, so a document can make the server fetch URLs or read local files.",
        "why": "The XML parser trusts markup that the attacker controls; entity expansion can "
        "exfiltrate files, pivot to internal services, and in some parsers exhaust memory or CPU.",
        "verify": "POST a document that declares an external entity aimed at a listener you "
        "control and watch for the callback; then confirm DTDs and external entities are "
        "disabled in the parser.",
    },
    "venom.idor": {
        "what": "Insecure direct object reference means an endpoint trusts the object id in the "
        "request without checking that the object belongs to the authenticated account.",
        "why": "IDs appear in URLs, so changing one number is enough to read another customer's "
        "invoice, order or profile when authorization happens only in the UI.",
        "verify": "Fetch the same object with two test accounts that you control; if the second "
        "account receives the first account's data, the server is missing an ownership check.",
    },
    "venom.authz.function": {
        "what": "Function-level authorization gaps let an ordinary account reach administrative "
        "or internal routes that should require a higher role.",
        "why": "Hiding admin links in the interface is not access control; the route remains "
        "reachable and can expose user management, exports or internal tooling.",
        "verify": "Call the privileged route with a low-privilege test account and confirm the "
        "server returns 403. A 200 page with real content means authorization is missing.",
    },
}


def learning_for(check_id: str) -> dict[str, str]:
    return _LEARNING.get(
        check_id,
        {
            "what": "This check is documented in the engine catalogue.",
            "why": "Findings are generated only from evidence collected during this scan.",
            "verify": "Review the request and response evidence attached to the finding.",
        },
    )
