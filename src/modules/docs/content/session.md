# Session

The Session Manager handles authentication state — the cookies, login flows, and rules that keep your testing tools talking to the target as a logged-in user.

## Cookie Jar

The shared cookie store used across WonderSuite's tools. The table shows every cookie — name, value, domain, path, and the `Secure` / `HttpOnly` / `SameSite` flags.

- **Add** — create a cookie by hand (name, value, domain, path, Secure, HttpOnly).
- **Export / Import** — save the jar to a JSON file or load one back — handy for moving an authenticated session between machines or restoring one later.
- **Clear All** — empties the jar.
- **Filter** — narrow by domain or name.

Missing `Secure` / `HttpOnly` flags on a session cookie are themselves worth noting as a finding.

## Macros

A macro is a recorded sequence of HTTP requests — typically a login flow. Each macro has a name, description, and an ordered list of **steps** (method + URL), and a step can **extract** a value from its response (by regex capture group) for later steps to use.

- **New Macro** opens the editor; add steps and save.
- Select a macro and **Run** it — WonderSuite executes the steps in order and shows the **extracted values** (CSRF tokens, session IDs, bearer tokens) it pulled out.

Macros are how you automate "log in, grab the token" so the rest of your testing stays authenticated.

## Session Rules

Rules control how sessions are maintained automatically across tools — for example: always use the Cookie Jar, inject a header, or run a macro to refresh auth when a session expires. Each rule has a name, a scope, and an enabled toggle. Toggle a rule on/off or delete it from the list.
