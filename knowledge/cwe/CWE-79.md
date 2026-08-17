# CWE-79: Cross-Site Scripting (XSS)

## Description

Cross-Site Scripting (CWE-79) occurs when an application includes user-controllable
data in output sent to a web browser without properly encoding or validating it.
An attacker can inject client-side scripts that execute in the victim's browser.

## Risk

- **CVSS Score**: Up to 8.8 (High)
- **Impact**: Session hijacking, credential theft, malware delivery, page defacement
- **OWASP**: A03:2021 — Injection
- **Affected Languages**: JavaScript, TypeScript, JSX, TSX, HTML templates

## Vulnerable Example (React)

```jsx
// VULNERABLE: user content rendered as raw HTML
function UserComment({ comment }) {
  return <div dangerouslySetInnerHTML={{ __html: comment }} />;
}

// Attacker submits: <script>document.cookie='stolen='+document.cookie</script>
```

## Vulnerable Example (Vanilla JS)

```javascript
// VULNERABLE: innerHTML with user input
const name = new URLSearchParams(window.location.search).get("name");
document.getElementById("greeting").innerHTML = "Hello, " + name;
```

## Safe Example (React)

```jsx
// SAFE: render as text, not HTML
function UserComment({ comment }) {
  return <div>{comment}</div>;  // React escapes this automatically
}

// SAFE: sanitize if HTML rendering is required
import DOMPurify from "dompurify";
function UserComment({ comment }) {
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(comment) }} />;
}
```

## Remediation

1. **Use framework-provided escaping** (React JSX, Django templates, Jinja2 auto-escape).
2. Avoid `innerHTML`, `document.write()`, and `dangerouslySetInnerHTML` with unsanitized data.
3. Apply a Content Security Policy (CSP) header to restrict script sources.
4. Sanitize HTML with DOMPurify before inserting into the DOM.
5. Use `textContent` instead of `innerHTML` when displaying plain text.
