# JavaScript / TypeScript Secure Coding Guide

## Overview

This guide covers critical JavaScript and TypeScript security patterns in
browser and Node.js environments that Raven's rule engine detects.

## 1. eval() and Dynamic Code Execution

```javascript
// VULNERABLE
const expr = req.query.formula;
const result = eval(expr);   // RCE in Node.js, XSS in browser

// ALSO VULNERABLE — same risk as eval()
const fn = new Function("return " + expr);

// SAFE — use explicit parsing
const num = parseFloat(req.query.value);  // for numbers
const data = JSON.parse(req.body);         // for data structures
```

## 2. XSS via innerHTML

```javascript
// VULNERABLE — browser XSS
const name = new URLSearchParams(location.search).get("name");
document.getElementById("greeting").innerHTML = "Hello, " + name;

// SAFE — use textContent (no HTML rendering)
document.getElementById("greeting").textContent = "Hello, " + name;

// SAFE — sanitize if HTML is needed
import DOMPurify from "dompurify";
element.innerHTML = DOMPurify.sanitize(userHtml);
```

## 3. React dangerouslySetInnerHTML

```jsx
// VULNERABLE
<div dangerouslySetInnerHTML={{ __html: userInput }} />

// SAFE — use JSX rendering (React escapes by default)
<div>{userInput}</div>

// SAFE — sanitize if raw HTML is required
import DOMPurify from "dompurify";
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userInput) }} />
```

## 4. SQL Injection in Node.js

```javascript
// VULNERABLE — string concatenation
const query = "SELECT * FROM users WHERE id = " + req.params.id;
db.query(query, callback);

// SAFE — parameterized query
db.query("SELECT * FROM users WHERE id = ?", [req.params.id], callback);

// SAFE — using an ORM (Sequelize, Prisma)
const user = await User.findByPk(req.params.id);
```

## 5. Prototype Pollution

```javascript
// VULNERABLE
function merge(target, source) {
  for (let key in source) {
    target[key] = source[key];  // attacker can set __proto__
  }
}
merge({}, JSON.parse('{"__proto__": {"admin": true}}'));

// SAFE — use Object.create(null) or validate keys
function safeMerge(target, source) {
  for (let key of Object.keys(source)) {
    if (key !== "__proto__" && key !== "constructor") {
      target[key] = source[key];
    }
  }
}
```

## 6. npm Dependency Vulnerabilities

```bash
# Check for vulnerabilities
npm audit

# Auto-fix non-breaking updates
npm audit fix

# Check specific package
npm audit --package lodash
```

## Security Checklist

- [ ] Never use `eval()` or `new Function()` with user data
- [ ] Use `textContent` instead of `innerHTML` for plain text
- [ ] Sanitize HTML with DOMPurify before `innerHTML` assignment
- [ ] Use parameterized queries for all database access
- [ ] Run `npm audit` regularly and in CI/CD
- [ ] Set Content Security Policy (CSP) headers
- [ ] Validate and sanitize all user inputs server-side
