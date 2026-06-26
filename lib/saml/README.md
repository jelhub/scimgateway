# Local `saml` Package

This folder contains a local copy of the [node-saml](https://github.com/auth0/node-saml) package (v4.0.0), originally authored by Auth0.  
Licensed under the MIT License — see [LICENSE](./LICENSE).

## Why This Exists

When compiling scimgateway plugins to standalone binaries using `bun build --compile`, the original `saml` npm package fails at runtime on any machine other than the build machine.

**Root cause:** The original `saml` package uses `fs.readFileSync` with `__dirname`-resolved paths to load XML template files (`saml11.template` and `saml20.template`) at module initialization:

```js
// Original saml/lib/saml11.js
var newSaml11Document = utils.factoryForNode(path.join(__dirname, 'saml11.template'));
```

```js
// Original saml/lib/utils.js
exports.factoryForNode = function factoryForNode(pathToTemplate) {
  const template = fs.readFileSync(pathToTemplate);  // fails in compiled binary
  ...
};
```

When Bun compiles the binary, `__dirname` gets baked in as the **absolute path from the build machine** (e.g. `/Users/xxx/.../node_modules/saml/lib/`). The `.template` files are not embedded in the binary, so the `readFileSync` call fails with `ENOENT` when the binary runs elsewhere.

## What Was Changed

Only one functional change was made — **templates are inlined as string constants** instead of being read from disk at runtime.

### `utils.js`
- Removed `const fs = require('fs')` — no longer needed
- Changed `factoryForNode(pathToTemplate)` to `factoryForNode(templateString)` — accepts an XML string directly instead of a file path

### `saml11.js` and `saml20.js`
- Removed `path.join(__dirname, '*.template')` file references
- Template XML is inlined as a string constant passed to `factoryForNode()`
- Removed `var path = require('path')` (no longer needed)

### `xml/encrypt.js` and `xml/sign.js`
- Copied unchanged from the original package

### `index.js`
- Copied unchanged from the original package

## Import Change

In `lib/samlAssertion.ts`:
```diff
-import { Saml20 as saml } from 'saml'
+import { Saml20 as saml } from './saml/index.js'
```

## Dependencies

The sub-dependencies used by this code remain as npm packages (not copied):
- `@xmldom/xmldom`
- `moment`
- `xml-crypto`
- `xml-encryption`
- `valid-url`
- `xml-name-validator`
- `async`
- `xpath`

The `saml` entry in `package.json` must be kept — it provides the sub-dependencies (@xmldom/xmldom, moment, xml-crypto, etc.) that this local copy requires.
