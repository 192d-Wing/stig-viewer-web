import js from '@eslint/js'
import reactPlugin from 'eslint-plugin-react'
import reactHooks from 'eslint-plugin-react-hooks'
import jsxA11y from 'eslint-plugin-jsx-a11y'
import security from 'eslint-plugin-security'
import noUnsanitized from 'eslint-plugin-no-unsanitized'
import globals from 'globals'

export default [
  js.configs.recommended,
  reactPlugin.configs.flat.recommended,
  reactPlugin.configs.flat['jsx-runtime'],
  jsxA11y.flatConfigs.strict,

  {
    plugins: {
      'react-hooks': reactHooks,
      security,
      'no-unsanitized': noUnsanitized,
    },

    languageOptions: {
      globals: { ...globals.browser },
      parserOptions: {
        ecmaVersion: 'latest',
        sourceType: 'module',
        ecmaFeatures: { jsx: true },
      },
    },

    settings: {
      react: { version: 'detect' },
    },

    rules: {
      // React hooks
      ...reactHooks.configs.recommended.rules,
      'react-hooks/exhaustive-deps': 'error',

      // Forbid dangerous React patterns
      'react/no-danger': 'error',
      'react/no-danger-with-children': 'error',

      // Core JS security
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-new-func': 'error',
      'no-script-url': 'error',

      // security plugin — explicit rule list avoids config-key fragility
      'security/detect-non-literal-regexp': 'error',
      'security/detect-eval-with-expression': 'error',
      'security/detect-pseudoRandomBytes': 'error',
      'security/detect-unsafe-regex': 'error',
      'security/detect-disable-mustache-escape': 'error',
      'security/detect-new-buffer': 'error',
      // warn-only: very noisy in normal React code
      'security/detect-object-injection': 'warn',
      'security/detect-possible-timing-attacks': 'warn',

      // XSS via innerHTML / outerHTML / document.write
      'no-unsanitized/method': 'error',
      'no-unsanitized/property': 'error',
    },
  },
]
