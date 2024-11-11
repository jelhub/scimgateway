// @typescript-eslint/parser also needs @typescript-eslint/eslint-plugin installed
import stylistic from '@stylistic/eslint-plugin'
import parserTs from '@typescript-eslint/parser'
import tseslint from '@typescript-eslint/eslint-plugin'

export default [
  {
    plugins: {
      '@stylistic': stylistic,
      '@typescript-eslint': tseslint,
    },
    languageOptions: {
      parser: parserTs,
    },
    rules: {
      ...stylistic.configs['recommended-flat'].rules,
      ...tseslint.configs['recommended'].rules,
      '@stylistic/no-trailing-spaces': ['error', { ignoreComments: true }],
      '@stylistic/brace-style': ['error', '1tbs', { allowSingleLine: true }],
      '@stylistic/max-statements-per-line': 'off',
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-unused-vars': ['warn', {
        argsIgnorePattern: '^_',
        varsIgnorePattern: '^_',
        caughtErrors: 'none' }],
    },
  },
  {
    ignores: [
      '**/node_modules/**',
      '**/dist/**',
      '**/build/**',
      '**/config/**',
      '**/lib/scim-stream.js',
    ],
  },
  {
    files: ['**/*.ts', '**/*.js'],
  },
]
