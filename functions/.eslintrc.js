module.exports = {
  root: true,
  env: { es6: true, node: true },
  parser: '@typescript-eslint/parser',
  parserOptions: { ecmaVersion: 2020, sourceType: 'module' },
  plugins: ['@typescript-eslint'],
  extends: [
    'eslint:recommended',
    'google',
    'plugin:@typescript-eslint/recommended',
  ],
  rules: {
    // Windows에서 흔히 걸리는 규칙들 완화/해제
    'linebreak-style': 'off',
    'object-curly-spacing': 'off',
    'indent': 'off',
    'max-len': 'off',
    'camelcase': 'off',
    'require-jsdoc': 'off',
    '@typescript-eslint/no-explicit-any': 'off',
  },
};
