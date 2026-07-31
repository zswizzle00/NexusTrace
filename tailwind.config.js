/**
 * static/css/tailwind.css is committed and served directly; there is NO build step in
 * normal development. Regenerate only when a template or JS file gains or loses a Tailwind
 * utility class. Only the tools/tailwindcss binary is git-ignored, so this is reproducible:
 *
 *   ./tools/tailwindcss -c tailwind.config.js \
 *       -i static/css/tailwind-input.css -o static/css/tailwind.css --minify
 */
module.exports = {
  darkMode: 'class',
  content: [
    './templates/**/*.html',
    './static/js/**/*.js',
  ],
  theme: {
    extend: {},
  },
  plugins: [],
};
