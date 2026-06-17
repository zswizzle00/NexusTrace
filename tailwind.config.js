/**
 * Tailwind CSS configuration for NexusTrace.
 *
 * The compiled stylesheet (static/css/tailwind.css) is committed to the repo and
 * served directly - there is NO build step in normal development. Only regenerate
 * the CSS when you add/remove Tailwind utility classes in a template or JS file:
 *
 *   ./tools/tailwindcss -c tailwind.config.js \
 *       -i static/css/tailwind-input.css -o static/css/tailwind.css --minify
 *
 * (Only the standalone `tools/tailwindcss` binary is git-ignored; this config and
 *  static/css/tailwind-input.css are committed so the build is reproducible.)
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
