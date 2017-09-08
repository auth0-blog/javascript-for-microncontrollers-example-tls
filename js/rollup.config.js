import resolve from 'rollup-plugin-node-resolve';
import babel from 'rollup-plugin-babel';
import cjs from 'rollup-plugin-commonjs';
import strip from 'rollup-plugin-strip';
import html from 'rollup-plugin-html';
import uglify from 'rollup-plugin-uglify';
import { minify } from 'uglify-es';


export default {
  entry: './main.js',
  format: 'es',
  dest: './dist/main.bundle.js',
  useStrict: false,
  plugins: [
    html({
      include: '**/*.html',
      htmlMinifierOptions: {
        collapseWhitespace: true,
        collapseBooleanAttributes: true,
        conservativeCollapse: true,
        minifyJS: true
      }
    }),
    strip({
      debugger: true
    }),
    resolve(),
    cjs(),
    babel({
      exclude: 'node_modules/**', // only transpile our source code
      presets: ['es2015-rollup']
    })/*,
    uglify({}, minify)*/
  ],
};
