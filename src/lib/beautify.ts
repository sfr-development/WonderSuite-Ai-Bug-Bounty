import { js_beautify, css_beautify, html_beautify } from 'js-beautify';

const JS_OPTS: Parameters<typeof js_beautify>[1] = {
  indent_size: 2,
  indent_char: ' ',
  max_preserve_newlines: 2,
  preserve_newlines: true,
  keep_array_indentation: false,
  break_chained_methods: false,
  space_in_empty_paren: false,
  wrap_line_length: 0,
  end_with_newline: true,
  templating: ['auto'],
  unescape_strings: false,
  e4x: true,
};

const CSS_OPTS: Parameters<typeof css_beautify>[1] = {
  indent_size: 2,
  newline_between_rules: true,
  end_with_newline: true,
  selector_separator_newline: true,
};

const HTML_OPTS: Parameters<typeof html_beautify>[1] = {
  indent_size: 2,
  indent_inner_html: true,
  wrap_line_length: 0,
  unformatted: ['pre', 'code', 'textarea', 'script', 'style'],
  content_unformatted: ['pre', 'textarea'],
  end_with_newline: true,
};

export type BeautifyLang = 'javascript' | 'typescript' | 'js' | 'ts' | 'css' | 'scss' | 'html' | 'xml' | 'json' | string;

export function beautify(code: string, lang: BeautifyLang): string {
  if (!code || !code.trim()) return code;
  try {
    switch (lang) {
      case 'json':
        return JSON.stringify(JSON.parse(code), null, 2);
      case 'js':
      case 'javascript':
      case 'ts':
      case 'typescript':
        return js_beautify(code, JS_OPTS);
      case 'css':
      case 'scss':
      case 'less':
        return css_beautify(code, CSS_OPTS);
      case 'html':
      case 'xml':
        return html_beautify(code, HTML_OPTS);
      default:
        return code;
    }
  } catch {
    return code;
  }
}

export function canBeautify(lang: string): boolean {
  return ['js', 'javascript', 'ts', 'typescript', 'css', 'scss', 'less', 'html', 'xml', 'json'].includes(lang);
}
