import { useState, useEffect, useRef } from 'react';
import { highlight, detectHighlightLang } from './highlighter';
import { beautify, canBeautify } from './beautify';

export interface CodeViewState {
  html: string;
  loading: boolean;
  canFormat: boolean;
}

export function useCodeView(
  code: string | undefined,
  mime?: string,
  path?: string,
  formatted?: boolean,
): CodeViewState {
  const [html, setHtml] = useState('');
  const [loading, setLoading] = useState(false);
  const reqRef = useRef(0);

  const lang = detectHighlightLang(mime, path);
  const canFormat = canBeautify(lang);

  useEffect(() => {
    if (!code) {
      setHtml('');
      setLoading(false);
      return;
    }

    const req = ++reqRef.current;
    setLoading(true);

    const source = formatted && canFormat ? beautify(code, lang) : code;

    highlight(source, lang).then(h => {
      if (req !== reqRef.current) return; // stale, discard
      setHtml(h);
      setLoading(false);
    });
  }, [code, lang, formatted, canFormat]);

  return { html, loading, canFormat };
}
