import React, { useRef, useEffect } from 'react';
import './HttpViewer.css';

interface HttpViewerProps {
  value: string;
  editable?: boolean;
  onChange?: (val: string) => void;
  placeholder?: string;
  isHex?: boolean;
  mimeType?: string;
  fileName?: string;
}

// Best-effort MIME/extension language detector
function detectLanguage(mimeType?: string, fileName?: string): string {
  const mime = mimeType?.toLowerCase() || '';
  const file = fileName?.toLowerCase() || '';
  if (mime.includes('json') || file.endsWith('.json')) return 'json';
  if (mime.includes('html') || file.endsWith('.html') || file.endsWith('.htm')) return 'html';
  if (mime.includes('xml') || file.endsWith('.xml')) return 'xml';
  if (mime.includes('css') || file.endsWith('.css')) return 'css';
  if (mime.includes('javascript') || mime.includes('ecmascript') || file.endsWith('.js') || file.endsWith('.jsx') || file.endsWith('.ts') || file.endsWith('.tsx')) return 'javascript';
  if (mime.includes('x-www-form-urlencoded')) return 'url-encoded';
  return '';
}

// Reusable premium color styles for sensitive headers
const sensitiveHeaders = ['authorization', 'cookie', 'set-cookie', 'x-api-key', 'x-auth-token', 'bearer', 'token'];
const securityHeaders = ['strict-transport-security', 'content-security-policy', 'x-frame-options', 'x-content-type-options', 'x-xss-protection', 'referrer-policy', 'permissions-policy'];

export function HttpViewer({ value, editable = false, onChange, placeholder = '', isHex = false, mimeType, fileName }: HttpViewerProps) {
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const highlightRef = useRef<HTMLDivElement>(null);

  // Sync scroll of textarea and highlighted background
  const handleScroll = (e: React.UIEvent<HTMLTextAreaElement>) => {
    if (highlightRef.current) {
      highlightRef.current.scrollTop = e.currentTarget.scrollTop;
      highlightRef.current.scrollLeft = e.currentTarget.scrollLeft;
    }
  };

  // Synchronize height on mount/value changes
  useEffect(() => {
    if (textareaRef.current && highlightRef.current) {
      highlightRef.current.scrollTop = textareaRef.current.scrollTop;
      highlightRef.current.scrollLeft = textareaRef.current.scrollLeft;
    }
  }, [value]);

  // Tokenize & color HEX dump line-by-line
  const renderHex = (text: string) => {
    const lines = text.split('\n');
    return lines.map((line, idx) => {
      // Hex pattern: 8-digit offset, spaces, 16 hex columns, spaces, 16 ASCII characters
      // Example: 00000000  47 45 54 20 2f 20 48 54  55 50 2f 31 2e 31 0d 0a  |GET / HTTP/1.1..|
      // Or:      00000000  47 45 54 20 2f ...       GET / ...
      const offsetMatch = line.match(/^([0-9a-fA-F]{8})/);
      if (offsetMatch) {
        const offset = offsetMatch[1];
        let rest = line.slice(8);
        
        // Find ASCII block (sometimes wrapped in |...|, or is the final 16 chars)
        let hexPart = rest;
        let asciiPart = '';
        const barIndex = rest.indexOf('|');
        if (barIndex !== -1) {
          hexPart = rest.slice(0, barIndex);
          asciiPart = rest.slice(barIndex);
        } else if (rest.length > 50) {
          // split based on standard width
          hexPart = rest.slice(0, 50);
          asciiPart = rest.slice(50);
        }

        return (
          <div key={idx} className="http-viewer-line">
            <span className="http-token-hex-offset">{offset}</span>
            <span className="http-token-hex-bytes">{hexPart}</span>
            <span className="http-token-hex-ascii">{asciiPart}</span>
          </div>
        );
      }
      return <div key={idx} className="http-viewer-line">{line}</div>;
    });
  };

  // High-performance React tokenization for JSON
  const renderJsonLine = (line: string) => {
    // Basic JSON tokenizer using Regex replacements into React elements
    const elements: React.ReactNode[] = [];
    let lastIndex = 0;
    
    // Pattern matches: JSON strings (including escaped chars), numbers/booleans/null, braces/brackets/colons/commas
    const jsonRe = /("(?:[^"\\]|\\.)*")|(\b(?:true|false|null|\d+(?:\.\d+)?)\b)|([\{\}\[\]:,])/g;
    let match;

    while ((match = jsonRe.exec(line)) !== null) {
      const matchIndex = match.index;
      // Push any raw preceding characters (like whitespace or colons)
      if (matchIndex > lastIndex) {
        elements.push(line.slice(lastIndex, matchIndex));
      }

      if (match[1]) {
        // String literal - determine if it is a JSON Key or String Value
        const isKey = line.slice(matchIndex + match[1].length).trim().startsWith(':');
        if (isKey) {
          elements.push(<span key={matchIndex} className="http-token-json-key">{match[1]}</span>);
        } else {
          elements.push(<span key={matchIndex} className="http-token-json-val">{match[1]}</span>);
        }
      } else if (match[2]) {
        // Literal Number, Bool, Null
        const val = match[2];
        let cls = 'http-token-json-num';
        if (val === 'true' || val === 'false') cls = 'http-token-json-bool';
        if (val === 'null') cls = 'http-token-json-null';
        elements.push(<span key={matchIndex} className={cls}>{val}</span>);
      } else if (match[3]) {
        // Punctuations
        elements.push(<span key={matchIndex} className="http-token-punctuation">{match[3]}</span>);
      }
      lastIndex = jsonRe.lastIndex;
    }

    if (lastIndex < line.length) {
      elements.push(line.slice(lastIndex));
    }

    return elements.length > 0 ? elements : line;
  };

  // High-performance HTML/XML tokenization
  const renderHtmlXmlLine = (line: string) => {
    const elements: React.ReactNode[] = [];
    let lastIndex = 0;
    
    // Tag matching: opening/closing tags, attributes, string values, comments
    const xmlRe = /(<\/?[a-zA-Z0-9:-]+>?)|(<!--[\s\S]*?-->)|(\b[a-zA-Z0-9:-]+=)|("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')/g;
    let match;

    while ((match = xmlRe.exec(line)) !== null) {
      const matchIndex = match.index;
      if (matchIndex > lastIndex) {
        elements.push(line.slice(lastIndex, matchIndex));
      }

      if (match[1]) {
        // Tag name
        elements.push(<span key={matchIndex} className="http-token-xml-tag">{match[1]}</span>);
      } else if (match[2]) {
        // Comment
        elements.push(<span key={matchIndex} className="http-token-comment">{match[2]}</span>);
      } else if (match[3]) {
        // Attribute name
        elements.push(<span key={matchIndex} className="http-token-xml-attr">{match[3]}</span>);
      } else if (match[4]) {
        // Attribute value
        elements.push(<span key={matchIndex} className="http-token-xml-val">{match[4]}</span>);
      }
      lastIndex = xmlRe.lastIndex;
    }

    if (lastIndex < line.length) {
      elements.push(line.slice(lastIndex));
    }

    return elements.length > 0 ? elements : line;
  };

  // High-performance URL-encoded form parameters tokenization
  const renderUrlEncodedLine = (line: string) => {
    if (!line.includes('=')) return line;
    const elements: React.ReactNode[] = [];
    const pairs = line.split('&');
    
    pairs.forEach((pair, idx) => {
      const eqIdx = pair.indexOf('=');
      if (eqIdx !== -1) {
        const key = pair.slice(0, eqIdx);
        const val = pair.slice(eqIdx + 1);
        elements.push(<span key={`k-${idx}`} className="http-token-url-key">{key}</span>);
        elements.push(<span key={`eq-${idx}`} className="http-token-punctuation">=</span>);
        elements.push(<span key={`v-${idx}`} className="http-token-url-val">{val}</span>);
      } else {
        elements.push(pair);
      }
      if (idx < pairs.length - 1) {
        elements.push(<span key={`amp-${idx}`} className="http-token-punctuation">&amp;</span>);
      }
    });

    return elements;
  };

  // High-performance full HTTP highlighting
  const renderHttpRaw = (text: string, lang: string) => {
    // Split headers from body (separated by double newline)
    const normalized = text.replace(/\r\n/g, '\n');
    const doubleNL = normalized.indexOf('\n\n');
    
    let headersStr = normalized;
    let bodyStr = '';
    
    if (doubleNL !== -1) {
      headersStr = normalized.slice(0, doubleNL);
      bodyStr = normalized.slice(doubleNL + 2);
    }

    const headerLines = headersStr.split('\n');
    const headerElements = headerLines.map((line, idx) => {
      if (idx === 0) {
        // First line: request line (GET / HTTP/1.1) or status line (HTTP/1.1 200 OK)
        const requestMatch = line.match(/^([A-Z]+)\s+(\S+)\s+(HTTP\/\d\.\d)/);
        if (requestMatch) {
          const [, method, path, proto] = requestMatch;
          let methodClass = 'http-token-req-method';
          if (method === 'GET') methodClass += ' get';
          if (method === 'POST') methodClass += ' post';
          if (method === 'DELETE') methodClass += ' delete';
          return (
            <div key={idx} className="http-viewer-line">
              <span className={methodClass}>{method}</span>{' '}
              <span className="http-token-req-path">{path}</span>{' '}
              <span className="http-token-req-proto">{proto}</span>
            </div>
          );
        }
        
        const responseMatch = line.match(/^(HTTP\/\d\.\d)\s+(\d{3})\s+(.*)$/);
        if (responseMatch) {
          const [, proto, status, phrase] = responseMatch;
          const statusNum = parseInt(status, 10);
          let statusClass = 'http-token-resp-status';
          if (statusNum >= 200 && statusNum < 300) statusClass += ' s2xx';
          else if (statusNum >= 300 && statusNum < 400) statusClass += ' s3xx';
          else if (statusNum >= 400 && statusNum < 500) statusClass += ' s4xx';
          else if (statusNum >= 500) statusClass += ' s5xx';
          
          return (
            <div key={idx} className="http-viewer-line">
              <span className="http-token-req-proto">{proto}</span>{' '}
              <span className={statusClass}>{status}</span>{' '}
              <span className="http-token-resp-phrase">{phrase}</span>
            </div>
          );
        }

        return <div key={idx} className="http-viewer-line http-token-req-line">{line}</div>;
      }

      // Standard headers: "Name: Value"
      const colonIdx = line.indexOf(':');
      if (colonIdx !== -1) {
        const key = line.slice(0, colonIdx);
        const val = line.slice(colonIdx + 1);
        const lowerKey = key.trim().toLowerCase();
        
        let valClass = 'http-token-hdr-val';
        if (sensitiveHeaders.includes(lowerKey)) valClass += ' sensitive';
        else if (securityHeaders.includes(lowerKey)) valClass += ' security';
        else if (lowerKey === 'content-type' || lowerKey === 'accept') valClass += ' content';

        return (
          <div key={idx} className="http-viewer-line">
            <span className="http-token-hdr-key">{key}</span>:
            <span className={valClass}>{val}</span>
          </div>
        );
      }

      return <div key={idx} className="http-viewer-line">{line}</div>;
    });

    const bodyLines = bodyStr ? bodyStr.split('\n') : [];
    const bodyElements = bodyLines.map((line, idx) => {
      let content: React.ReactNode = line;
      if (lang === 'json') {
        content = renderJsonLine(line);
      } else if (lang === 'html' || lang === 'xml') {
        content = renderHtmlXmlLine(line);
      } else if (lang === 'url-encoded') {
        content = renderUrlEncodedLine(line);
      }
      return <div key={`b-${idx}`} className="http-viewer-line">{content}</div>;
    });

    return (
      <>
        {headerElements}
        {bodyStr && <div className="http-viewer-line http-token-punctuation" style={{margin: '4px 0'}} />}
        {bodyElements}
      </>
    );
  };

  const detectedLang = detectLanguage(mimeType, fileName);

  return (
    <div className="http-viewer-container">
      {editable ? (
        <div className="http-viewer-editor-wrap">
          {/* Transparent textarea overlaid on top */}
          <textarea
            ref={textareaRef}
            className="http-viewer-textarea"
            value={value}
            onChange={(e) => onChange?.(e.target.value)}
            onScroll={handleScroll}
            placeholder={placeholder}
            spellCheck={false}
            autoCapitalize="off"
            autoComplete="off"
            autoCorrect="off"
          />
          {/* Synchronized highlighted rendering underneath */}
          <div ref={highlightRef} className="http-viewer-highlighted-bg">
            {isHex ? renderHex(value) : renderHttpRaw(value, detectedLang)}
            {/* Pad the bottom to ensure scroll alignment */}
            <div className="http-viewer-spacer" />
          </div>
        </div>
      ) : (
        <div className="http-viewer-readonly">
          {isHex ? renderHex(value) : renderHttpRaw(value, detectedLang)}
        </div>
      )}
    </div>
  );
}
