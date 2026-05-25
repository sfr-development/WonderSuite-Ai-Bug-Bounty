import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import { DetachedWindowApp } from './components/layout/DetachedWindowApp';
import './styles/globals.css';

// Boot fork: when the URL hash is #detached:<moduleId>, this is a popped-out
// window — mount only that module with a slim shell. Otherwise, full app.
const hash = window.location.hash || '';
const match = hash.match(/^#detached:(.+)$/);
const root = ReactDOM.createRoot(document.getElementById('root')!);

if (match) {
  const moduleId = decodeURIComponent(match[1]);
  root.render(
    <React.StrictMode>
      <DetachedWindowApp moduleId={moduleId} />
    </React.StrictMode>
  );
} else {
  root.render(
    <React.StrictMode>
      <App />
    </React.StrictMode>
  );
}
