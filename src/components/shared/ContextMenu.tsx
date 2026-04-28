import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { Zap, FileJson, ArrowRightLeft, Target, PlusCircle, ListOrdered, Layers, Globe, Search, MessageSquare, Code, Link2, Activity, Network, Clock, Bug, GitCompare, Trash2, Link, TerminalSquare, Download, BookText } from 'lucide-react';
import { useAppStore } from '../../stores';
import './ContextMenu.css';

export function ContextMenu() {
  const { contextMenu, closeContextMenu, sendTo, addToast, addScope } = useAppStore();
  const menuRef = useRef<HTMLDivElement>(null);

  const [styles, setStyles] = useState<React.CSSProperties>({ top: -9999, left: -9999, opacity: 0 });

  // Handle dynamic positioning
  useLayoutEffect(() => {
    if (!contextMenu.isOpen || !menuRef.current) return;

    const { innerWidth, innerHeight } = window;
    // Reset any previous constraints to get true height
    menuRef.current.style.maxHeight = 'none';
    const rect = menuRef.current.getBoundingClientRect();
    menuRef.current.style.maxHeight = ''; // Restore CSS max-height

    let { x, y } = contextMenu;
    const padding = 12;
    const newStyles: React.CSSProperties = { opacity: 1 };

    // X axis calculation
    if (x + rect.width > innerWidth - padding) {
      newStyles.left = 'auto';
      newStyles.right = padding;
    } else {
      newStyles.left = x;
      newStyles.right = 'auto';
    }
    
    // Y axis calculation
    if (y + rect.height > innerHeight - padding) {
      // Flips the menu upward, minimum padding from bottom bounds
      newStyles.top = 'auto';
      newStyles.bottom = Math.max(padding, innerHeight - y + 5); 
    } else {
      newStyles.top = y;
      newStyles.bottom = 'auto';
    }

    setStyles(newStyles);
  }, [contextMenu.isOpen, contextMenu.x, contextMenu.y]);

  // Close when clicking outside
  useEffect(() => {
    if (!contextMenu.isOpen) return;
    const handleClick = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        closeContextMenu();
      }
    };
    document.addEventListener('mousedown', handleClick);
    return () => document.removeEventListener('mousedown', handleClick);
  }, [contextMenu.isOpen, closeContextMenu]);

  if (!contextMenu.isOpen || !contextMenu.data) return null;

  const { method, url, requestRaw, responseRaw } = contextMenu.data;
  
  const handleAction = (tool: string, target?: 'left' | 'right') => {
    sendTo(tool, method, url, requestRaw, responseRaw, target);
    closeContextMenu();
  };

  const executeGeneric = (actionName: string) => {
    addToast({ title: 'Feature in Development', message: `'${actionName}' will be available in a future update.`, type: 'info' });
    closeContextMenu();
  };

  const executeAddToScope = () => {
    try {
      const u = new URL(url);
      addScope(u.hostname);
      addToast({ title: 'Scope Updated', message: `${u.hostname} added to global scope.`, type: 'success' });
    } catch {
      addToast({ title: 'Scope Error', message: 'Could not parse URL hostname.', type: 'error' });
    }
    closeContextMenu();
  };

  const copyUrl = () => {
    navigator.clipboard.writeText(url);
    closeContextMenu();
  };

  return (
    <div
      ref={menuRef}
      className="context-menu"
      style={styles}
      onContextMenu={(e) => e.preventDefault()}
    >
      <div className="context-menu-header">
        <span className="context-method">{method || 'TARGET'}</span>
        <span className="context-url" title={url}>{url || 'Global Selection'}</span>
      </div>
      
      <div className="context-menu-actions">
        <button onClick={executeAddToScope}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}><PlusCircle size={14} /> Add to scope</div>
        </button>
        <div className="context-menu-divider" />
        
        <button onClick={() => handleAction('intruder')}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}><Zap size={14} /> Send to Intruder</div>
        </button>
        <button onClick={() => handleAction('repeater')}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}><ArrowRightLeft size={14} /> Send to Repeater</div>
        </button>
        <button onClick={() => handleAction('sequencer')}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}><ListOrdered size={14} /> Send to Sequencer</div>
        </button>
        <button onClick={() => handleAction('organizer')}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}><Layers size={14} /> Send to Organizer</div>
        </button>
        
        <div className="context-submenu-trigger">
          <button style={{ width: '100%' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}><FileJson size={14} /> Send to Comparer</div>
          </button>
          <div className="context-submenu">
            <button onClick={() => handleAction('comparer', 'left')}>Send to Left (Item 1)</button>
            <button onClick={() => handleAction('comparer', 'right')}>Send to Right (Item 2)</button>
          </div>
        </div>

        <div className="context-menu-divider" />
        
        <div className="context-submenu-trigger">
          <button style={{ width: '100%' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}><Globe size={14} /> Request in browser</div>
          </button>
          <div className="context-submenu">
            <button onClick={() => executeGeneric('Browser Original')}>In original session</button>
            <button onClick={() => executeGeneric('Browser Current')}>In current session</button>
          </div>
        </div>

        <div className="context-submenu-trigger">
          <button style={{ width: '100%' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}><Target size={14} /> Engagement tools</div>
          </button>
          <div className="context-submenu">
            <button onClick={() => executeGeneric('Search')}><Search size={12} style={{ marginRight: 6 }}/> Search</button>
            <button onClick={() => executeGeneric('Find comments')}><MessageSquare size={12} style={{ marginRight: 6 }}/> Find comments</button>
            <button onClick={() => executeGeneric('Find scripts')}><Code size={12} style={{ marginRight: 6 }}/> Find scripts</button>
            <button onClick={() => executeGeneric('Find references')}><Link2 size={12} style={{ marginRight: 6 }}/> Find references</button>
            <button onClick={() => executeGeneric('Analyze target')}><Activity size={12} style={{ marginRight: 6 }}/> Analyze target</button>
            <button onClick={() => executeGeneric('Discover content')}><Network size={12} style={{ marginRight: 6 }}/> Discover content</button>
            <button onClick={() => executeGeneric('Schedule task')}><Clock size={12} style={{ marginRight: 6 }}/> Schedule task</button>
            <button onClick={() => executeGeneric('Auto setup attack')}><Bug size={12} style={{ marginRight: 6 }}/> Simulate manual testing</button>
          </div>
        </div>

        <button onClick={() => executeGeneric('Compare sites')}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}><GitCompare size={14} /> Compare site maps</div>
        </button>

        <div className="context-menu-divider" />

        <button onClick={() => executeGeneric('Delete item')} style={{ color: 'var(--red)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}><Trash2 size={14} /> Delete item</div>
        </button>
        <button onClick={copyUrl}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}><Link size={14} /> Copy URL</div>
        </button>
        <button onClick={() => {
          navigator.clipboard.writeText(`curl -X ${method || 'GET'} "${url}"`);
          closeContextMenu();
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}><TerminalSquare size={14} /> Copy as curl command</div>
        </button>
        <button onClick={() => executeGeneric('Save items')}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}><Download size={14} /> Save item</div>
        </button>
        
        <div className="context-menu-divider" />
        
        <button onClick={() => executeGeneric('Sitemap Documentation')}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}><BookText size={14} /> Site map documentation</div>
        </button>

      </div>
    </div>
  );
}
