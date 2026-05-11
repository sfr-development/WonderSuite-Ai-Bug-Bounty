import { useState, useCallback, useEffect } from 'react';
import { Bookmark, Plus, Trash2, CheckCircle, Clock, XCircle, AlertCircle, FolderOpen } from 'lucide-react';
import { useAppStore } from '../../stores';
import './Organizer.css';

type ItemStatus = 'new' | 'in_progress' | 'done' | 'ignored';
type ItemColor = '' | 'red' | 'orange' | 'green' | 'blue' | 'purple';

interface OrganizerItem {
  id: string;
  method: string;
  url: string;
  host: string;
  status: ItemStatus;
  color: ItemColor;
  notes: string;
  collection: string;
  timestamp: string;
  source_tool: string;
}

const statusConfig: Record<ItemStatus, { icon: typeof CheckCircle; label: string; color: string }> = {
  new: { icon: AlertCircle, label: 'New', color: '#64b4ff' },
  in_progress: { icon: Clock, label: 'In Progress', color: '#f0c040' },
  done: { icon: CheckCircle, label: 'Done', color: 'var(--green)' },
  ignored: { icon: XCircle, label: 'Ignored', color: 'var(--text-3)' },
};

export function Organizer() {
  const [items, setItems] = useState<OrganizerItem[]>([]);
  const [collections, setCollections] = useState<string[]>(['Default']);
  const [activeCollection, setActiveCollection] = useState('Default');
  const [selected, setSelected] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<ItemStatus | ''>('');
  const [newCollName, setNewCollName] = useState('');
  const [showNewColl, setShowNewColl] = useState(false);
  const { pendingSendTo, clearSendTo } = useAppStore();

  useEffect(() => {
    if (pendingSendTo?.tool === 'organizer') {
      let host = '';
      try { host = new URL(pendingSendTo.url).hostname; } catch { host = 'unknown'; }
      const item: OrganizerItem = {
        id: `org-${Date.now()}`, method: pendingSendTo.method || 'GET', url: pendingSendTo.url,
        host, status: 'new', color: '', notes: '', collection: activeCollection,
        timestamp: new Date().toISOString(), source_tool: 'Context Menu',
      };
      setItems(prev => [...prev, item]);
      setSelected(item.id);
      clearSendTo();
    }
  }, [pendingSendTo, clearSendTo, activeCollection]);

  const addItem = useCallback(() => {
    const item: OrganizerItem = {
      id: `org-${Date.now()}`,
      method: 'GET',
      url: 'https://example.com',
      host: 'example.com',
      status: 'new',
      color: '',
      notes: '',
      collection: activeCollection,
      timestamp: new Date().toISOString(),
      source_tool: 'Manual',
    };
    setItems(prev => [...prev, item]);
    setSelected(item.id);
  }, [activeCollection]);

  const updateItem = (id: string, upd: Partial<OrganizerItem>) => {
    setItems(prev => prev.map(i => i.id === id ? { ...i, ...upd } : i));
  };

  const removeItem = (id: string) => {
    setItems(prev => prev.filter(i => i.id !== id));
    if (selected === id) setSelected(null);
  };

  const addCollection = () => {
    if (newCollName.trim() && !collections.includes(newCollName.trim())) {
      setCollections(prev => [...prev, newCollName.trim()]);
      setActiveCollection(newCollName.trim());
    }
    setNewCollName('');
    setShowNewColl(false);
  };

  const filtered = items.filter(i => {
    if (i.collection !== activeCollection) return false;
    if (statusFilter && i.status !== statusFilter) return false;
    return true;
  });

  const selectedItem = items.find(i => i.id === selected);

  return (
    <div className="organizer">
      <div className="organizer-toolbar">
        <Bookmark size={14} />
        <span className="organizer-title">Organizer</span>
        <div style={{ flex: 1 }} />
        <button className="organizer-btn primary" onClick={addItem}><Plus size={11} /> Add Item</button>
      </div>

      <div className="organizer-body">
        {/* Collections sidebar */}
        <div className="organizer-collections">
          <div className="organizer-coll-header">
            Collections
            <button className="organizer-coll-add" onClick={() => setShowNewColl(!showNewColl)}><Plus size={10} /></button>
          </div>
          {showNewColl && (
            <div className="organizer-coll-new">
              <input value={newCollName} onChange={e => setNewCollName(e.target.value)}
                placeholder="Name..." onKeyDown={e => e.key === 'Enter' && addCollection()} autoFocus />
            </div>
          )}
          {collections.map(c => (
            <div key={c} className={`organizer-coll-item ${activeCollection === c ? 'active' : ''}`} onClick={() => setActiveCollection(c)}>
              <FolderOpen size={11} />
              {c}
              <span className="organizer-coll-count">{items.filter(i => i.collection === c).length}</span>
            </div>
          ))}
        </div>

        {/* Items list + detail */}
        <div className="organizer-main">
          {/* Status filter */}
          <div className="organizer-filter">
            {(['', 'new', 'in_progress', 'done', 'ignored'] as const).map(s => (
              <button key={s} className={`organizer-filter-btn ${statusFilter === s ? 'active' : ''}`} onClick={() => setStatusFilter(s)}>
                {s ? statusConfig[s].label : 'All'}
              </button>
            ))}
            <span className="organizer-filter-count">{filtered.length} items</span>
          </div>

          <div className="organizer-content">
            {/* Item list */}
            <div className="organizer-list">
              {filtered.map(item => {
                const S = statusConfig[item.status];
                return (
                  <div key={item.id} className={`organizer-item ${selected === item.id ? 'selected' : ''}`}
                    onClick={() => setSelected(item.id)}
                    style={item.color ? { borderLeft: `3px solid var(--${item.color || 'text-3'})` } : undefined}>
                    <S.icon size={10} style={{ color: S.color, flexShrink: 0 }} />
                    <span className="organizer-item-method" style={{ color: item.method === 'GET' ? 'var(--green)' : '#f0c040' }}>{item.method}</span>
                    <span className="organizer-item-host">{item.host}</span>
                    <span className="organizer-item-url">{item.url}</span>
                    <span className="organizer-item-tool">{item.source_tool}</span>
                    <button className="organizer-item-del" onClick={e => { e.stopPropagation(); removeItem(item.id); }}><Trash2 size={9} /></button>
                  </div>
                );
              })}
              {filtered.length === 0 && (
                <div className="organizer-empty">
                  <Bookmark size={24} strokeWidth={1} />
                  <span>No items in this collection</span>
                </div>
              )}
            </div>

            {/* Detail panel */}
            {selectedItem && (
              <div className="organizer-detail">
                <div className="organizer-detail-header">
                  <span className="organizer-detail-method" style={{ color: selectedItem.method === 'GET' ? 'var(--green)' : '#f0c040' }}>{selectedItem.method}</span>
                  <span className="organizer-detail-url">{selectedItem.url}</span>
                </div>

                <div className="organizer-detail-row">
                  <label>Status</label>
                  <select value={selectedItem.status} onChange={e => updateItem(selectedItem.id, { status: e.target.value as ItemStatus })}>
                    {Object.entries(statusConfig).map(([k, v]) => (
                      <option key={k} value={k}>{v.label}</option>
                    ))}
                  </select>
                </div>

                <div className="organizer-detail-row">
                  <label>Color</label>
                  <div className="organizer-colors">
                    {(['', 'red', 'orange', 'green', 'blue', 'purple'] as ItemColor[]).map(c => (
                      <span key={c} className={`organizer-color-dot ${selectedItem.color === c ? 'active' : ''}`}
                        style={{ background: c ? `var(--${c === 'orange' ? 'yellow' : c})` : 'var(--text-3)' }}
                        onClick={() => updateItem(selectedItem.id, { color: c })} />
                    ))}
                  </div>
                </div>

                <div className="organizer-detail-row">
                  <label>Collection</label>
                  <select value={selectedItem.collection} onChange={e => updateItem(selectedItem.id, { collection: e.target.value })}>
                    {collections.map(c => <option key={c} value={c}>{c}</option>)}
                  </select>
                </div>

                <div className="organizer-detail-notes">
                  <label>Notes</label>
                  <textarea value={selectedItem.notes} onChange={e => updateItem(selectedItem.id, { notes: e.target.value })}
                    placeholder="Add notes about this item..." />
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
