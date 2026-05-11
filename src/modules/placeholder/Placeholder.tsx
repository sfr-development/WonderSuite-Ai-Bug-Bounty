import { Construction } from 'lucide-react';

export function Placeholder() {
  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', color: 'var(--text-3)', gap: 8 }}>
      <Construction size={28} />
      <span style={{ fontSize: 12 }}>Coming soon</span>
    </div>
  );
}
