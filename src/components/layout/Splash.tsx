import { useState, useEffect } from 'react';
import './Splash.css';

interface Props {
  onFinish: () => void;
}

export function Splash({ onFinish }: Props) {
  const [status, setStatus] = useState('Initializing core...');
  const [fading, setFading] = useState(false);

  useEffect(() => {
    const steps = [
      [400, 'Loading modules...'],
      [900, 'Starting engine...'],
      [1400, 'Connecting services...'],
      [1800, 'Ready'],
    ] as const;

    const timers = steps.map(([ms, text]) =>
      setTimeout(() => setStatus(text as string), ms)
    );

    const fadeTimer = setTimeout(() => setFading(true), 2000);
    const doneTimer = setTimeout(onFinish, 2400);

    return () => {
      timers.forEach(clearTimeout);
      clearTimeout(fadeTimer);
      clearTimeout(doneTimer);
    };
  }, [onFinish]);

  return (
    <div className={`splash ${fading ? 'fade-out' : ''}`}>
      <div className="splash-logo">
        <img src="/wondersuite_logo.png" alt="WonderSuite" className="splash-logo-img" />
      </div>
      <div className="splash-bar">
        <div className="splash-bar-fill" />
      </div>
      <div className="splash-status">{status}</div>
    </div>
  );
}
