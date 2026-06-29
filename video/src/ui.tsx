import React from 'react';
import {AbsoluteFill, interpolate, spring, useCurrentFrame, useVideoConfig} from 'remotion';
import {C, SANS, MONO} from './theme';

export const Bg: React.FC<{children?: React.ReactNode}> = ({children}) => (
  <AbsoluteFill
    style={{
      background: `radial-gradient(900px 520px at 50% -8%, #16203a 0%, ${C.bg} 62%)`,
      fontFamily: SANS,
      color: C.txt,
    }}
  >
    {children}
  </AbsoluteFill>
);

// Shield + check mark, draws/scales in.
export const Shield: React.FC<{size?: number; delay?: number; color?: string}> = ({
  size = 120,
  delay = 0,
  color = C.acc,
}) => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const s = spring({frame: frame - delay, fps, config: {damping: 13, mass: 0.7}});
  const dash = interpolate(s, [0, 1], [40, 0]);
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" style={{transform: `scale(${0.4 + s * 0.6})`}}>
      <path
        d="M12 3l7 4v5c0 4-3 7-7 8-4-1-7-4-7-8V7z"
        stroke={color}
        strokeWidth={1.6}
        strokeLinecap="round"
        strokeLinejoin="round"
        fill="rgba(91,140,255,.10)"
      />
      <path
        d="M9 12l2 2 4-4"
        stroke={color}
        strokeWidth={2}
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeDasharray={12}
        strokeDashoffset={dash}
      />
    </svg>
  );
};

export const Pill: React.FC<{children: React.ReactNode; delay?: number; tone?: keyof typeof tones}> = ({
  children,
  delay = 0,
  tone = 'mut',
}) => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const s = spring({frame: frame - delay, fps, config: {damping: 14}});
  const t = tones[tone];
  return (
    <div
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 8,
        padding: '10px 18px',
        borderRadius: 999,
        border: `1px solid ${t.border}`,
        background: t.bg,
        color: t.fg,
        fontSize: 24,
        fontWeight: 500,
        opacity: s,
        transform: `translateY(${(1 - s) * 14}px)`,
      }}
    >
      {children}
    </div>
  );
};

const tones = {
  mut: {fg: C.mut, border: C.line, bg: C.panel2},
  acc: {fg: C.acc, border: 'rgba(91,140,255,.5)', bg: C.accbg},
  ok: {fg: C.ok, border: 'rgba(52,211,153,.5)', bg: C.okbg},
  bad: {fg: C.bad, border: 'rgba(248,113,113,.5)', bg: C.badbg},
};

// Fade+rise wrapper.
export const Rise: React.FC<{children: React.ReactNode; delay?: number; y?: number}> = ({
  children,
  delay = 0,
  y = 26,
}) => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const s = spring({frame: frame - delay, fps, config: {damping: 16}});
  return <div style={{opacity: s, transform: `translateY(${(1 - s) * y}px)`}}>{children}</div>;
};

export const Mono: React.FC<{children: React.ReactNode; style?: React.CSSProperties}> = ({children, style}) => (
  <span style={{fontFamily: MONO, ...style}}>{children}</span>
);

// Typewriter: reveals `text` over `chars` frames starting at `start`.
export const useTypewriter = (text: string, start: number, cps = 38) => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const n = Math.max(0, Math.floor(((frame - start) / fps) * cps));
  return text.slice(0, n);
};

export {C};
