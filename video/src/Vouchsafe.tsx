import React from 'react';
import {
  AbsoluteFill,
  Series,
  interpolate,
  spring,
  useCurrentFrame,
  useVideoConfig,
  Sequence,
} from 'remotion';
import {Bg, Shield, Pill, Rise, Mono, useTypewriter, C} from './ui';
import {MONO} from './theme';

const Center: React.FC<{children: React.ReactNode; gap?: number}> = ({children, gap = 22}) => (
  <AbsoluteFill style={{justifyContent: 'center', alignItems: 'center', textAlign: 'center', padding: 90}}>
    <div style={{display: 'flex', flexDirection: 'column', alignItems: 'center', gap}}>{children}</div>
  </AbsoluteFill>
);

const Kicker: React.FC<{children: React.ReactNode; tone?: string}> = ({children, tone = C.acc}) => (
  <div style={{fontSize: 26, letterSpacing: 4, textTransform: 'uppercase', color: tone, fontWeight: 600}}>
    {children}
  </div>
);

// ---------- 1. TITLE ----------
const TitleScene: React.FC = () => (
  <Bg>
    <Center gap={26}>
      <Shield size={150} delay={4} />
      <Rise delay={12}>
        <div style={{fontSize: 116, fontWeight: 700, letterSpacing: -2}}>
          Vouch<span style={{color: C.acc}}>safe</span>
        </div>
      </Rise>
      <Rise delay={22}>
        <div style={{fontSize: 40, color: C.txt, maxWidth: 820, lineHeight: 1.25}}>
          Lo <b style={{color: C.acc}}>scontrino revocabile</b> per i contenuti AI
        </div>
      </Rise>
      <div style={{display: 'flex', gap: 12, marginTop: 14, flexWrap: 'wrap', justifyContent: 'center'}}>
        <Pill delay={40} tone="mut">🔓 Apache-2.0</Pill>
        <Pill delay={46} tone="mut">🔑 WebAuthn · Ed25519</Pill>
        <Pill delay={52} tone="mut">🪶 zero infra</Pill>
      </div>
    </Center>
  </Bg>
);

// ---------- 2. PROBLEM ----------
const ProblemScene: React.FC = () => {
  return (
    <Bg>
      <Center gap={30}>
        <Rise delay={2}>
          <Kicker>Il problema</Kicker>
        </Rise>
        <Rise delay={8}>
          <div style={{fontSize: 64, fontWeight: 600, lineHeight: 1.15, maxWidth: 900}}>
            Gli agenti AI agiscono <span style={{color: C.acc}}>al posto tuo</span>.
          </div>
        </Rise>
        <Rise delay={40}>
          <div
            style={{
              marginTop: 10,
              padding: '20px 26px',
              borderRadius: 16,
              border: `1px solid ${C.line}`,
              background: C.panel,
              fontSize: 30,
              color: C.mut,
              display: 'flex',
              gap: 14,
              alignItems: 'center',
            }}
          >
            <span style={{fontSize: 34}}>🤖</span> «Ho pubblicato il post, prenotato il volo, risposto al cliente…»
          </div>
        </Rise>
        <Rise delay={78}>
          <div style={{fontSize: 50, fontWeight: 600, marginTop: 18, color: C.txt, maxWidth: 980, lineHeight: 1.2}}>
            Ma <span style={{color: C.warn}}>chi l'ha autorizzato</span> — ed è{' '}
            <span style={{color: C.warn}}>ancora valido</span>?
          </div>
        </Rise>
      </Center>
    </Bg>
  );
};

// ---------- 3. MECHANISM + REVOKE ----------
const FlowNode: React.FC<{ic: string; t: string; s: string; delay: number}> = ({ic, t, s, delay}) => (
  <Rise delay={delay} y={18}>
    <div
      style={{
        width: 200,
        padding: '18px 10px',
        borderRadius: 16,
        border: `1px solid ${C.line}`,
        background: C.panel,
        textAlign: 'center',
      }}
    >
      <div style={{fontSize: 40}}>{ic}</div>
      <div style={{fontSize: 26, fontWeight: 600, marginTop: 6}}>{t}</div>
      <div style={{fontSize: 19, color: C.mut, marginTop: 2}}>{s}</div>
    </div>
  </Rise>
);

const Arrow: React.FC<{delay: number}> = ({delay}) => {
  const f = useCurrentFrame();
  const o = interpolate(f, [delay, delay + 10], [0, 1], {extrapolateLeft: 'clamp', extrapolateRight: 'clamp'});
  return <div style={{fontSize: 36, color: C.mut, opacity: o}}>→</div>;
};

const MechanismScene: React.FC = () => {
  const f = useCurrentFrame();
  const {fps} = useVideoConfig();
  const flip = 250; // frame where revoke happens
  const revoked = f >= flip;
  const toRed = interpolate(f, [flip, flip + 16], [0, 1], {extrapolateLeft: 'clamp', extrapolateRight: 'clamp'});
  const shake = revoked ? Math.sin((f - flip) * 1.2) * interpolate(f, [flip, flip + 22], [8, 0], {extrapolateRight: 'clamp'}) : 0;
  const stamp = spring({frame: f - flip, fps, config: {damping: 9, mass: 0.6}});

  const badgeBorder = `1px solid ${revoked ? 'rgba(248,113,113,.6)' : 'rgba(52,211,153,.55)'}`;
  const badgeBg = revoked ? C.badbg : C.okbg;
  const badgeCol = revoked ? C.bad : C.ok;

  return (
    <Bg>
      <AbsoluteFill style={{justifyContent: 'center', alignItems: 'center', padding: 70}}>
        <Rise delay={2}>
          <Kicker>Come funziona</Kicker>
        </Rise>

        <div style={{display: 'flex', alignItems: 'center', gap: 16, marginTop: 40}}>
          <FlowNode ic="🧑" t="Persona" s="firma con passkey" delay={10} />
          <Arrow delay={26} />
          <FlowNode ic="📜" t="Mandato" s="cosa · per quanto" delay={34} />
          <Arrow delay={50} />
          <FlowNode ic="🤖" t="Agente" s="produce output" delay={58} />
          <Arrow delay={74} />
          <FlowNode ic="🧾" t="Ricevuta" s="firmata sull'output" delay={82} />
        </div>

        {/* trust badge — in normal column flow (NOT a Sequence overlay) */}
        {f >= 120 && (
          <div
            style={{
              marginTop: 64,
              width: 880,
              transform: `translateX(${shake}px)`,
              opacity: interpolate(f, [120, 134], [0, 1], {extrapolateLeft: 'clamp', extrapolateRight: 'clamp'}),
            }}
          >
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 22,
                padding: '30px 36px',
                borderRadius: 20,
                border: badgeBorder,
                background: badgeBg,
              }}
            >
              <div style={{fontSize: 66}}>{revoked ? '⛔' : '🛡️'}</div>
              <div style={{textAlign: 'left'}}>
                <div style={{fontSize: 37, fontWeight: 700, color: badgeCol, lineHeight: 1.2}}>
                  {revoked ? 'Revocato — la ricevuta non vale più' : 'Autorizzato da una persona · valido'}
                </div>
                <div style={{fontSize: 25, color: C.mut, marginTop: 8, fontFamily: MONO}}>
                  scope post:linkedin · did:key:z6Mk…5mh6B
                </div>
              </div>
            </div>
          </div>
        )}

        {/* REVOCA stamp + caption */}
        {revoked && (
          <div
            style={{
              marginTop: 34,
              display: 'flex',
              alignItems: 'center',
              gap: 16,
              opacity: toRed,
            }}
          >
            <div
              style={{
                transform: `scale(${0.6 + stamp * 0.4}) rotate(-6deg)`,
                border: `3px solid ${C.bad}`,
                color: C.bad,
                fontWeight: 800,
                fontSize: 30,
                letterSpacing: 3,
                padding: '6px 16px',
                borderRadius: 10,
              }}
            >
              REVOCA
            </div>
            <div style={{fontSize: 32, color: C.txt}}>→ rifiutato <b style={{color: C.bad}}>in tempo reale</b></div>
          </div>
        )}
      </AbsoluteFill>
    </Bg>
  );
};

// ---------- 4. CLI / INTEGRATION ----------
const TLine: React.FC<{text: string; start: number; color?: string; prompt?: boolean}> = ({
  text,
  start,
  color,
  prompt,
}) => {
  const shown = useTypewriter(text, start, 42);
  const f = useCurrentFrame();
  if (f < start) return null;
  return (
    <div style={{fontFamily: MONO, fontSize: 27, lineHeight: 1.7, color: color || C.txt, whiteSpace: 'pre'}}>
      {prompt ? <span style={{color: C.acc}}>$ </span> : '  '}
      {shown}
    </div>
  );
};

const CliScene: React.FC = () => {
  return (
    <Bg>
      <AbsoluteFill style={{justifyContent: 'center', alignItems: 'center', padding: 70}}>
        <Rise delay={2}>
          <Kicker>Mettilo nel tuo agente</Kicker>
        </Rise>

        <Rise delay={10}>
          <div
            style={{
              marginTop: 36,
              width: 940,
              borderRadius: 18,
              border: `1px solid ${C.line}`,
              background: '#0a0e17',
              overflow: 'hidden',
              boxShadow: '0 30px 80px rgba(0,0,0,.45)',
            }}
          >
            <div style={{display: 'flex', gap: 9, padding: '16px 20px', borderBottom: `1px solid ${C.line}`}}>
              <span style={{width: 14, height: 14, borderRadius: 99, background: '#ff5f57'}} />
              <span style={{width: 14, height: 14, borderRadius: 99, background: '#febc2e'}} />
              <span style={{width: 14, height: 14, borderRadius: 99, background: '#28c840'}} />
              <span style={{marginLeft: 12, color: C.mut, fontFamily: MONO, fontSize: 20}}>agent — shell</span>
            </div>
            <div style={{padding: '24px 28px', minHeight: 380}}>
              <TLine text="vouchsafe keygen --out agent.pem" start={18} prompt />
              <TLine text="did:key:z6Mk…  ← l'identità dell'agente" start={52} color={C.mut} />
              <TLine text="vouchsafe sign report.md > report.md.receipt" start={92} prompt />
              <TLine text="vouchsafe verify report.md report.md.receipt" start={150} prompt />
              <TLine text="✓ VALID — autorizzato da un umano · in scope · vivo" start={196} color={C.ok} />
              <div style={{height: 18}} />
              <TLine text="# l'umano revoca il mandato…" start={244} color={C.warn} />
              <TLine text="vouchsafe verify report.md report.md.receipt" start={278} prompt />
              <TLine text="✗ INVALID — notRevoked" start={320} color={C.bad} />
            </div>
          </div>
        </Rise>

        <div style={{display: 'flex', gap: 12, marginTop: 30, flexWrap: 'wrap', justifyContent: 'center'}}>
          <Pill delay={120} tone="acc">Claude Code</Pill>
          <Pill delay={128} tone="acc">Codex</Pill>
          <Pill delay={136} tone="acc">MCP</Pill>
          <Pill delay={144} tone="mut">un hook · e basta</Pill>
        </div>
      </AbsoluteFill>
    </Bg>
  );
};

// ---------- 5. OUTRO ----------
const OutroScene: React.FC = () => (
  <Bg>
    <Center gap={26}>
      <Shield size={120} delay={3} />
      <Rise delay={10}>
        <div style={{fontSize: 60, fontWeight: 700, letterSpacing: -1, maxWidth: 920, lineHeight: 1.12}}>
          Lo scontrino <span style={{color: C.acc}}>revocabile</span> per i contenuti AI
        </div>
      </Rise>
      <Rise delay={24}>
        <div style={{fontSize: 34, color: C.mut, maxWidth: 880, lineHeight: 1.3}}>
          Consenso umano + scontrino sull'output + <b style={{color: C.txt}}>revoca viva</b>. Open source.
        </div>
      </Rise>
      <Rise delay={40}>
        <div
          style={{
            marginTop: 18,
            padding: '16px 26px',
            borderRadius: 14,
            border: `1px solid ${C.line}`,
            background: C.panel2,
            fontFamily: MONO,
            fontSize: 30,
            color: C.acc,
          }}
        >
          github.com/lorenzotalamucci0-stack/vouchsafe
        </div>
      </Rise>
    </Center>
  </Bg>
);

// ---------- MAIN ----------
export const Vouchsafe: React.FC = () => {
  return (
    <Series>
      <Series.Sequence durationInFrames={150}>
        <TitleScene />
      </Series.Sequence>
      <Series.Sequence durationInFrames={240}>
        <ProblemScene />
      </Series.Sequence>
      <Series.Sequence durationInFrames={420}>
        <MechanismScene />
      </Series.Sequence>
      <Series.Sequence durationInFrames={380}>
        <CliScene />
      </Series.Sequence>
      <Series.Sequence durationInFrames={250}>
        <OutroScene />
      </Series.Sequence>
    </Series>
  );
};
