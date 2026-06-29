import React from 'react';
import {Composition} from 'remotion';
import {Vouchsafe} from './Vouchsafe';

export const RemotionRoot: React.FC = () => {
  return (
    <Composition
      id="Vouchsafe"
      component={Vouchsafe}
      durationInFrames={1440}
      fps={30}
      width={1080}
      height={1080}
    />
  );
};
