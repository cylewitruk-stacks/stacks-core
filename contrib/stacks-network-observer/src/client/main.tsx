import React from 'react';
import {createRoot} from 'react-dom/client';
import {Theme} from '@astryxdesign/core/theme';
import {neutralTheme} from '@astryxdesign/theme-neutral/built';

import '@astryxdesign/core/reset.css';
import '@astryxdesign/core/astryx.css';
import '@astryxdesign/theme-neutral/theme.css';
import './observer.css';
import {App} from './App';

const root = document.getElementById('root');
if (!root) throw new Error('missing application root');

createRoot(root).render(
  <React.StrictMode>
    <Theme theme={neutralTheme} mode="dark">
      <App />
    </Theme>
  </React.StrictMode>,
);
