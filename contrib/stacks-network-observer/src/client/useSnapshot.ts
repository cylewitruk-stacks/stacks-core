import {useCallback, useEffect, useState} from 'react';

import type {
  NetworkSnapshot,
  PublicPortalSnapshot,
  ViewerPrincipal,
  ViewerSession,
} from '../shared/model';

interface PortalState {
  publicSnapshot: PublicPortalSnapshot | null;
  federationSnapshot: NetworkSnapshot | null;
  principal: ViewerPrincipal | null;
  connected: boolean;
  sessionLoading: boolean;
  error: string | null;
  authError: string | null;
  login(email: string, password: string): Promise<boolean>;
  logout(): Promise<void>;
}

export function useSnapshot(): PortalState {
  const [publicSnapshot, setPublicSnapshot] = useState<PublicPortalSnapshot | null>(null);
  const [federationSnapshot, setFederationSnapshot] = useState<NetworkSnapshot | null>(null);
  const [principal, setPrincipal] = useState<ViewerPrincipal | null>(null);
  const [sessionLoading, setSessionLoading] = useState(true);
  const [publicConnected, setPublicConnected] = useState(false);
  const [federationConnected, setFederationConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [authError, setAuthError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    Promise.all([
      fetchJson<PublicPortalSnapshot>('/api/public/snapshot'),
      fetchJson<ViewerSession>('/api/session'),
    ]).then(([publicValue, session]) => {
      if (!active) return;
      setPublicSnapshot(publicValue);
      setPrincipal(session.principal);
    }).catch(reason => active && setError(String(reason)))
      .finally(() => active && setSessionLoading(false));
    const events = new EventSource('/api/public/events');
    events.addEventListener('open', () => setPublicConnected(true));
    events.addEventListener('snapshot', event => {
      try {
        setPublicSnapshot(JSON.parse((event as MessageEvent<string>).data) as PublicPortalSnapshot);
        setError(null);
      } catch {
        setError('public data stream sent an invalid snapshot');
      }
    });
    events.addEventListener('error', () => setPublicConnected(false));
    return () => {
      active = false;
      events.close();
    };
  }, []);

  useEffect(() => {
    if (!principal) {
      setFederationSnapshot(null);
      setFederationConnected(false);
      return;
    }
    let active = true;
    fetchJson<NetworkSnapshot>('/api/federation/snapshot')
      .then(value => active && setFederationSnapshot(value))
      .catch(reason => active && setError(String(reason)));
    const events = new EventSource('/api/federation/events');
    events.addEventListener('open', () => {
      setFederationConnected(true);
      setError(null);
    });
    events.addEventListener('snapshot', event => {
      try {
        setFederationSnapshot(JSON.parse((event as MessageEvent<string>).data) as NetworkSnapshot);
        setError(null);
      } catch {
        setError('federation stream sent an invalid snapshot');
      }
    });
    events.addEventListener('error', () => {
      setFederationConnected(false);
      setError('authenticated telemetry stream is reconnecting');
      void fetchJson<ViewerSession>('/api/session')
        .then(session => {
          if (!active || session.principal) return;
          setPrincipal(null);
          setFederationSnapshot(null);
          setAuthError('Your federation session expired. Sign in again.');
        })
        .catch(() => undefined);
    });
    return () => {
      active = false;
      events.close();
    };
  }, [principal]);

  const login = useCallback(async (email: string, password: string): Promise<boolean> => {
    setAuthError(null);
    const response = await fetch('/api/session/login', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({email, password}),
    });
    if (!response.ok) {
      setAuthError(response.status === 401 ? 'Email or password is invalid.' : 'Sign-in is temporarily unavailable.');
      return false;
    }
    const session = await response.json() as ViewerSession;
    setPrincipal(session.principal);
    return session.principal !== null;
  }, []);

  const logout = useCallback(async (): Promise<void> => {
    await fetch('/api/session/logout', {method: 'POST'});
    setPrincipal(null);
    setFederationSnapshot(null);
    setError(null);
    setAuthError(null);
  }, []);

  return {
    publicSnapshot,
    federationSnapshot,
    principal,
    connected: principal ? federationConnected : publicConnected,
    sessionLoading,
    error,
    authError,
    login,
    logout,
  };
}

async function fetchJson<T>(path: string): Promise<T> {
  const response = await fetch(path, {cache: 'no-store'});
  if (!response.ok) throw new Error(`${path} returned ${response.status}`);
  return response.json() as Promise<T>;
}
