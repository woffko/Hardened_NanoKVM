import { http } from '@/lib/http.ts';

export type FirewallMode = 'baseline' | 'restricted' | 'paranoid';

export type FirewallStatus = {
  config: {
    mode: FirewallMode;
  };
  effectiveMode: FirewallMode;
  restrictedActive: boolean;
  paranoidActive: boolean;
  paranoidAvailable: boolean;
  confirmationRequired: boolean;
  httpsEnabled: boolean;
  httpsPort: number;
  backend: {
    preferred: string;
    iptables: FirewallTool;
    ip6tables: FirewallTool;
    nft: FirewallTool;
  };
  rules: {
    ipv4: string;
    ipv6: string;
    nft: string;
  };
  message: string;
};

export type FirewallTool = {
  installed: boolean;
  detail: string;
};

export function getStatus() {
  return http.get('/api/system/firewall');
}

export function setMode(mode: FirewallMode) {
  return http.post('/api/system/firewall', { mode });
}

export function confirmPending() {
  return http.post('/api/system/firewall/confirm');
}
