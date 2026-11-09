import { randomBytes } from 'crypto';
import { isValidClientId } from './security';

export interface DeviceProfile {
  id: string;
  name: string;
  token: string;
  createdAt: number;
  lastActive: number;
  totalQueries: number;
  blockedQueries: number;
  status: 'active' | 'paused' | 'revoked';
}

export interface UserAccount {
  id: string;
  role: 'admin' | 'user';
  name: string;
  createdAt: number;
}

/** Hard cap so anonymous registrations on a public instance cannot exhaust memory. */
const MAX_DEVICES = Math.max(10, parseInt(process.env.MAX_DEVICES || '1000', 10) || 1000);

export type RegisterResult =
  | { ok: true; device: DeviceProfile }
  | { ok: false; error: string; status: number };

class UserManager {
  private static instance: UserManager;
  private devices = new Map<string, DeviceProfile>(); // keyed by token

  private constructor() {}

  public static getInstance(): UserManager {
    if (!UserManager.instance) UserManager.instance = new UserManager();
    return UserManager.instance;
  }

  public getUsers(): UserAccount[] {
    return [{ id: 'admin', role: 'admin', name: 'Administrator', createdAt: 0 }];
  }

  public getDevices(): DeviceProfile[] {
    return Array.from(this.devices.values());
  }

  public getDeviceByToken(token: string): DeviceProfile | undefined {
    return this.devices.get(token);
  }

  /**
   * Public registration returns a token with a random suffix so tokens are not
   * guessable (a guessable token lets anyone read or pollute someone's stats).
   */
  public registerDevice(rawName: unknown, rawToken: unknown): RegisterResult {
    if (this.devices.size >= MAX_DEVICES) {
      return { ok: false, error: 'Device limit reached on this instance', status: 503 };
    }
    const name = typeof rawName === 'string' ? rawName.replace(/[\u0000-\u001f<>]/g, '').trim().slice(0, 64) : '';
    const base =
      (typeof rawToken === 'string' ? rawToken : '')
        .toLowerCase()
        .replace(/[^a-z0-9-]/g, '-')
        .replace(/-+/g, '-')
        .replace(/^-|-$/g, '')
        .slice(0, 40) || 'device';
    const token = `${base}-${randomBytes(4).toString('hex')}`;
    if (!isValidClientId(token) || this.devices.has(token)) {
      return { ok: false, error: 'Invalid device token', status: 400 };
    }
    const device: DeviceProfile = {
      id: `dev_${randomBytes(6).toString('hex')}`,
      name: name || 'My Device',
      token,
      createdAt: Date.now(),
      lastActive: 0,
      totalQueries: 0,
      blockedQueries: 0,
      status: 'active',
    };
    this.devices.set(token, device);
    return { ok: true, device };
  }

  public setDeviceStatus(id: string, status: DeviceProfile['status']): boolean {
    for (const d of this.devices.values()) {
      if (d.id === id) {
        d.status = status;
        return true;
      }
    }
    return false;
  }

  public deleteDevice(id: string): boolean {
    for (const [token, d] of this.devices) {
      if (d.id === id) {
        this.devices.delete(token);
        return true;
      }
    }
    return false;
  }

  public recordDeviceActivity(token: string | undefined, blocked: boolean) {
    if (!token) return;
    const dev = this.devices.get(token);
    if (!dev) return;
    dev.totalQueries++;
    if (blocked) dev.blockedQueries++;
    dev.lastActive = Date.now();
  }
}

export const userManager = UserManager.getInstance();
