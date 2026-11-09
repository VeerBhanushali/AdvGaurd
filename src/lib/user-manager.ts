export interface DeviceProfile {
  id: string;
  name: string;
  token: string;
  ownerEmail: string;
  createdAt: number;
  lastActive: number;
  totalQueries: number;
  blockedQueries: number;
  status: 'active' | 'paused' | 'revoked';
}

export interface UserAccount {
  id: string;
  email: string;
  role: 'admin' | 'user';
  name: string;
  createdAt: number;
}

class UserManager {
  private static instance: UserManager;
  private users: UserAccount[] = [
    {
      id: 'usr_admin',
      email: 'veer@bhanushali.com',
      role: 'admin',
      name: 'Veer Bhanushali',
      createdAt: Date.now() - 86400000 * 30,
    },
  ];

  private devices: DeviceProfile[] = [
    {
      id: 'dev_1',
      name: 'Veer’s iPhone 15 Pro',
      token: 'veer-iphone',
      ownerEmail: 'veer@bhanushali.com',
      createdAt: Date.now() - 86400000 * 14,
      lastActive: Date.now() - 1000 * 60 * 2,
      totalQueries: 1420,
      blockedQueries: 380,
      status: 'active',
    },
    {
      id: 'dev_2',
      name: 'Work MacBook Pro',
      token: 'work-laptop',
      ownerEmail: 'veer@bhanushali.com',
      createdAt: Date.now() - 86400000 * 7,
      lastActive: Date.now() - 1000 * 60 * 15,
      totalQueries: 890,
      blockedQueries: 140,
      status: 'active',
    },
    {
      id: 'dev_3',
      name: 'Living Room Smart TV',
      token: 'smart-tv',
      ownerEmail: 'veer@bhanushali.com',
      createdAt: Date.now() - 86400000 * 3,
      lastActive: Date.now() - 1000 * 60 * 45,
      totalQueries: 410,
      blockedQueries: 95,
      status: 'active',
    },
  ];

  private constructor() {}

  public static getInstance(): UserManager {
    if (!UserManager.instance) {
      UserManager.instance = new UserManager();
    }
    return UserManager.instance;
  }

  public getUsers(): UserAccount[] {
    return this.users;
  }

  public getDevices(): DeviceProfile[] {
    return this.devices;
  }

  public registerDevice(name: string, token: string, ownerEmail = 'veer@bhanushali.com'): DeviceProfile {
    const cleanToken = token.trim().toLowerCase().replace(/[^a-z0-9-_]/g, '') || `dev-${Date.now().toString(36)}`;
    const newDev: DeviceProfile = {
      id: `dev_${Date.now()}`,
      name: name.trim() || 'My Device',
      token: cleanToken,
      ownerEmail,
      createdAt: Date.now(),
      lastActive: Date.now(),
      totalQueries: 0,
      blockedQueries: 0,
      status: 'active',
    };
    this.devices.push(newDev);
    return newDev;
  }

  public toggleDeviceStatus(id: string, status: 'active' | 'paused' | 'revoked'): boolean {
    const dev = this.devices.find((d) => d.id === id);
    if (!dev) return false;
    dev.status = status;
    return true;
  }

  public deleteDevice(id: string): boolean {
    const idx = this.devices.findIndex((d) => d.id === id);
    if (idx === -1) return false;
    this.devices.splice(idx, 1);
    return true;
  }

  public recordDeviceActivity(tokenOrIp: string, blocked: boolean) {
    const dev = this.devices.find((d) => d.token === tokenOrIp || tokenOrIp.includes(d.token));
    if (dev) {
      dev.totalQueries++;
      if (blocked) dev.blockedQueries++;
      dev.lastActive = Date.now();
    }
  }
}

export const userManager = UserManager.getInstance();
