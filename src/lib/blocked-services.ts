export interface BlockedServiceDef {
  id: string;
  name: string;
  category: string;
  domains: string[];
  icon: string; // keyword or emoji
}

export const BLOCKED_SERVICES: BlockedServiceDef[] = [
  {
    id: 'tiktok',
    name: 'TikTok',
    category: 'Social',
    domains: ['tiktok.com', 'byteoversea.com', 'ibytedtos.com', 'muscdn.com', 'musical.ly', 'tiktokcdn.com', 'tiktokv.com'],
    icon: '🎵',
  },
  {
    id: 'youtube',
    name: 'YouTube',
    category: 'Video',
    domains: ['youtube.com', 'youtu.be', 'ytimg.com', 'googlevideo.com'],
    icon: '▶️',
  },
  {
    id: 'discord',
    name: 'Discord',
    category: 'Communication',
    domains: ['discord.com', 'discordapp.com', 'discord.gg', 'discordapp.net'],
    icon: '💬',
  },
  {
    id: 'facebook',
    name: 'Facebook',
    category: 'Social',
    domains: ['facebook.com', 'fb.com', 'fbcdn.net', 'fbsbx.com', 'facebook.net'],
    icon: '👥',
  },
  {
    id: 'instagram',
    name: 'Instagram',
    category: 'Social',
    domains: ['instagram.com', 'cdninstagram.com'],
    icon: '📷',
  },
  {
    id: 'whatsapp',
    name: 'WhatsApp',
    category: 'Communication',
    domains: ['whatsapp.com', 'whatsapp.net'],
    icon: '📞',
  },
  {
    id: 'telegram',
    name: 'Telegram',
    category: 'Communication',
    domains: ['telegram.org', 't.me', 'telegra.ph', 'telegram.me'],
    icon: '✈️',
  },
  {
    id: 'twitter',
    name: 'Twitter / X',
    category: 'Social',
    domains: ['twitter.com', 'x.com', 'twimg.com', 't.co'],
    icon: '🐦',
  },
  {
    id: 'netflix',
    name: 'Netflix',
    category: 'Entertainment',
    domains: ['netflix.com', 'nflxext.com', 'nflximg.net', 'nflxvideo.net'],
    icon: '🎬',
  },
  {
    id: 'steam',
    name: 'Steam',
    category: 'Gaming',
    domains: ['steampowered.com', 'steamcommunity.com', 'steamstatic.com'],
    icon: '🎮',
  },
  {
    id: 'spotify',
    name: 'Spotify',
    category: 'Music',
    domains: ['spotify.com', 'scdn.co', 'spotifycdn.com'],
    icon: '🎧',
  },
  {
    id: 'reddit',
    name: 'Reddit',
    category: 'Social',
    domains: ['reddit.com', 'redd.it', 'redditstatic.com', 'redditmedia.com'],
    icon: '🤖',
  },
  {
    id: 'roblox',
    name: 'Roblox',
    category: 'Gaming',
    domains: ['roblox.com', 'rbxcdn.com'],
    icon: '🧱',
  },
  {
    id: 'twitch',
    name: 'Twitch',
    category: 'Streaming',
    domains: ['twitch.tv', 'ttvnw.net', 'jtvnw.net'],
    icon: '👾',
  },
];

