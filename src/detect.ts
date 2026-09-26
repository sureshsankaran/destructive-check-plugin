/**
 * Destructive Command Check Plugin for OpenCode
 *
 * Automatically checks for destructive commands before any tool/bash call.
 * This plugin runs for all sessions and agents, protecting against potentially
 * harmful operations by asking for user permission.
 *
 * Destructive patterns detected:
 * - rm -rf, rm -fr, rm -r with dangerous paths
 * - git push --force, git reset (--hard/--soft/--mixed) moving HEAD
 * - DROP TABLE, DELETE FROM, TRUNCATE
 * - chmod 777, chown on system dirs
 * - dd commands
 * - format/mkfs commands
 * - sudo rm, sudo chmod, sudo chown
 * - kubectl delete, docker rm -f
 * - aws s3 rm --recursive
 * - echo/cat/printf > ~/.env (file overwrite via shell redirect)
 *
 * The plugin will:
 * 1. Detect destructive patterns in bash commands
 * 2. Detect destructive file operations (deleting important files)
 * 3. Ask for user permission before executing dangerous operations
 *
 * Installation:
 * Add to your opencode.json config:
 * {
 *   "plugin": ["file:///path/to/.opencode/plugins/destructive-check.ts"]
 * }
 */


// Destructive command patterns to check
export const DESTRUCTIVE_PATTERNS = {
  // File deletion - dangerous patterns
  rmDangerous: [
    /\brm\s+(-[rRf]+\s+)*[\/~](?=[\s;&|]|$)/i, // rm / or rm ~ (allows trailing args, e.g. --no-preserve-root)
    /\brm\s+(-[rRf]+\s+)*\/\*/, // rm /*
    /\brm\s+(-[rRf]+\s+)*~\/\*/, // rm ~/*
    /\brm\s+(-[rRf]+\s+)*\$HOME\b/i, // rm $HOME
    /\brm\s+(-[rRf]+\s+)*\/home\b/i, // rm /home
    /\brm\s+(-[rRf]+\s+)*\/etc\b/i, // rm /etc
    /\brm\s+(-[rRf]+\s+)*\/var\b/i, // rm /var
    /\brm\s+(-[rRf]+\s+)*\/usr\b/i, // rm /usr
    /\brm\s+(-[rRf]+\s+)*\/bin\b/i, // rm /bin
    /\brm\s+(-[rRf]+\s+)*\/sbin\b/i, // rm /sbin
    /\brm\s+(-[rRf]+\s+)*\/boot\b/i, // rm /boot
    /\brm\s+(-[rRf]+\s+)*\/lib\b/i, // rm /lib
    /\brm\s+(-[rRf]+\s+)*\/opt\b/i, // rm /opt
    /\brm\s+(-[rRf]+\s+)*\/root\b/i, // rm /root
    /\brm\s+(-[rRf]+\s+)*\/sys\b/i, // rm /sys
    /\brm\s+(-[rRf]+\s+)*\/proc\b/i, // rm /proc
    /\brm\s+(-[rRf]+\s+)*\/dev\b/i, // rm /dev
    /\brm\s+(-[rRf]+\s+)*\/mnt\b/i, // rm /mnt
    /\brm\s+(-[rRf]+\s+)*\/tmp\b/i, // rm /tmp
    /\brm\s+(-[rRf]+\s+)*\.git\b/i, // rm .git
    /\brm\s+(-[rRf]+\s+)*node_modules\b/i, // rm node_modules (dangerous in wrong dir)
  ],

  // Git destructive operations
  git: [
    /\bgit\s+push\s+.*--force\b/i, // git push --force
    /\bgit\s+push\s+.*-f\b/i, // git push -f
    // git reset patterns: catch both HEAD movement (rewrites history) and --hard (discards changes)
    /\bgit\s+reset\s+(--hard|--soft|--mixed)?\s*(HEAD|@)[\~\^]/i, // git reset moving HEAD (rewrites commit history)
    /\bgit\s+reset\s+--hard\b/i, // git reset --hard (discards working directory changes)
    /\bgit\s+clean\s+.*-f/i, // git clean -f
    /\bgit\s+checkout\s+--\s+\./i, // git checkout -- .
    /\bgit\s+stash\s+drop/i, // git stash drop
    /\bgit\s+branch\s+.*-D\b/i, // git branch -D
    /\bgit\s+reflog\s+expire/i, // git reflog expire
    /\bgit\s+gc\s+--prune/i, // git gc --prune
  ],

  // Database destructive operations
  database: [
    /\bDROP\s+(TABLE|DATABASE|SCHEMA|INDEX)\b/i,
    /\bTRUNCATE\s+TABLE\b/i,
    /\bDELETE\s+FROM\s+\S+\s*(;|\s*$)/i, // DELETE without WHERE
    /\bALTER\s+TABLE\s+\S+\s+DROP\b/i,
  ],

  // System destructive operations
  system: [
    /\bchmod\s+(-R\s+)?777\s+\//i, // chmod 777 /
    /\bchown\s+(-R\s+)?\S+\s+\//i, // chown on root
    /\bdd\s+.*of=\/dev\//i, // dd to device
    /\bmkfs\b/i, // Format filesystem
    /\bformat\s+[a-z]:/i, // Windows format
    /\bfdisk\b/i, // Partition tool
    /\bparted\b/i, // Partition tool
  ],

  // Elevated privileges with destructive commands
  sudo: [
    /\bsudo\s+rm\s+(-[rRf]+\s+)*\//i, // sudo rm on root
    /\bsudo\s+chmod\b/i, // sudo chmod
    /\bsudo\s+chown\b/i, // sudo chown
    /\bsudo\s+dd\b/i, // sudo dd
    /\bsudo\s+mkfs\b/i, // sudo mkfs
  ],

  // Container/cloud destructive operations
  container: [
    /\bkubectl\s+delete\s+(namespace|ns|pod|deployment|service)\b/i,
    /\bdocker\s+rm\s+.*-f/i, // docker rm -f
    /\bdocker\s+system\s+prune\s+.*-a/i, // docker system prune -a
    /\bdocker\s+volume\s+rm\b/i, // docker volume rm
    /\baws\s+s3\s+rm\s+.*--recursive\b/i, // aws s3 rm --recursive
    /\baws\s+ec2\s+terminate-instances\b/i, // terminate EC2
    /\bgcloud\s+.*delete\b/i, // gcloud delete operations
  ],

  // Package manager destructive operations
  packages: [
    /\bnpm\s+cache\s+clean\s+--force\b/i, // npm cache clean --force
    /\byarn\s+cache\s+clean\b/i, // yarn cache clean
    /\bpip\s+uninstall\s+.*-y\b/i, // pip uninstall -y (auto-confirm)
    /\bbrew\s+uninstall\s+--force\b/i, // brew uninstall --force
  ],

  // Network destructive operations
  network: [
    /\biptables\s+.*-F\b/i, // Flush iptables
    /\biptables\s+.*--flush\b/i, // Flush iptables
    /\bufw\s+reset\b/i, // Reset firewall
  ],

  // File overwrite via shell redirection (> to sensitive files, NOT >>)
  // These patterns catch ANY command redirecting to sensitive files
  // Uses negative lookbehind (?<!>) to exclude >> (append)
  fileOverwrite: [
    // .env files (credentials, secrets)
    /(?<!>)>\s*~\/\.env\b/i, // > ~/.env (not >>)
    /(?<!>)>\s*\$HOME\/\.env\b/i, // > $HOME/.env
    /(?<!>)>\s*\.env\b/i, // > .env (current directory)
    /(?<!>)>\s*[^\s>]*\/\.env\b/i, // > any/path/.env

    // SSH keys and config
    /(?<!>)>\s*~\/\.ssh\//i, // > ~/.ssh/*
    /(?<!>)>\s*\$HOME\/\.ssh\//i, // > $HOME/.ssh/*
    /(?<!>)>\s*[^\s>]*\/\.ssh\//i, // > any/path/.ssh/*

    // Shell config files
    /(?<!>)>\s*~\/\.bashrc\b/i, // > ~/.bashrc
    /(?<!>)>\s*~\/\.zshrc\b/i, // > ~/.zshrc
    /(?<!>)>\s*~\/\.profile\b/i, // > ~/.profile
    /(?<!>)>\s*~\/\.bash_profile\b/i, // > ~/.bash_profile
    /(?<!>)>\s*~\/\.zprofile\b/i, // > ~/.zprofile
    /(?<!>)>\s*\$HOME\/\.(bashrc|zshrc|profile|bash_profile|zprofile)\b/i, // > $HOME/.shellconfig

    // System directories
    /(?<!>)>\s*\/etc\//i, // > /etc/*
    /(?<!>)>\s*\/usr\//i, // > /usr/*
    /(?<!>)>\s*\/bin\//i, // > /bin/*
    /(?<!>)>\s*\/sbin\//i, // > /sbin/*
    /(?<!>)>\s*\/var\//i, // > /var/*

    // Git config
    /(?<!>)>\s*~\/\.gitconfig\b/i, // > ~/.gitconfig
    /(?<!>)>\s*\.git\//i, // > .git/*

    // Credentials and tokens
    /(?<!>)>\s*[^\s>]*credentials\b/i, // > *credentials*
    /(?<!>)>\s*[^\s>]*\.pem\b/i, // > *.pem
    /(?<!>)>\s*[^\s>]*\.key\b/i, // > *.key
    /(?<!>)>\s*[^\s>]*\.crt\b/i, // > *.crt
    /(?<!>)>\s*[^\s>]*id_rsa\b/i, // > *id_rsa*
    /(?<!>)>\s*[^\s>]*id_ed25519\b/i, // > *id_ed25519*
    /(?<!>)>\s*[^\s>]*\.secrets?\b/i, // > *.secret or *.secrets

    // Config files in home directory
    /(?<!>)>\s*~\/\.[a-z]/i, // > ~/.* (any dotfile in home)
    /(?<!>)>\s*\$HOME\/\.[a-z]/i, // > $HOME/.* (any dotfile in home)
  ],
}

// File paths that are dangerous to delete/modify
export const DANGEROUS_PATHS = [
  "/",
  "/*",
  "/home",
  "/etc",
  "/var",
  "/usr",
  "/bin",
  "/sbin",
  "/boot",
  "/lib",
  "/opt",
  "/root",
  "/sys",
  "/proc",
  "/dev",
  "~",
  "~/",
  "$HOME",
  ".git",
  ".env",
  ".ssh",
  "package.json",
  "package-lock.json",
  "yarn.lock",
  "bun.lockb",
  "Cargo.toml",
  "go.mod",
  "pyproject.toml",
  "requirements.txt",
]

export type DestructiveMatch = {
  category: string
  pattern: string
  severity: "critical" | "high" | "medium"
  command: string
}

// Check if a command matches any destructive pattern
export function checkCommand(command: string): DestructiveMatch | null {
  for (const [category, patterns] of Object.entries(DESTRUCTIVE_PATTERNS)) {
    for (const pattern of patterns) {
      if (pattern.test(command)) {
        const severity = getSeverity(category)
        return {
          category,
          pattern: pattern.toString(),
          severity,
          command,
        }
      }
    }
  }
  return null
}

// Determine severity based on category
export function getSeverity(category: string): "critical" | "high" | "medium" {
  if (category === "rmDangerous" || category === "sudo" || category === "system") {
    return "critical"
  }
  if (category === "git" || category === "database" || category === "container" || category === "fileOverwrite") {
    return "high"
  }
  return "medium"
}

// Get human-readable label for category
export function getCategoryLabel(category: string): string {
  const labels: Record<string, string> = {
    rmDangerous: "Dangerous File Deletion",
    git: "Destructive Git Operation",
    database: "Database Modification",
    system: "System-Level Change",
    sudo: "Elevated Privilege Operation",
    container: "Container/Cloud Operation",
    packages: "Package Management",
    network: "Network Configuration",
    fileOverwrite: "File Overwrite via Redirect",
  }
  return labels[category] || category
}

// Check if a file path is dangerous
export function isDangerousPath(path: string): boolean {
  const normalized = path.replace(/\\/g, "/").toLowerCase()
  return DANGEROUS_PATHS.some((dangerous) => {
    const normalizedDangerous = dangerous.toLowerCase()
    return (
      normalized === normalizedDangerous ||
      normalized.startsWith(normalizedDangerous + "/") ||
      normalized.endsWith("/" + normalizedDangerous)
    )
  })
}

// Statistics tracking
export type Stats = {
  checked: number
  permissionsRequested: number
  lastMatch?: DestructiveMatch
}

// Plugin state per session
const sessions: Record<string, Stats> = {}

const MAX_TRACKED_SESSIONS = 1000

export function getStats(sessionID: string): Stats {
  if (!sessions[sessionID]) {
    // Cap tracked sessions so long-lived hosts don't grow this map forever
    const ids = Object.keys(sessions)
    if (ids.length >= MAX_TRACKED_SESSIONS) {
      delete sessions[ids[0]]
    }
    sessions[sessionID] = { checked: 0, permissionsRequested: 0 }
  }
  return sessions[sessionID]
}

// Global stats
export const globalStats: Stats = { checked: 0, permissionsRequested: 0 }
