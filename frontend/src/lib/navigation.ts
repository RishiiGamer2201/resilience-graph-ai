import type { LucideIcon } from 'lucide-react'
import {
  Activity,
  Boxes,
  ChartNoAxesCombined,
  ClipboardCheck,
  Cpu,
  Crosshair,
  Database,
  LayoutDashboard,
  Radar,
  ScanSearch,
  Satellite,
  Shield,
  Users,
  Waypoints,
} from 'lucide-react'

export interface NavigationItem {
  to: string
  label: string
  shortLabel: string
  description: string
  icon: LucideIcon
}

export interface NavigationGroup {
  label: string
  items: NavigationItem[]
}

export const navigationGroups: NavigationGroup[] = [
  {
    label: 'Start here',
    items: [
      { to: '/investigate', label: 'Guided investigation', shortLabel: 'Investigate', description: 'Follow the attack story step by step', icon: Crosshair },
      { to: '/analyze', label: 'Check a security log', shortLabel: 'Analyze', description: 'Upload a log or use a sample', icon: ScanSearch },
      { to: '/incident', label: 'Incident timeline', shortLabel: 'Incident', description: 'See suspicious events in time order', icon: Radar },
    ],
  },
  {
    label: 'Understand the attack',
    items: [
      { to: '/overview', label: 'Incident summary', shortLabel: 'Summary', description: 'Get the important facts at a glance', icon: LayoutDashboard },
      { to: '/graph', label: '2D attack map', shortLabel: 'Map', description: 'See how the attacker moved between computers', icon: Waypoints },
      { to: '/digital-twin', label: 'Safe response test', shortLabel: 'Test', description: 'Test isolation without touching real systems', icon: Cpu },
      { to: '/attackers', label: 'Compromised accounts', shortLabel: 'Accounts', description: 'See which accounts were used in the attack', icon: Users },
      { to: '/threat-intel', label: 'Known threat comparison', shortLabel: 'Threats', description: 'Compare this incident with known attacker behavior', icon: Shield },
      { to: '/threat-radar', label: 'External threat reports', shortLabel: 'Reports', description: 'Find public reports related to this incident', icon: Satellite },
    ],
  },
  {
    label: 'Check the system',
    items: [
      { to: '/scoreboard', label: 'Evaluation results', shortLabel: 'Results', description: 'See which requirements were tested', icon: ClipboardCheck },
      { to: '/metrics', label: 'Model performance', shortLabel: 'Performance', description: 'See how accurate and reliable the models were', icon: ChartNoAxesCombined },
      { to: '/world-model', label: 'Network world model', shortLabel: 'World model', description: 'See the 24 network states the model learned, and where a baseline beats it', icon: Boxes },
      { to: '/methodology', label: 'Data and limitations', shortLabel: 'Method', description: 'See where results came from and what they cannot prove', icon: Database },
    ],
  },
]

export const navigationItems = navigationGroups.flatMap((group) => group.items)

export const getNavigationItem = (pathname: string) =>
  navigationItems.find((item) => pathname === item.to) ?? {
    to: pathname,
    label: 'Operations',
    shortLabel: 'Operations',
    description: 'SOC command center',
    icon: Activity,
  }
