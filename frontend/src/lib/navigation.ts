import type { LucideIcon } from 'lucide-react'
import {
  Activity,
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
    label: 'Respond',
    items: [
      { to: '/investigate', label: 'Investigation', shortLabel: 'Investigate', description: 'Run the bounded response workflow', icon: Crosshair },
      { to: '/analyze', label: 'Analyze log', shortLabel: 'Analyze', description: 'Submit a log for deterministic analysis', icon: ScanSearch },
      { to: '/incident', label: 'Live incident', shortLabel: 'Incident', description: 'Follow the active incident stream', icon: Radar },
    ],
  },
  {
    label: 'Understand',
    items: [
      { to: '/overview', label: 'Incident brief', shortLabel: 'Brief', description: 'Read the current operational picture', icon: LayoutDashboard },
      { to: '/graph', label: 'Attack graph', shortLabel: 'Graph', description: 'Inspect lateral movement and reachability', icon: Waypoints },
      { to: '/digital-twin', label: 'Digital twin', shortLabel: 'Twin', description: 'Test containment counterfactuals', icon: Cpu },
      { to: '/attackers', label: 'Attackers', shortLabel: 'Actors', description: 'Review attributed threat actors', icon: Users },
      { to: '/threat-intel', label: 'Threat intelligence', shortLabel: 'Intel', description: 'Trace evidence and attribution', icon: Shield },
      { to: '/threat-radar', label: 'Threat radar', shortLabel: 'Radar', description: 'Compare threats across dimensions', icon: Satellite },
    ],
  },
  {
    label: 'Validate',
    items: [
      { to: '/scoreboard', label: 'PS7 scoreboard', shortLabel: 'Scoreboard', description: 'Verify challenge coverage and claims', icon: ClipboardCheck },
      { to: '/metrics', label: 'Models and metrics', shortLabel: 'Metrics', description: 'Inspect measured model performance', icon: ChartNoAxesCombined },
      { to: '/methodology', label: 'Data and methodology', shortLabel: 'Method', description: 'Review provenance and limitations', icon: Database },
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
