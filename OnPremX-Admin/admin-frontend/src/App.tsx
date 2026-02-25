import { useEffect, useState } from 'react';
import axios from 'axios';
import { 
  Monitor, Search, X, Sun, Moon, Database, ChevronRight, 
  Shield, Zap, Globe, Terminal, LayoutGrid, List as ListIcon, 
  Activity, Layers, Box, AlertTriangle, ShieldCheck, RefreshCw, Trash2, Play, StopCircle, AlertCircle, Download
} from 'lucide-react';

// --- Interfaces ---

interface Patch {
  hotfix_id: string;
  description: string;
  installed_by: string;
  installed_on: string;
}

interface EventLog {
  time_generated: string;
  entry_type: string;
  source: string;
  message: string;
  event_id: number;
}

interface Software {
  name: string;
  version: string;
  vendor: string;
  uninstall_string?: string;
}

interface Service {
  name: string;
  status: string;
}

interface SecurityInfo {
  usb_blocked: boolean;
  rdp_blocked: boolean;
  usb_devices: string[];
  rdp_sessions: string[];
}

interface AgentData {
  hostname: string;
  os: string;
  arch: string;
  platform: string;
  platform_version: string;
  uptime: number;
  cpu_model: string;
  cpu_usage: number;
  total_ram: number;
  used_ram: number;
  ram_usage: number;
  total_disk: number;
  used_disk: number;
  disk_usage: number;
  agent_version: string;
  last_seen: string;
  ip_address?: string;
  mac_address?: string;
  software?: Software[];
  services?: Service[];
  patches?: Patch[];
  event_logs?: EventLog[];
  rdp_enabled?: boolean;
  security?: SecurityInfo;
  tags?: string[];
  group?: string;
}

interface Script {
  id: string;
  name: string;
  description: string;
  content: string;
}

// --- Components ---

function App() {
  const [activeView, setActiveView] = useState<'overview' | 'endpoints' | 'scripts' | 'logs' | 'network'>('overview');
  const [agents, setAgents] = useState<AgentData[]>([]);
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState<Date>(new Date());
  const [searchTerm, setSearchTerm] = useState('');
  const [viewMode, setViewMode] = useState<'grid' | 'list'>('grid');
  const [theme, setTheme] = useState<'light' | 'dark'>(() => {
    const t = localStorage.getItem('theme');
    return t === 'light' || t === 'dark' ? (t as 'light' | 'dark') : 'light';
  });
  
  const [selectedAgent, setSelectedAgent] = useState<AgentData | null>(null);
  const [showBulkUpdate, setShowBulkUpdate] = useState(false);
  const [scripts, setScripts] = useState<Script[]>([]);

  useEffect(() => {
    const root = document.documentElement;
    if (theme === 'dark') root.classList.add('dark');
    else root.classList.remove('dark');
    localStorage.setItem('theme', theme);
  }, [theme]);

  const fetchAgents = async () => {
    try {
      const response = await axios.get('/api/agents');
      setAgents(response.data);
      setLastUpdated(new Date());
      if (selectedAgent) {
        const updated = response.data.find((a: AgentData) => a.hostname === selectedAgent.hostname);
        if (updated) setSelectedAgent(updated);
      }
    } catch (error) {
      console.error('Error fetching agents:', error);
    } finally {
      setLoading(false);
    }
  };

  const fetchScripts = async () => {
    try {
      const response = await axios.get('/api/scripts');
      setScripts(response.data);
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    fetchAgents();
    fetchScripts();
    const interval = setInterval(fetchAgents, 5000);
    return () => clearInterval(interval);
  }, []);

  const formatUptime = (seconds: number) => {
    const days = Math.floor(seconds / (3600 * 24));
    const hours = Math.floor((seconds % (3600 * 24)) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    return `${days}d ${hours}h ${minutes}m`;
  };

  const isOnline = (lastSeen: string) => {
    const diff = (new Date().getTime() - new Date(lastSeen).getTime()) / 1000;
    return diff < 60;
  };

  const filteredAgents = agents.filter(agent => 
    agent.hostname.toLowerCase().includes(searchTerm.toLowerCase()) ||
    agent.platform.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-[#0f172a] text-slate-900 dark:text-slate-100 font-sans selection:bg-slate-900 selection:text-white transition-colors duration-300">
      <div className="flex h-screen overflow-hidden">
        {/* Minimalist Sidebar */}
        <aside className="w-64 bg-white dark:bg-slate-900 border-r border-slate-200 dark:border-slate-800 flex flex-col z-30 transition-colors">
          <div className="p-8">
            <div className="flex items-center gap-3 mb-12">
              <div className="w-8 h-8 bg-slate-900 dark:bg-indigo-600 rounded-lg flex items-center justify-center text-white">
                <Shield size={18} strokeWidth={2.5} />
              </div>
              <div>
                <h1 className="text-sm font-bold tracking-tight uppercase leading-tight">OnPremX</h1>
                <p className="text-[10px] text-slate-400 dark:text-slate-500 font-medium italic lowercase">by priyanshu</p>
              </div>
            </div>

            <nav className="space-y-1">
              <SidebarItem 
                icon={<Activity size={18}/>} 
                label="Overview" 
                active={activeView === 'overview'} 
                onClick={() => setActiveView('overview')}
              />
              <SidebarItem 
                icon={<Monitor size={18}/>} 
                label="Endpoints" 
                count={agents.length} 
                active={activeView === 'endpoints'} 
                onClick={() => setActiveView('endpoints')}
              />
              <SidebarItem 
                icon={<Terminal size={18}/>} 
                label="Scripts" 
                active={activeView === 'scripts'} 
                onClick={() => setActiveView('scripts')}
              />
              <SidebarItem 
                icon={<Database size={18}/>} 
                label="Logs" 
                active={activeView === 'logs'} 
                onClick={() => setActiveView('logs')}
              />
              <SidebarItem 
                icon={<Globe size={18}/>} 
                label="Network" 
                active={activeView === 'network'} 
                onClick={() => setActiveView('network')}
              />
            </nav>
          </div>

          <div className="mt-auto p-6 border-t border-slate-100 dark:border-slate-800">
          </div>
        </aside>

        {/* Main Workspace */}
        <main className="flex-1 flex flex-col overflow-hidden bg-slate-50 dark:bg-[#0f172a] transition-colors">
          {/* Minimal Header */}
          <header className="h-16 bg-white dark:bg-slate-900 border-b border-slate-200 dark:border-slate-800 px-8 flex justify-between items-center shrink-0 transition-colors">
            <div className="flex items-center gap-4 flex-1 max-w-xl">
              <Search className="text-slate-400" size={18} />
              <input 
                type="text" 
                placeholder="Search endpoints..." 
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="bg-transparent text-sm w-full focus:outline-none placeholder:text-slate-400 text-slate-900 dark:text-slate-100"
              />
            </div>

            <div className="flex items-center gap-6">
              <span className="text-[11px] font-medium text-slate-400 tabular-nums uppercase tracking-widest">
                Synced {lastUpdated.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
              </span>

              <a 
                href="/dl/OnPremX-Agent.exe" 
                download
                className="flex items-center gap-2 px-4 py-2 bg-emerald-600/10 dark:bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-500/20 rounded-lg text-xs font-bold uppercase tracking-wider hover:bg-emerald-600 hover:text-white dark:hover:bg-emerald-600 dark:hover:text-white transition-all shadow-sm"
              >
                <Monitor size={14} />
                Download Agent (.exe)
              </a>

              <a 
                href="/dl/install_agent.bat" 
                download
                className="flex items-center gap-2 px-4 py-2 bg-indigo-600/10 dark:bg-indigo-500/10 text-indigo-600 dark:text-indigo-400 border border-indigo-200 dark:border-indigo-500/20 rounded-lg text-xs font-bold uppercase tracking-wider hover:bg-indigo-600 hover:text-white dark:hover:bg-indigo-600 dark:hover:text-white transition-all shadow-sm"
              >
                <Download size={14} />
                One-Click Setup (.bat)
              </a>

              <button 
                onClick={() => setShowBulkUpdate(true)}
                className="minimal-button-primary"
              >
                Bulk Sync
              </button>
              <button
                onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
                className="p-2 text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors"
              >
                {theme === 'dark' ? <Sun size={18} /> : <Moon size={18} />}
              </button>
            </div>
          </header>

          {/* Content Area */}
          <div className="flex-1 overflow-y-auto p-8 custom-scrollbar">
            {activeView === 'overview' && (
              <>
                {/* Minimal Metrics Cards */}
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-12">
                  <MetricCard title="Live Nodes" value={agents.filter(a => isOnline(a.last_seen)).length} trend="Active" />
                  <MetricCard title="Total Managed" value={agents.length} trend="Stable" />
                  <MetricCard title="App Instances" value={agents.reduce((acc, curr) => acc + (curr.software?.length || 0), 0)} trend="Indexed" />
                  <MetricCard title="System Alerts" value={agents.filter(a => (a.security?.usb_devices?.length || 0) > 0).length} trend="Review" />
                </div>

                {/* List/Grid Header */}
                <div className="flex justify-between items-center mb-6">
                  <h2 className="text-sm font-bold text-slate-900 dark:text-slate-100 uppercase tracking-widest">Managed Grid</h2>
                  <div className="flex bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg p-0.5">
                    <button 
                      onClick={() => setViewMode('grid')}
                      className={`p-1.5 rounded-md transition-all ${viewMode === 'grid' ? 'bg-slate-100 dark:bg-slate-700 text-slate-900 dark:text-white' : 'text-slate-400 hover:text-slate-600'}`}
                    >
                      <LayoutGrid size={16} />
                    </button>
                    <button 
                      onClick={() => setViewMode('list')}
                      className={`p-1.5 rounded-md transition-all ${viewMode === 'list' ? 'bg-slate-100 dark:bg-slate-700 text-slate-900 dark:text-white' : 'text-slate-400 hover:text-slate-600'}`}
                    >
                      <ListIcon size={16} />
                    </button>
                  </div>
                </div>

                {loading ? (
                  <div className="flex flex-col items-center justify-center py-24">
                    <div className="w-8 h-8 border-2 border-slate-200 dark:border-slate-700 border-t-slate-900 dark:border-t-indigo-500 rounded-full animate-spin"></div>
                    <p className="mt-4 text-[11px] font-bold text-slate-400 uppercase tracking-widest">Polling Data...</p>
                  </div>
                ) : filteredAgents.length === 0 ? (
                  <div className="minimal-card py-20 text-center border-dashed dark:border-slate-700">
                     <p className="text-slate-400 text-sm">No endpoints matching current filter.</p>
                  </div>
                ) : viewMode === 'grid' ? (
                  <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">
                    {filteredAgents.map(agent => (
                      <MinimalAgentCard key={agent.hostname} agent={agent} isOnline={isOnline(agent.last_seen)} onClick={() => setSelectedAgent(agent)} />
                    ))}
                  </div>
                ) : (
                  <div className="minimal-card overflow-hidden">
                    <table className="w-full text-left">
                      <thead className="bg-slate-50 dark:bg-slate-800/50 border-b border-slate-200 dark:border-slate-700">
                        <tr className="text-[10px] font-bold text-slate-400 dark:text-slate-500 uppercase tracking-widest">
                          <th className="px-6 py-4">Endpoint</th>
                          <th className="px-6 py-4">Platform</th>
                          <th className="px-6 py-4">Network IP</th>
                          <th className="px-6 py-4">Status</th>
                          <th className="px-6 py-4 text-right">Access</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                        {filteredAgents.map(agent => (
                          <tr key={agent.hostname} className="hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors cursor-pointer group" onClick={() => setSelectedAgent(agent)}>
                            <td className="px-6 py-4 font-semibold text-slate-900 dark:text-slate-100 text-sm">{agent.hostname}</td>
                            <td className="px-6 py-4 text-xs text-slate-500 dark:text-slate-400">{agent.platform}</td>
                            <td className="px-6 py-4 text-xs tabular-nums text-slate-400">{agent.ip_address}</td>
                            <td className="px-6 py-4">
                               <span className={`minimal-badge ${isOnline(agent.last_seen) ? 'status-online' : 'status-offline'}`}>
                                  {isOnline(agent.last_seen) ? 'Active' : 'Dormant'}
                               </span>
                            </td>
                            <td className="px-6 py-4 text-right">
                               <ChevronRight className="inline-block text-slate-300 dark:text-slate-600 group-hover:text-slate-900 dark:group-hover:text-white transition-colors" size={16} />
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </>
            )}

            {activeView === 'endpoints' && (
              <div className="space-y-6">
                <h2 className="text-sm font-bold text-slate-900 dark:text-slate-100 uppercase tracking-widest">Global Endpoints</h2>
                <div className="minimal-card overflow-hidden">
                  <table className="w-full text-left">
                    <thead className="bg-slate-50 dark:bg-slate-800/50 border-b border-slate-200 dark:border-slate-700">
                      <tr className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">
                        <th className="px-6 py-4">Endpoint Name</th>
                        <th className="px-6 py-4">OS Version</th>
                        <th className="px-6 py-4">Core Version</th>
                        <th className="px-6 py-4">Last Sync</th>
                        <th className="px-6 py-4 text-right">Action</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                      {agents.map(agent => (
                        <tr key={agent.hostname} className="hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors cursor-pointer" onClick={() => setSelectedAgent(agent)}>
                          <td className="px-6 py-4 font-semibold text-slate-900 dark:text-slate-100 text-sm">{agent.hostname}</td>
                          <td className="px-6 py-4 text-xs text-slate-500 dark:text-slate-400">{agent.platform_version}</td>
                          <td className="px-6 py-4 text-xs tabular-nums text-slate-400">v{agent.agent_version}</td>
                          <td className="px-6 py-4 text-xs text-slate-400">{new Date(agent.last_seen).toLocaleString()}</td>
                          <td className="px-6 py-4 text-right">
                            <button className="text-[10px] font-bold text-slate-900 dark:text-slate-100 uppercase tracking-widest hover:underline">Manage</button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {activeView === 'scripts' && (
              <div className="space-y-6">
                <h2 className="text-sm font-bold text-slate-900 dark:text-slate-100 uppercase tracking-widest">Central Script Library</h2>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                  {scripts.map(script => (
                    <div key={script.id} className="minimal-card p-6 flex flex-col justify-between">
                      <div>
                        <div className="flex items-center gap-3 mb-4">
                          <div className="p-2 bg-slate-50 dark:bg-slate-900 rounded-lg text-slate-900 dark:text-slate-100 border border-slate-100 dark:border-slate-700">
                            <Terminal size={18} />
                          </div>
                          <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100">{script.name}</h3>
                        </div>
                        <p className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed mb-6">{script.description}</p>
                      </div>
                      <button className="minimal-button-secondary w-full text-[10px] uppercase tracking-widest">Execute on Grid</button>
                    </div>
                  ))}
                  <div className="minimal-card p-6 border-dashed dark:border-slate-700 flex flex-col items-center justify-center text-center cursor-pointer hover:bg-slate-50 dark:hover:bg-slate-800/50">
                    <div className="p-3 bg-slate-50 dark:bg-slate-900 rounded-full text-slate-400 mb-3">
                      <Zap size={20} />
                    </div>
                    <span className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">New Script</span>
                  </div>
                </div>
              </div>
            )}

            {activeView === 'logs' && (
              <div className="space-y-6">
                <h2 className="text-sm font-bold text-slate-900 dark:text-slate-100 uppercase tracking-widest">System-Wide Audit Logs</h2>
                <div className="minimal-card p-8 text-center py-32 border-dashed dark:border-slate-700">
                  <Database className="text-slate-200 dark:text-slate-800 mx-auto mb-4" size={48} />
                  <p className="text-slate-400 text-sm">Audit trail is currently being indexed. Recent agent heartbeats are available in individual endpoint views.</p>
                </div>
              </div>
            )}

            {activeView === 'network' && (
              <div className="space-y-6">
                <h2 className="text-sm font-bold text-slate-900 dark:text-slate-100 uppercase tracking-widest">Network Topology</h2>
                <div className="minimal-card overflow-hidden">
                  <table className="w-full text-left">
                    <thead className="bg-slate-50 dark:bg-slate-800/50 border-b border-slate-200 dark:border-slate-700">
                      <tr className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">
                        <th className="px-6 py-4">Internal IP</th>
                        <th className="px-6 py-4">MAC Identifier</th>
                        <th className="px-6 py-4">Host Node</th>
                        <th className="px-6 py-4 text-right">Uplink</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                      {agents.map(agent => (
                        <tr key={agent.hostname} className="hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors">
                          <td className="px-6 py-4 font-mono text-xs text-blue-600 dark:text-indigo-400 tabular-nums">{agent.ip_address}</td>
                          <td className="px-6 py-4 font-mono text-xs text-slate-400 tabular-nums">{agent.mac_address}</td>
                          <td className="px-6 py-4 font-semibold text-slate-900 dark:text-slate-100 text-sm">{agent.hostname}</td>
                          <td className="px-6 py-4 text-right">
                             <span className="w-2 h-2 rounded-full bg-emerald-500 inline-block shadow-sm"></span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        </main>
      </div>

      {/* Minimal Modals */}
      {showBulkUpdate && (
        <MinimalBulkUpdateModal 
          agents={agents}
          isOnline={isOnline}
          onClose={() => setShowBulkUpdate(false)}
        />
      )}

      {selectedAgent && (
        <MinimalAgentDetailModal 
          agent={selectedAgent} 
          onClose={() => setSelectedAgent(null)} 
          isOnline={isOnline(selectedAgent.last_seen)}
          formatUptime={formatUptime}
          scripts={scripts}
        />
      )}
    </div>
  );
}

// --- Minimal UI Components ---

function SidebarItem({ icon, label, active = false, count, onClick }: any) {
  return (
    <button 
      onClick={onClick}
      className={`w-full flex items-center justify-between px-4 py-2.5 rounded-lg transition-all duration-200 group ${
        active 
          ? 'nav-item-active' 
          : 'nav-item-inactive'
      }`}
    >
      <div className="flex items-center gap-3">
        <span className={active ? 'text-white' : 'text-slate-400 group-hover:text-slate-900'}>{icon}</span>
        <span className="text-sm font-medium">{label}</span>
      </div>
      {count !== undefined && (
        <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${active ? 'bg-white/20' : 'bg-slate-100 dark:bg-slate-800 text-slate-500'}`}>
          {count}
        </span>
      )}
    </button>
  );
}

function MetricCard({ title, value, trend }: any) {
  return (
    <div className="minimal-card p-6 transition-colors">
      <div className="flex justify-between items-start mb-4">
        <span className="text-[10px] font-bold text-slate-400 dark:text-slate-500 uppercase tracking-widest">{title}</span>
        <span className="text-[10px] font-bold text-slate-900 dark:text-indigo-400 bg-slate-50 dark:bg-indigo-500/10 px-2 py-0.5 rounded-md border border-transparent dark:border-indigo-500/20">{trend}</span>
      </div>
      <h3 className="text-2xl font-bold text-slate-900 dark:text-white tabular-nums leading-none">{value}</h3>
    </div>
  );
}

function MinimalAgentCard({ agent, isOnline, onClick }: any) {
  return (
    <div 
      onClick={onClick}
      className="minimal-card p-6 cursor-pointer group"
    >
      <div className="flex justify-between items-start mb-8">
        <div>
          <h3 className="text-base font-bold text-slate-900 dark:text-white group-hover:text-blue-600 dark:group-hover:text-indigo-400 transition-colors">{agent.hostname}</h3>
          <div className="flex items-center gap-2 mt-1.5">
            <div className={`w-1.5 h-1.5 rounded-full ${isOnline ? 'bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.4)]' : 'bg-slate-300 dark:bg-slate-700'}`}></div>
            <span className="text-[10px] font-bold uppercase tracking-widest text-slate-400 dark:text-slate-500">{isOnline ? 'Live Connection' : 'Offline'}</span>
          </div>
        </div>
        <div className="p-2 bg-slate-50 dark:bg-slate-800 rounded-lg text-slate-400 dark:text-slate-500">
          <Monitor size={18}/>
        </div>
      </div>

      <div className="space-y-4">
        <div className="grid grid-cols-2 gap-4">
          <div>
            <span className="text-[9px] font-bold text-slate-400 dark:text-slate-500 uppercase block mb-1">CPU Load</span>
            <span className="text-sm font-semibold text-slate-900 dark:text-slate-100 tabular-nums">{agent.cpu_usage.toFixed(1)}%</span>
          </div>
          <div>
            <span className="text-[9px] font-bold text-slate-400 dark:text-slate-500 uppercase block mb-1">RAM Load</span>
            <span className="text-sm font-semibold text-slate-900 dark:text-slate-100 tabular-nums">{agent.ram_usage.toFixed(1)}%</span>
          </div>
        </div>
        
        <div className="h-1 w-full bg-slate-100 dark:bg-slate-800 rounded-full overflow-hidden">
          <div className="h-full bg-slate-900 dark:bg-indigo-500 transition-all duration-1000" style={{ width: `${agent.cpu_usage}%` }}></div>
        </div>

        <div className="pt-4 border-t border-slate-50 dark:border-slate-800 flex justify-between items-center text-[10px] font-medium text-slate-400 dark:text-slate-500">
           <span className="uppercase">{agent.platform}</span>
           <span className="tabular-nums uppercase">{new Date(agent.last_seen).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
        </div>
      </div>
    </div>
  );
}

function MinimalBulkUpdateModal({ agents, isOnline, onClose }: any) {
  const [selected, setSelected] = useState<string[]>([]);
  const toggleSelect = (hostname: string) => setSelected(prev => prev.includes(hostname) ? prev.filter(h => h !== hostname) : [...prev, hostname]);

  const handleUpdate = async () => {
    if (selected.length === 0) return;
    try {
      await axios.post('/api/agents/bulk-update', { hostnames: selected });
      alert(`Queued update for ${selected.length} agents.`);
      onClose();
    } catch (e) {
      alert("Failed to queue update.");
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/10 dark:bg-black/60 backdrop-blur-sm transition-colors">
      <div className="bg-white dark:bg-slate-900 rounded-2xl shadow-2xl w-full max-w-xl border border-slate-200 dark:border-slate-800 overflow-hidden flex flex-col max-h-[80vh] transition-colors">
        <div className="p-6 border-b border-slate-100 dark:border-slate-800 flex justify-between items-center bg-white dark:bg-slate-900">
          <h3 className="font-bold text-sm uppercase tracking-widest text-slate-900 dark:text-slate-100">Bulk Deployment</h3>
          <button onClick={onClose} className="p-2 text-slate-400 hover:text-slate-900 dark:hover:text-white transition-all"><X size={20} /></button>
        </div>
        <div className="p-8 flex-1 overflow-y-auto custom-scrollbar dark:bg-slate-900/50">
          <div className="bg-slate-50 dark:bg-slate-800 rounded-xl p-4 mb-6 text-xs text-slate-600 dark:text-slate-400 leading-relaxed border border-slate-100 dark:border-slate-700">
            Select grid nodes to deploy latest core updates. This will temporarily interrupt service on target machines.
          </div>
          <div className="border border-slate-100 dark:border-slate-800 rounded-xl overflow-hidden">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-50 dark:bg-slate-800 text-slate-400 dark:text-slate-500 font-bold uppercase tracking-widest border-b border-slate-100 dark:border-slate-800">
                <tr>
                  <th className="p-4 w-10"></th>
                  <th className="p-4">Node</th>
                  <th className="p-4">Version</th>
                  <th className="p-4 text-right">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-50 dark:divide-slate-800">
                {agents.map((agent: any) => (
                  <tr key={agent.hostname} className="hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors">
                    <td className="p-4">
                      <input type="checkbox" checked={selected.includes(agent.hostname)} onChange={() => toggleSelect(agent.hostname)} className="w-4 h-4 rounded border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-indigo-600 focus:ring-slate-900/5 dark:focus:ring-indigo-500/10 transition-all" />
                    </td>
                    <td className="p-4 font-semibold text-slate-900 dark:text-slate-100">{agent.hostname}</td>
                    <td className="p-4 text-slate-500 tabular-nums">v{agent.agent_version}</td>
                    <td className="p-4 text-right">
                      <span className={`text-[10px] font-bold uppercase tracking-wider ${isOnline(agent.last_seen) ? 'text-emerald-600 dark:text-emerald-400' : 'text-slate-300 dark:text-slate-700'}`}>
                        {isOnline(agent.last_seen) ? 'Online' : 'Lost'}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
        <div className="p-6 border-t border-slate-100 dark:border-slate-800 flex justify-between items-center bg-slate-50 dark:bg-slate-900">
          <span className="text-[11px] font-bold text-slate-400 dark:text-slate-500 uppercase tracking-widest">Selection: {selected.length}</span>
          <div className="flex gap-3">
            <button onClick={onClose} className="minimal-button-secondary">Cancel</button>
            <button onClick={handleUpdate} className="minimal-button-primary" disabled={selected.length === 0}>Deploy Update</button>
          </div>
        </div>
      </div>
    </div>
  );
}

function MinimalAgentDetailModal({ agent, onClose, isOnline, formatUptime, scripts }: any) {
  const [activeTab, setActiveTab] = useState<'overview' | 'software' | 'services' | 'patches' | 'events' | 'remote' | 'security' | 'console'>('overview');

  const tabs = [
    { id: 'overview', label: 'Core', icon: <Activity size={14}/> },
    { id: 'software', label: 'Apps', icon: <Box size={14}/> },
    { id: 'services', label: 'Services', icon: <Layers size={14}/> },
    { id: 'patches', label: 'Patches', icon: <ShieldCheck size={14}/> },
    { id: 'events', label: 'Logs', icon: <AlertTriangle size={14}/> },
    { id: 'console', label: 'Console', icon: <Terminal size={14}/> },
    { id: 'security', label: 'Security', icon: <Shield size={14}/> },
  ];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/10 dark:bg-black/60 backdrop-blur-sm transition-colors">
      <div className="bg-white dark:bg-slate-900 rounded-2xl shadow-2xl w-full max-w-5xl h-[90vh] flex flex-col border border-slate-200 dark:border-slate-800 overflow-hidden transition-colors">
        {/* Modal Header */}
        <div className="p-8 border-b border-slate-100 dark:border-slate-800 flex justify-between items-start bg-white dark:bg-slate-900 shrink-0 transition-colors">
          <div className="flex gap-6 items-center">
            <div className="w-14 h-14 bg-slate-50 dark:bg-slate-800 rounded-2xl flex items-center justify-center text-slate-900 dark:text-white border border-slate-100 dark:border-slate-700">
              <Monitor size={24} />
            </div>
            <div>
              <h2 className="text-xl font-bold text-slate-900 dark:text-white tracking-tight">{agent.hostname}</h2>
              <div className="flex gap-4 mt-1.5 text-[10px] font-bold text-slate-400 dark:text-slate-500 uppercase tracking-widest">
                <span className="flex items-center gap-1.5 text-slate-400 dark:text-slate-500"><Layers size={12}/> {agent.platform}</span>
                <span className="flex items-center gap-1.5 text-slate-400 dark:text-slate-500"><Globe size={12}/> {agent.ip_address}</span>
                <span className="flex items-center gap-1.5 text-slate-400 dark:text-slate-500"><Zap size={12}/> Node v{agent.agent_version}</span>
              </div>
            </div>
          </div>
          <button onClick={onClose} className="p-2 text-slate-300 dark:text-slate-600 hover:text-slate-900 dark:hover:text-white transition-colors"><X size={24} /></button>
        </div>

        {/* Modal Tabs */}
        <div className="flex px-8 bg-white dark:bg-slate-900 border-b border-slate-100 dark:border-slate-800 overflow-x-auto no-scrollbar shrink-0 transition-colors">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`flex items-center gap-2 px-4 py-4 text-[10px] font-bold uppercase tracking-widest border-b-2 transition-all whitespace-nowrap ${
                activeTab === tab.id 
                  ? 'border-slate-900 dark:border-indigo-500 text-slate-900 dark:text-white' 
                  : 'border-transparent text-slate-400 dark:text-slate-600 hover:text-slate-600 dark:hover:text-slate-400'
              }`}
            >
              {tab.icon}
              {tab.label}
            </button>
          ))}
        </div>
        
        {/* Modal Content */}
        <div className="flex-1 overflow-y-auto p-8 bg-slate-50/30 dark:bg-slate-900/50 custom-scrollbar">
          {activeTab === 'overview' && (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
              <div className="space-y-8">
                <MinimalDetailSection title="Architecture">
                  <MinimalDetailRow label="Processor" value={agent.cpu_model} />
                  <MinimalDetailRow label="Current Load" value={`${agent.cpu_usage.toFixed(1)}%`} />
                  <MinimalDetailRow label="Total RAM" value={`${(agent.total_ram / (1024**3)).toFixed(2)} GB`} />
                  <MinimalDetailRow label="Used RAM" value={`${(agent.used_ram / (1024**3)).toFixed(2)} GB (${agent.ram_usage.toFixed(1)}%)`} />
                  <MinimalDetailRow label="Disk Storage" value={`${(agent.total_disk / (1024**3)).toFixed(2)} GB (${agent.disk_usage.toFixed(1)}% used)`} />
                </MinimalDetailSection>
                <MinimalDetailSection title="Network">
                  <MinimalDetailRow label="Local IP" value={agent.ip_address} />
                  <MinimalDetailRow label="MAC Address" value={agent.mac_address} />
                </MinimalDetailSection>
              </div>
              <div className="space-y-8">
                <MinimalDetailSection title="Performance">
                  <MinimalDetailRow label="System Uptime" value={formatUptime(agent.uptime)} />
                  <MinimalDetailRow label="Last Seen" value={new Date(agent.last_seen).toLocaleString()} />
                  <MinimalDetailRow label="Arch Type" value={agent.arch} />
                  <MinimalDetailRow label="Status" value={isOnline ? 'Online' : 'Disconnected'} />
                </MinimalDetailSection>
                <div className="p-8 bg-white dark:bg-slate-800 rounded-2xl border border-slate-200 dark:border-slate-700 text-center shadow-sm transition-colors">
                  <p className="text-[10px] font-bold text-slate-400 dark:text-slate-500 uppercase tracking-[0.2em] mb-3">Endpoint Verification</p>
                  <div className="flex items-center justify-center gap-2 text-emerald-600 dark:text-emerald-400 font-bold text-xs uppercase tracking-widest">
                    <ShieldCheck size={16} strokeWidth={2.5} /> Active Core Node
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'software' && <SoftwareTab software={agent.software || []} hostname={agent.hostname} />}
          {activeTab === 'services' && <ServicesTab services={agent.services || []} hostname={agent.hostname} />}
          {activeTab === 'patches' && <PatchesTab patches={agent.patches || []} />}
          {activeTab === 'events' && <EventsTab events={agent.event_logs || []} />}
          {activeTab === 'console' && <ConsoleTab hostname={agent.hostname} scripts={scripts} />}
          {activeTab === 'security' && <SecurityTab agent={agent} />}
        </div>
      </div>
    </div>
  );
}

function SoftwareTab({ software, hostname }: { software: Software[], hostname: string }) {
  const [search, setSearch] = useState('');
  const filtered = software.filter(s => s.name.toLowerCase().includes(search.toLowerCase()));

  const handleUninstall = async (s: Software) => {
    if (!s.uninstall_string) return alert("Uninstall string not available.");
    if (!confirm(`Uninstall ${s.name}?`)) return;
    try {
      await axios.post('/api/command/queue', { hostname, command: s.uninstall_string });
      alert("Uninstall command queued.");
    } catch (e) { alert("Failed to queue."); }
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h3 className="text-[10px] font-bold text-slate-900 dark:text-slate-100 tracking-[0.2em] uppercase transition-colors">Installed Applications ({software.length})</h3>
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" size={14} />
          <input 
            type="text" 
            placeholder="Filter apps..." 
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="minimal-input pl-9 w-64"
          />
        </div>
      </div>
      <div className="minimal-card overflow-hidden">
        <table className="w-full text-left text-xs">
          <thead className="bg-slate-50 dark:bg-slate-800/50 border-b border-slate-100 dark:border-slate-700">
            <tr className="text-[10px] font-bold text-slate-400 dark:text-slate-500 uppercase tracking-widest">
              <th className="px-6 py-4">Application</th>
              <th className="px-6 py-4">Version</th>
              <th className="px-6 py-4">Vendor</th>
              <th className="px-6 py-4 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-50 dark:divide-slate-800">
            {filtered.map((s, i) => (
              <tr key={i} className="hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors group">
                <td className="px-6 py-4 font-semibold text-slate-900 dark:text-slate-100">{s.name}</td>
                <td className="px-6 py-4 text-slate-500 dark:text-slate-400 tabular-nums">{s.version}</td>
                <td className="px-6 py-4 text-slate-400 dark:text-slate-500 uppercase text-[10px] font-bold tracking-wider">{s.vendor}</td>
                <td className="px-6 py-4 text-right">
                  {s.uninstall_string && (
                    <button onClick={() => handleUninstall(s)} className="text-rose-500 hover:text-rose-700 p-1 transition-colors">
                      <Trash2 size={16} />
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function ServicesTab({ services, hostname }: { services: Service[], hostname: string }) {
  const [loadingSvc, setLoadingSvc] = useState<string | null>(null);

  const handleService = async (name: string, action: 'start' | 'stop' | 'restart') => {
    setLoadingSvc(name);
    try {
      const cmd = action === 'restart' ? `Restart-Service -Name "${name}" -Force` : 
                  action === 'start' ? `Start-Service -Name "${name}"` : `Stop-Service -Name "${name}" -Force`;
      await axios.post('/api/command/queue', { hostname, command: cmd });
      alert(`Command queued: ${action} ${name}`);
    } catch (e) { alert("Failed to queue."); } finally { setLoadingSvc(null); }
  };

  return (
    <div className="space-y-6">
      <h3 className="text-[10px] font-bold text-slate-900 dark:text-slate-100 tracking-[0.2em] uppercase transition-colors">System Services ({services.length})</h3>
      <div className="minimal-card overflow-hidden">
        <table className="w-full text-left text-xs">
          <thead className="bg-slate-50 dark:bg-slate-800/50 border-b border-slate-100 dark:border-slate-700">
            <tr className="text-[10px] font-bold text-slate-400 dark:text-slate-500 uppercase tracking-widest">
              <th className="px-6 py-4">Service Name</th>
              <th className="px-6 py-4">Status</th>
              <th className="px-6 py-4 text-right">Controls</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-50 dark:divide-slate-800">
            {services.map((svc, i) => (
              <tr key={i} className="hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors">
                <td className="px-6 py-4 font-semibold text-slate-900 dark:text-slate-100">{svc.name}</td>
                <td className="px-6 py-4">
                  <span className={`minimal-badge ${svc.status === 'Running' ? 'status-online' : 'status-offline'}`}>
                    {svc.status}
                  </span>
                </td>
                <td className="px-6 py-4 text-right flex justify-end gap-2">
                  <button disabled={loadingSvc === svc.name} onClick={() => handleService(svc.name, svc.status === 'Running' ? 'stop' : 'start')} className="p-1.5 text-slate-400 dark:text-slate-500 hover:text-slate-900 dark:hover:text-white bg-slate-50 dark:bg-slate-800 rounded-lg transition-all">
                    {svc.status === 'Running' ? <StopCircle size={16}/> : <Play size={16}/>}
                  </button>
                  <button disabled={loadingSvc === svc.name} onClick={() => handleService(svc.name, 'restart')} className="p-1.5 text-slate-400 dark:text-slate-500 hover:text-slate-900 dark:hover:text-white bg-slate-50 dark:bg-slate-800 rounded-lg transition-all">
                    <RefreshCw size={16} className={loadingSvc === svc.name ? 'animate-spin' : ''}/>
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function ConsoleTab({ hostname, scripts }: { hostname: string, scripts: Script[] }) {
  const [cmd, setCmd] = useState('');
  const [output, setOutput] = useState('');
  const [loading, setLoading] = useState(false);

  const runCommand = async (commandStr: string) => {
    setLoading(true);
    setOutput(prev => `> Running: ${commandStr}\n${prev}`);
    try {
      const res = await axios.post('/api/command/queue', { hostname, command: commandStr });
      const cmdId = res.data.command_id;
      
      // Poll for result
      const poll = setInterval(async () => {
        const check = await axios.get(`/api/commands/${hostname}`);
        const found = check.data.find((c: any) => c.id === cmdId);
        if (found && (found.status === 'completed' || found.status === 'failed')) {
          setOutput(prev => `[${found.status.toUpperCase()}] Result:\n${found.output}\n\n${prev}`);
          setLoading(false);
          clearInterval(poll);
        }
      }, 2000);
    } catch (e) {
      setOutput(prev => `ERROR: Failed to connect to server.\n${prev}`);
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h3 className="text-[10px] font-bold text-slate-900 dark:text-slate-100 tracking-[0.2em] uppercase transition-colors">PowerShell Console</h3>
        <div className="flex gap-2">
          {scripts.map(s => (
            <button key={s.id} onClick={() => runCommand(s.content)} className="minimal-button-secondary text-[10px] px-3 py-1.5">
              {s.name}
            </button>
          ))}
        </div>
      </div>
      <div className="space-y-4">
        <div className="flex gap-3">
          <input 
            type="text" 
            value={cmd}
            onChange={e => setCmd(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && runCommand(cmd)}
            placeholder="Type PowerShell command..."
            className="minimal-input flex-1 mono font-medium"
          />
          <button onClick={() => runCommand(cmd)} disabled={loading} className="minimal-button-primary flex items-center gap-2">
            {loading ? <RefreshCw size={14} className="animate-spin"/> : <Zap size={14}/>} Run
          </button>
        </div>
        <div className="bg-slate-900 dark:bg-black text-slate-100 dark:text-indigo-400 p-6 rounded-xl mono text-xs h-[400px] overflow-y-auto whitespace-pre-wrap shadow-inner border border-slate-800 dark:border-slate-700 transition-colors">
          {output || 'System terminal ready. Type a command to begin execution.'}
        </div>
      </div>
    </div>
  );
}

function SecurityTab({ agent }: { agent: AgentData }) {
  const handleControl = async (action: string) => {
    try {
      await axios.post('/api/security/control', { hostname: agent.hostname, action });
      alert(`Security protocol ${action} queued.`);
    } catch (e) { alert("Failed to deploy security policy."); }
  };

  return (
    <div className="space-y-10">
      <h3 className="text-[10px] font-bold text-slate-900 dark:text-slate-100 tracking-[0.2em] uppercase transition-colors">Security Protocols</h3>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
        <SecurityControl 
          title="Peripheral Control" 
          desc="Manage USB storage device access on this endpoint."
          status={agent.security?.usb_blocked ? 'Blocked' : 'Active'}
          onEnable={() => handleControl('block_usb')}
          onDisable={() => handleControl('allow_usb')}
        />
        <SecurityControl 
          title="Remote Access" 
          desc="Toggle RDP capabilities and clipboard redirection."
          status={agent.security?.rdp_blocked ? 'Blocked' : 'Active'}
          onEnable={() => handleControl('block_rdp')}
          onDisable={() => handleControl('allow_rdp')}
        />
      </div>
      <div className="minimal-card p-8 transition-colors">
         <h4 className="text-[10px] font-bold text-slate-400 dark:text-slate-500 uppercase tracking-widest mb-6">Device Inventory</h4>
         <div className="grid grid-cols-2 gap-8 text-xs">
            <div>
               <p className="font-bold text-slate-900 dark:text-slate-100 mb-2 transition-colors">Connected USB Drives</p>
               {agent.security?.usb_devices?.length ? agent.security.usb_devices.map((d, i) => <div key={i} className="text-slate-500 flex items-center gap-2 mb-1"><Box size={12}/> {d}</div>) : <p className="text-slate-300 dark:text-slate-700 italic">No devices found</p>}
            </div>
            <div>
               <p className="font-bold text-slate-900 dark:text-slate-100 mb-2 transition-colors">Active RDP Sessions</p>
               {agent.security?.rdp_sessions?.length ? agent.security.rdp_sessions.map((s, i) => <div key={i} className="text-slate-500 flex items-center gap-2 mb-1"><Activity size={12}/> {s}</div>) : <p className="text-slate-300 dark:text-slate-700 italic">No active sessions</p>}
            </div>
         </div>
      </div>
    </div>
  );
}

function SecurityControl({ title, desc, status, onEnable, onDisable }: any) {
  return (
    <div className="minimal-card p-6 flex flex-col justify-between transition-colors">
      <div>
        <div className="flex justify-between items-center mb-4">
          <h4 className="text-sm font-bold text-slate-900 dark:text-slate-100 transition-colors">{title}</h4>
          <span className={`minimal-badge ${status === 'Active' ? 'status-online' : 'status-offline'}`}>{status}</span>
        </div>
        <p className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed mb-6 transition-colors">{desc}</p>
      </div>
      <div className="flex gap-3">
        <button onClick={onEnable} className="minimal-button-primary flex-1 text-[10px] uppercase">Enforce Policy</button>
        <button onClick={onDisable} className="minimal-button-secondary flex-1 text-[10px] uppercase">Lift Policy</button>
      </div>
    </div>
  );
}

function PatchesTab({ patches }: { patches: Patch[] }) {
  return (
    <div className="space-y-6">
      <h3 className="text-[10px] font-bold text-slate-900 dark:text-slate-100 tracking-[0.2em] uppercase transition-colors">Security Patches ({patches.length})</h3>
      <div className="minimal-card overflow-hidden transition-colors">
        <table className="w-full text-left text-xs">
          <thead className="bg-slate-50 dark:bg-slate-800/50 border-b border-slate-100 dark:border-slate-700">
            <tr className="text-[10px] font-bold text-slate-400 dark:text-slate-500 uppercase tracking-widest">
              <th className="px-6 py-4">Hotfix ID</th>
              <th className="px-6 py-4">Description</th>
              <th className="px-6 py-4">Installed By</th>
              <th className="px-6 py-4 text-right">Date</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-50 dark:divide-slate-800">
            {patches.map((p, i) => (
              <tr key={i} className="hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors">
                <td className="px-6 py-4 font-bold text-blue-600 dark:text-indigo-400 transition-colors">{p.hotfix_id}</td>
                <td className="px-6 py-4 text-slate-600 dark:text-slate-400 max-w-xs truncate transition-colors">{p.description}</td>
                <td className="px-6 py-4 text-slate-400 dark:text-slate-500 uppercase text-[9px] font-black transition-colors">{p.installed_by}</td>
                <td className="px-6 py-4 text-right text-slate-500 dark:text-slate-400 tabular-nums transition-colors">
                   {new Date(p.installed_on).toLocaleDateString()}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function EventsTab({ events }: { events: EventLog[] }) {
  return (
    <div className="space-y-6">
      <h3 className="text-[10px] font-bold text-slate-900 dark:text-slate-100 tracking-[0.2em] uppercase transition-colors">Recent System Errors ({events.length})</h3>
      <div className="space-y-3">
        {events.map((e, i) => (
          <div key={i} className="minimal-card p-5 flex gap-4 items-start transition-colors">
             <div className="p-2 bg-rose-50 dark:bg-rose-500/10 text-rose-500 dark:text-rose-400 rounded-lg border border-rose-100 dark:border-rose-500/20 transition-colors">
                <AlertCircle size={18} />
             </div>
             <div className="flex-1">
                <div className="flex justify-between items-start mb-1">
                   <p className="text-xs font-bold text-slate-900 dark:text-slate-100 uppercase tracking-wide transition-colors">{e.source}</p>
                   <span className="text-[9px] font-bold text-slate-400 dark:text-slate-500 tabular-nums uppercase transition-colors">{new Date(e.time_generated).toLocaleString()}</span>
                </div>
                <p className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed font-medium transition-colors">{e.message}</p>
                <p className="text-[9px] font-bold text-slate-300 dark:text-slate-600 mt-2 uppercase tracking-widest transition-colors">Event ID: {e.event_id}</p>
             </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function MinimalDetailSection({ title, children }: any) {
  return (
    <div>
      <h3 className="text-[10px] font-bold text-slate-900 dark:text-slate-100 tracking-[0.2em] uppercase mb-6 transition-colors">{title}</h3>
      <div className="space-y-4">{children}</div>
    </div>
  );
}

function MinimalDetailRow({ label, value }: any) {
  return (
    <div className="flex justify-between items-baseline border-b border-slate-50 dark:border-slate-800 pb-3 transition-colors">
      <span className="text-[10px] font-bold text-slate-400 dark:text-slate-500 uppercase tracking-widest transition-colors">{label}</span>
      <span className="text-xs font-semibold text-slate-900 dark:text-slate-100 text-right max-w-[60%] truncate tabular-nums transition-colors">{value}</span>
    </div>
  );
}

export default App;
