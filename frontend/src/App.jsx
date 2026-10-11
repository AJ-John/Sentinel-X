import { useEffect, useState } from "react";
import axios from "axios";

import {
  Shield,
  Activity,
  Brain,
  Link,
  AlertTriangle,
  Server,
  RefreshCw,
  Play,
  Zap,
  X,
  CheckCircle,
  Eye,
  BarChart3,
  Search,
  Download,
  Filter,
  Clock,
  Copy,
  Users,
} from "lucide-react";

import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from "recharts";

const API = "http://127.0.0.1:8000";
const WS_BASE = "ws://127.0.0.1:8000/ws/security";

function DashboardApp({ token, user, onLogout }) {
  const [threats, setThreats] = useState([]);
  const [system, setSystem] = useState(null);
  const [loading, setLoading] = useState(true);

  const [selectedThreat, setSelectedThreat] = useState(null);

  const [simulating, setSimulating] = useState(false);
  const [simulationResult, setSimulationResult] = useState(null);

  // =====================================================
  // REAL-TIME SECURITY MONITORING
  // =====================================================

  const [liveEvents, setLiveEvents] = useState([]);
  const [wsConnected, setWsConnected] = useState(false);
  const [riskHistory, setRiskHistory] = useState([]);
  const [selectedLiveEvent, setSelectedLiveEvent] = useState(null);
  const [liveSearch, setLiveSearch] = useState("");
  const [liveRiskFilter, setLiveRiskFilter] = useState("ALL");
  const [historyEvents, setHistoryEvents] = useState([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyRiskFilter, setHistoryRiskFilter] = useState("ALL");
  const [dashboardStats, setDashboardStats] = useState(null);
  const [selectedHistoryEvent, setSelectedHistoryEvent] = useState(null);
  const [actionLoading, setActionLoading] = useState(false);
  const [operationMessage, setOperationMessage] = useState("");

  // =====================================================
  // RBAC / USER MANAGEMENT
  // =====================================================

  const [users, setUsers] = useState([]);
  const [showUserManagement, setShowUserManagement] = useState(false);
  const [newUsername, setNewUsername] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [newRole, setNewRole] = useState("analyst");
  const [userBusy, setUserBusy] = useState(false);
  const [userMessage, setUserMessage] = useState("");


  // =====================================================
  // AUTHENTICATED API CONFIG
  // =====================================================

  useEffect(() => {
    if (user?.role === "admin") {
      loadUsers();
    }
  }, [user?.role]);

  useEffect(() => {
    axios.defaults.headers.common.Authorization = `Bearer ${token}`;
    return () => {
      delete axios.defaults.headers.common.Authorization;
    };
  }, [token]);

  // =====================================================
  // LOAD DASHBOARD DATA
  // =====================================================


  const loadUsers = async () => {
    if (user?.role !== "admin") return;

    try {
      const response = await axios.get(`${API}/users`);
      setUsers(response.data.users || []);
    } catch (error) {
      setUserMessage(
        error?.response?.data?.detail || "Unable to load users."
      );
    }
  };

  const handleCreateUser = async (event) => {
    event.preventDefault();

    setUserBusy(true);
    setUserMessage("");

    try {
      await axios.post(`${API}/users`, {
        username: newUsername.trim(),
        password: newPassword,
        role: newRole,
      });

      setNewUsername("");
      setNewPassword("");
      setNewRole("analyst");
      setUserMessage("User created successfully.");
      await loadUsers();
    } catch (error) {
      setUserMessage(
        error?.response?.data?.detail || "Unable to create user."
      );
    } finally {
      setUserBusy(false);
    }
  };

  const handleDeleteUser = async (username) => {
    if (username === user?.username) {
      setUserMessage("You cannot delete your own account.");
      return;
    }

    if (!window.confirm(`Delete user "${username}"?`)) return;

    setUserBusy(true);
    setUserMessage("");

    try {
      await axios.delete(
        `${API}/users/${encodeURIComponent(username)}`
      );

      setUserMessage("User deleted successfully.");
      await loadUsers();
    } catch (error) {
      setUserMessage(
        error?.response?.data?.detail || "Unable to delete user."
      );
    } finally {
      setUserBusy(false);
    }
  };

  const loadData = async () => {
    try {
      setLoading(true);

      const [threatResponse, systemResponse, historyResponse, statsResponse] = await Promise.all([
        axios.get(`${API}/blockchain/threats`),
        axios.get(`${API}/system`),
        axios.get(`${API}/events?limit=100`),
        axios.get(`${API}/dashboard/stats`),
      ]);

      setThreats(threatResponse.data.threats || []);
      setSystem(systemResponse.data);
      setHistoryEvents(historyResponse.data.events || []);
      setDashboardStats(statsResponse.data || null);
    } catch (error) {
      console.error("SentinelX API error:", error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  // =====================================================
  // REAL-TIME WEBSOCKET CONNECTION
  // =====================================================

  useEffect(() => {
    let websocket;
    let reconnectTimer;
    let isUnmounted = false;

    const connectWebSocket = () => {
      if (isUnmounted) return;

      websocket = new WebSocket(`${WS_BASE}?token=${encodeURIComponent(token)}`);

      websocket.onopen = () => {
        console.log("SentinelX WebSocket connected");
        setWsConnected(true);
      };

      websocket.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);

          console.log("Real-time security event:", data);

          setLiveEvents((previous) => [
            data,
            ...previous,
          ].slice(0, 20));

          setRiskHistory((previous) => [
            {
              time: new Date().toLocaleTimeString(),
              risk: data.risk_analysis?.risk_score ?? 0,
              level: data.risk_analysis?.risk_level ?? "LOW",
            },
            ...previous,
          ].slice(0, 12));

          // Refresh blockchain registry and system information
          loadData();
        } catch (error) {
          console.error(
            "WebSocket message error:",
            error
          );
        }
      };

      websocket.onerror = (error) => {
        console.error(
          "SentinelX WebSocket error:",
          error
        );

        setWsConnected(false);
      };

      websocket.onclose = () => {
        console.log(
          "SentinelX WebSocket disconnected"
        );

        setWsConnected(false);

        if (!isUnmounted) {
          reconnectTimer = setTimeout(() => {
            console.log(
              "Attempting SentinelX WebSocket reconnect..."
            );

            connectWebSocket();
          }, 3000);
        }
      };
    };

    connectWebSocket();

    return () => {
      isUnmounted = true;

      if (reconnectTimer) {
        clearTimeout(reconnectTimer);
      }

      if (
        websocket &&
        websocket.readyState === WebSocket.OPEN
      ) {
        websocket.close();
      }
    };
  }, []);

  // =====================================================
  // MONGODB HISTORY / SOC ACTIONS
  // =====================================================

  const refreshHistory = async (riskOverride = historyRiskFilter) => {
    try {
      setHistoryLoading(true);
      const query = riskOverride !== "ALL" ? `&risk=${encodeURIComponent(riskOverride)}` : "";
      const [eventsResponse, statsResponse] = await Promise.all([
        axios.get(`${API}/events?limit=100${query}`),
        axios.get(`${API}/dashboard/stats`),
      ]);
      setHistoryEvents(eventsResponse.data.events || []);
      setDashboardStats(statsResponse.data || null);
    } catch (error) {
      console.error("History refresh error:", error);
    } finally {
      setHistoryLoading(false);
    }
  };

  const openHistoryEvent = async (eventId) => {
    try {
      setOperationMessage("");
      const response = await axios.get(`${API}/events/${eventId}`);
      setSelectedHistoryEvent(response.data);
    } catch (error) {
      console.error("Event details error:", error);
    }
  };

  const acknowledgeHistoryEvent = async (eventId) => {
    try {
      setActionLoading(true);
      await axios.post(`${API}/events/${eventId}/acknowledge`);
      setOperationMessage("Event acknowledged successfully.");
      await refreshHistory();
      await openHistoryEvent(eventId);
    } catch (error) {
      setOperationMessage(error.response?.data?.detail || "Unable to acknowledge event.");
    } finally {
      setActionLoading(false);
    }
  };

  const executeHistoryAction = async (eventId, action) => {
    try {
      setActionLoading(true);
      const response = await axios.post(`${API}/events/${eventId}/action`, { action });
      setOperationMessage(response.data.message || `Simulated action executed: ${action}`);
      await refreshHistory();
      await openHistoryEvent(eventId);
    } catch (error) {
      setOperationMessage(error.response?.data?.detail || "Unable to execute simulated action.");
    } finally {
      setActionLoading(false);
    }
  };

  // =====================================================
  // VIEW BLOCKCHAIN THREAT DETAILS
  // =====================================================

  const viewThreatDetails = async (threatId) => {
    try {
      const response = await axios.get(
        `${API}/blockchain/threat/${threatId}`
      );

      setSelectedThreat(response.data);
    } catch (error) {
      console.error(
        "Threat details error:",
        error
      );
    }
  };

  // =====================================================
  // SECURITY EVENT SIMULATOR
  // =====================================================

  const simulateEvent = async (event) => {
    try {
      setSimulating(true);
      setSimulationResult(null);

      const response = await axios.post(
        `${API}/events`,
        event
      );

      setSimulationResult(response.data);

      await new Promise((resolve) =>
        setTimeout(resolve, 500)
      );

      await loadData();
    } catch (error) {
      console.error(
        "Simulation error:",
        error
      );

      setSimulationResult({
        error:
          error.response?.data?.detail ||
          "Unable to connect to SentinelX backend.",
      });
    } finally {
      setSimulating(false);
    }
  };

  // =====================================================
  // LIVE EVENT ACTIONS
  // =====================================================

  const exportLiveEvents = () => {
    if (liveEvents.length === 0) return;

    const rows = [
      [
        "Time",
        "Source IP",
        "Event Type",
        "Attack",
        "Risk Level",
        "Risk Score",
        "ML Status",
        "Agent Status",
        "Response",
      ],
      ...liveEvents.map((item) => {
        const attacks =
          item.threat_analysis?.detections
            ?.map((detection) => detection.attack_type)
            .join(", ") || "NORMAL";

        return [
          new Date().toLocaleString(),
          item.event?.source_ip || "",
          item.event?.event_type || "",
          attacks,
          item.risk_analysis?.risk_level || "",
          item.risk_analysis?.risk_score ?? 0,
          item.ml_analysis?.ml_status || "",
          item.event?.agent_status || "",
          item.response?.response_action || "",
        ];
      }),
    ];

    const csv = rows
      .map((row) =>
        row
          .map((value) =>
            `"${String(value).replace(/"/g, '""')}"`
          )
          .join(",")
      )
      .join("\n");

    const blob = new Blob([csv], {
      type: "text/csv;charset=utf-8;",
    });

    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `sentinelx-live-events-${Date.now()}.csv`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const copyValue = async (value) => {
    try {
      await navigator.clipboard.writeText(String(value));
    } catch (error) {
      console.error("Clipboard error:", error);
    }
  };

  const filteredLiveEvents = liveEvents.filter((item) => {
    const risk =
      item.risk_analysis?.risk_level || "LOW";

    const source =
      item.event?.source_ip || "";

    const eventType =
      item.event?.event_type || "";

    const attack =
      item.threat_analysis?.detections
        ?.map((detection) => detection.attack_type)
        .join(" ") || "NORMAL";

    const search =
      liveSearch.trim().toLowerCase();

    const matchesSearch =
      !search ||
      source.toLowerCase().includes(search) ||
      eventType.toLowerCase().includes(search) ||
      attack.toLowerCase().includes(search);

    const matchesRisk =
      liveRiskFilter === "ALL" ||
      risk === liveRiskFilter;

    return matchesSearch && matchesRisk;
  });

  // =====================================================
  // CLEAR LIVE ACTIVITY
  // =====================================================

  const clearLiveActivity = () => {
    setLiveEvents([]);
    setRiskHistory([]);
    setSimulationResult(null);
  };

  // =====================================================
  // NORMAL EVENT
  // =====================================================

  const normalEvent = {
    source_ip: "192.168.1.50",
    event_type: "NORMAL_ACTIVITY",
    severity: "LOW",
    agent_status: "NORMAL",
    description: "Simulated normal network activity",
    packets_per_min: 50,
    connections_per_min: 25,
    unique_ports: 5,
    failed_connections: 2,
    login_failures: 1,
    new_device: false,
  };

  // =====================================================
  // BRUTE FORCE EVENT
  // =====================================================

  const bruteForceEvent = {
    source_ip: "192.168.1.101",
    event_type: "BRUTE_FORCE",
    severity: "HIGH",
    agent_status: "SUSPICIOUS",
    description: "Simulated repeated login attempts",
    packets_per_min: 100,
    connections_per_min: 80,
    unique_ports: 5,
    failed_connections: 25,
    login_failures: 25,
    new_device: false,
  };

  // =====================================================
  // PORT SCAN EVENT
  // =====================================================

  const portScanEvent = {
    source_ip: "192.168.1.102",
    event_type: "PORT_SCAN",
    severity: "HIGH",
    agent_status: "SUSPICIOUS",
    description: "Simulated port scanning behavior",
    packets_per_min: 300,
    connections_per_min: 200,
    unique_ports: 40,
    failed_connections: 10,
    login_failures: 2,
    new_device: false,
  };

  // =====================================================
  // TRAFFIC SPIKE EVENT
  // =====================================================

  const trafficSpikeEvent = {
    source_ip: "192.168.1.103",
    event_type: "TRAFFIC_SPIKE",
    severity: "HIGH",
    agent_status: "SUSPICIOUS",
    description: "Simulated abnormal network traffic",
    packets_per_min: 1200,
    connections_per_min: 600,
    unique_ports: 8,
    failed_connections: 5,
    login_failures: 2,
    new_device: false,
  };

  // =====================================================
  // CRITICAL MULTI-THREAT EVENT
  // =====================================================

  const criticalEvent = {
    source_ip: "192.168.1.104",
    event_type: "MULTI_THREAT",
    severity: "CRITICAL",
    agent_status: "HIGH_ACTIVITY",
    description: "Simulated combined cyber threat",
    packets_per_min: 900,
    connections_per_min: 550,
    unique_ports: 60,
    failed_connections: 220,
    login_failures: 90,
    new_device: true,
  };

  // =====================================================
  // DASHBOARD STATISTICS
  // =====================================================
  // Use the backend /dashboard/stats response for SOC-wide
  // statistics. The `threats` state contains blockchain
  // registry records only, so it must not be used for the
  // overall MongoDB/event analytics.

  const totalThreats =
    dashboardStats?.threats_detected ?? 0;

  const criticalThreats =
    dashboardStats?.critical_events ?? 0;

  const averageRisk = Number(
    dashboardStats?.average_risk ?? 0
  );

  // =====================================================
  // SOC ANALYTICS
  // =====================================================

  const attackDistribution =
    dashboardStats?.attack_distribution || {};

  const attackCounts = {
    BRUTE_FORCE:
      attackDistribution.BRUTE_FORCE ?? 0,
    PORT_SCAN:
      attackDistribution.PORT_SCAN ?? 0,
    TRAFFIC_SPIKE:
      attackDistribution.TRAFFIC_SPIKE ?? 0,
  };

  const attackChartData = [
    {
      name: "Brute Force",
      count: attackCounts.BRUTE_FORCE,
    },
    {
      name: "Port Scan",
      count: attackCounts.PORT_SCAN,
    },
    {
      name: "Traffic Spike",
      count: attackCounts.TRAFFIC_SPIKE,
    },
  ];

  const riskDistribution =
    dashboardStats?.risk_distribution || {};

  const riskCounts = {
    CRITICAL:
      riskDistribution.CRITICAL ?? 0,
    HIGH:
      riskDistribution.HIGH ?? 0,
    MEDIUM:
      riskDistribution.MEDIUM ?? 0,
    LOW:
      riskDistribution.LOW ?? 0,
  };

  const riskChartData = [
    {
      name: "Critical",
      value: riskCounts.CRITICAL,
    },
    {
      name: "High",
      value: riskCounts.HIGH,
    },
    {
      name: "Medium",
      value: riskCounts.MEDIUM,
    },
    {
      name: "Low",
      value: riskCounts.LOW,
    },
  ].filter(
    (item) => item.value > 0
  );

  // =====================================================
  // SOC COMMAND CENTER METRICS
  // =====================================================

  const liveThreats = liveEvents.filter(
    (item) => item.threat_analysis?.threat_detected
  ).length;

  const liveCritical = liveEvents.filter(
    (item) => item.risk_analysis?.risk_level === "CRITICAL"
  ).length;

  const liveAutomatedResponses = liveEvents.filter(
    (item) => item.response?.automatic_response === true
  ).length;

  const systemOnline =
    system &&
    system.security_engine &&
    system.ml_engine;

  // =====================================================
  // LOCAL AGENT STATUS
  // =====================================================

  const latestLiveEvent =
    liveEvents.length > 0
      ? liveEvents[0]
      : null;

  const latestAgentEvent =
    latestLiveEvent?.event || null;

  const latestMl =
    latestLiveEvent?.ml_analysis || null;

  const agentStatus =
    latestAgentEvent?.agent_status ||
    "WAITING";

  const agentStatusLabel = {
    BASELINE_LEARNING: "BASELINE LEARNING",
    NORMAL: "NORMAL",
    SUSPICIOUS: "SUSPICIOUS",
    HIGH_ACTIVITY: "HIGH ACTIVITY",
  }[agentStatus] || agentStatus;

  const agentStatusClass =
    agentStatus === "HIGH_ACTIVITY"
      ? "text-red-400"
      : agentStatus === "SUSPICIOUS"
        ? "text-yellow-400"
        : agentStatus === "NORMAL"
          ? "text-emerald-400"
          : "text-cyan-400";

  // =====================================================
  // UI
  // =====================================================

  return (
    <div className="min-h-screen bg-slate-950 text-white">

      {/* =================================================
          HEADER
      ================================================= */}

      <header className="border-b border-slate-800 bg-slate-900">

        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-5">

          <div className="flex items-center gap-3">

            <div className="rounded-xl bg-cyan-500/10 p-3">
              <Shield className="h-7 w-7 text-cyan-400" />
            </div>

            <div>

              <h1 className="text-2xl font-bold">
                SentinelX
              </h1>

              <p className="text-sm text-slate-400">
                AI-Powered Cyber Defense Network
              </p>

            </div>

          </div>

          <div className="flex items-center gap-3">

            <span
              className={`h-3 w-3 rounded-full ${
                wsConnected
                  ? "animate-pulse bg-emerald-400"
                  : "bg-red-500"
              }`}
            />

            <span className="text-sm text-slate-300">
              {wsConnected
                ? "LIVE MONITORING"
                : "MONITORING OFFLINE"}
            </span>

            <button
              onClick={loadData}
              className="ml-4 rounded-lg border border-slate-700 p-2 hover:bg-slate-800"
              title="Refresh dashboard"
            >
              <RefreshCw
                className={`h-4 w-4 ${
                  loading
                    ? "animate-spin"
                    : ""
                }`}
              />
            </button>

            <div className="ml-2 hidden items-center gap-2 rounded-lg border border-slate-700 px-3 py-2 md:flex">
              <div>
                <p className="text-xs font-semibold text-white">{user?.username}</p>
                <p className="text-[10px] uppercase text-slate-500">{user?.role}</p>
              </div>
            </div>

            {user?.role === "admin" && (
              <button
                onClick={() => {
                  setShowUserManagement(true);
                  loadUsers();
                }}
                className="ml-2 flex items-center gap-2 rounded-lg border border-cyan-900/60 px-3 py-2 text-xs text-cyan-300 hover:bg-cyan-950/40"
                title="User management"
              >
                <Users className="h-4 w-4" />
                Users
              </button>
            )}

            <button
              onClick={onLogout}
              className="rounded-lg border border-red-900/60 px-3 py-2 text-xs text-red-300 hover:bg-red-950/40"
            >
              Logout
            </button>

          </div>

        </div>

      </header>

      {/* =================================================
          MAIN
      ================================================= */}

      <main className="mx-auto max-w-7xl space-y-6 px-6 py-8">

        {/* =================================================
            STAT CARDS
        ================================================= */}

        <section className="grid gap-4 md:grid-cols-4">

          <StatCard
            icon={<AlertTriangle />}
            title="Total Threats"
            value={totalThreats}
          />

          <StatCard
            icon={<Shield />}
            title="Critical Threats"
            value={criticalThreats}
          />

          <StatCard
            icon={<Brain />}
            title="Average Risk"
            value={`${averageRisk}/100`}
          />

          <StatCard
            icon={<Link />}
            title="Blockchain"
            value="Connected"
          />

        </section>

        {/* =================================================
            SOC COMMAND CENTER
        ================================================= */}

        <section className="rounded-2xl border border-slate-800 bg-slate-900 p-6">

          <div className="mb-5 flex flex-wrap items-center justify-between gap-4">

            <div>
              <h2 className="text-lg font-semibold">
                SOC Command Center
              </h2>
              <p className="text-sm text-slate-400">
                Live operational status of the SentinelX defense network
              </p>
            </div>

            <div className="flex items-center gap-2 rounded-full border border-slate-700 bg-slate-950 px-3 py-1.5">
              <span className={`h-2.5 w-2.5 rounded-full ${
                wsConnected
                  ? "animate-pulse bg-emerald-400"
                  : "bg-red-500"
              }`} />
              <span className={`text-xs font-semibold ${
                wsConnected
                  ? "text-emerald-400"
                  : "text-red-400"
              }`}>
                {wsConnected ? "SOC ONLINE" : "SOC OFFLINE"}
              </span>
            </div>

          </div>

          <div className="grid gap-4 md:grid-cols-4">

            <CommandMetric
              icon={<Activity />}
              label="Events Processed"
              value={liveEvents.length}
              detail="Current live feed"
            />

            <CommandMetric
              icon={<AlertTriangle />}
              label="Threats Detected"
              value={liveThreats}
              detail="Current live feed"
            />

            <CommandMetric
              icon={<Shield />}
              label="Critical Events"
              value={liveCritical}
              detail="CRITICAL risk"
            />

            <CommandMetric
              icon={<Zap />}
              label="Automated Responses"
              value={liveAutomatedResponses}
              detail="Engine actions"
            />

          </div>

          <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">

            <HealthItem
              label="FastAPI Backend"
              online={Boolean(systemOnline)}
              detail={systemOnline ? "API responding" : "Checking"}
            />

            <HealthItem
              label="MongoDB"
              online={Boolean(system?.database)}
              detail={system?.database || "Checking"}
            />

            <HealthItem
              label="ML Engine"
              online={Boolean(system?.ml_engine)}
              detail={system?.ml_engine || "Checking"}
            />

            <HealthItem
              label="WebSocket"
              online={wsConnected}
              detail={wsConnected ? "Live stream active" : "Disconnected"}
            />

          </div>

        </section>

        {/* =================================================
            ENGINE STATUS
        ================================================= */}

        <section className="grid gap-4 md:grid-cols-3">

          <StatusCard
            icon={<Activity />}
            title="Security Engine"
            status={
              system?.security_engine ||
              "Loading"
            }
          />

          <StatusCard
            icon={<Brain />}
            title="ML Engine"
            status={
              system?.ml_engine ||
              "Loading"
            }
          />

          <StatusCard
            icon={<Link />}
            title="Blockchain"
            status="Connected"
          />

        </section>

        {/* =================================================
            LOCAL SECURITY AGENT
        ================================================= */}

        <section className="rounded-2xl border border-slate-800 bg-slate-900 p-6">

          <div className="mb-5 flex items-center gap-3">

            <div className="rounded-xl bg-cyan-500/10 p-3">
              <Server className="h-6 w-6 text-cyan-400" />
            </div>

            <div>

              <h2 className="text-lg font-semibold">
                Local Security Agent
              </h2>

              <p className="text-sm text-slate-400">
                Endpoint baseline and latest security activity
              </p>

            </div>

          </div>

          <div className="grid gap-4 md:grid-cols-5">

            <div className="rounded-xl border border-slate-700 bg-slate-950 p-4">

              <p className="text-xs text-slate-500">
                Agent Status
              </p>

              <p className={`mt-2 font-semibold ${agentStatusClass}`}>
                ● {agentStatusLabel}
              </p>

            </div>

            <div className="rounded-xl border border-slate-700 bg-slate-950 p-4">

              <p className="text-xs text-slate-500">
                ML Status
              </p>

              <p className="mt-2 font-semibold text-cyan-400">
                {latestMl?.ml_status || "WAITING"}
              </p>

            </div>

            <div className="rounded-xl border border-slate-700 bg-slate-950 p-4">

              <p className="text-xs text-slate-500">
                Connections / min
              </p>

              <p className="mt-2 font-semibold">
                {latestAgentEvent?.connections_per_min ?? "—"}
              </p>

            </div>

            <div className="rounded-xl border border-slate-700 bg-slate-950 p-4">

              <p className="text-xs text-slate-500">
                Unique Ports
              </p>

              <p className="mt-2 font-semibold">
                {latestAgentEvent?.unique_ports ?? "—"}
              </p>

            </div>

            <div className="rounded-xl border border-slate-700 bg-slate-950 p-4">

              <p className="text-xs text-slate-500">
                Last Event
              </p>

              <p className="mt-2 truncate font-semibold text-cyan-300">
                {latestAgentEvent?.event_type || "WAITING"}
              </p>

            </div>

          </div>

        </section>

        {/* =================================================
            REAL-TIME SECURITY ACTIVITY
        ================================================= */}

        <section className="rounded-2xl border border-slate-800 bg-slate-900 p-6">

          <div className="mb-6 flex items-center justify-between">

            <div className="flex items-center gap-3">

              <div className="rounded-xl bg-cyan-500/10 p-3">
                <Activity className="h-6 w-6 text-cyan-400" />
              </div>

              <div>

                <h2 className="text-lg font-semibold">
                  Real-Time Security Activity
                </h2>

                <p className="text-sm text-slate-400">
                  Live security events received from SentinelX
                </p>

              </div>

            </div>

            <div className="flex flex-wrap items-center justify-end gap-2">

              <button
                onClick={exportLiveEvents}
                disabled={liveEvents.length === 0}
                className="flex items-center gap-2 rounded-lg border border-slate-700 px-3 py-2 text-xs text-slate-300 transition hover:border-cyan-700 hover:bg-slate-800 hover:text-white disabled:cursor-not-allowed disabled:opacity-40"
                title="Export live events as CSV"
              >
                <Download className="h-3.5 w-3.5" />
                Export CSV
              </button>

              <button
                onClick={clearLiveActivity}
                className="rounded-lg border border-slate-700 px-3 py-2 text-xs text-slate-300 transition hover:border-cyan-700 hover:bg-slate-800 hover:text-white"
                title="Clear the current live activity feed"
              >
                Clear
              </button>

              <div className="flex items-center gap-2">

                <span
                  className={`h-2.5 w-2.5 rounded-full ${
                  wsConnected
                    ? "animate-pulse bg-emerald-400"
                    : "bg-red-500"
                }`}
              />

              <span
                className={`text-xs font-semibold ${
                  wsConnected
                    ? "text-emerald-400"
                    : "text-red-400"
                }`}
              >
                {wsConnected
                  ? "CONNECTED"
                  : "DISCONNECTED"}
              </span>

              </div>

            </div>

          </div>

          <div className="mb-4 grid gap-3 md:grid-cols-[1fr_auto]">

            <div className="relative">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
              <input
                value={liveSearch}
                onChange={(event) => setLiveSearch(event.target.value)}
                placeholder="Search IP, event type, or attack..."
                className="w-full rounded-lg border border-slate-700 bg-slate-950 py-2.5 pl-9 pr-3 text-sm text-white outline-none transition focus:border-cyan-700"
              />
            </div>

            <div className="flex items-center gap-2">
              <Filter className="h-4 w-4 text-slate-500" />
              <select
                value={liveRiskFilter}
                onChange={(event) => setLiveRiskFilter(event.target.value)}
                className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2.5 text-sm text-slate-300 outline-none"
              >
                <option value="ALL">All Risk Levels</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>
            </div>

          </div>

          {liveEvents.length === 0 ? (

            <div className="rounded-xl border border-dashed border-slate-700 p-8 text-center">

              <Activity className="mx-auto h-8 w-8 text-slate-600" />

              <p className="mt-3 text-slate-400">
                Waiting for security events...
              </p>

              <p className="mt-1 text-xs text-slate-500">
                New events will appear here automatically.
              </p>

            </div>

          ) : (

            <div className="max-h-[500px] space-y-3 overflow-y-auto pr-2">

              {filteredLiveEvents.map(
                (item, index) => {

                  const risk =
                    item.risk_analysis
                      ?.risk_level ||
                    "LOW";

                  const score =
                    item.risk_analysis
                      ?.risk_score ?? 0;

                  const source =
                    item.event
                      ?.source_ip ||
                    "Unknown";

                  const attacks =
                    item.threat_analysis
                      ?.detections
                      ?.map(
                        (detection) =>
                          detection.attack_type
                      )
                      .join(", ") ||
                    "NORMAL";

                  const responseAction =
                    item.response
                      ?.response_action ||
                    "NONE";

                  return (
                    <div
                      key={`${
                        item.event_id ||
                        "event"
                      }-${index}`}
                      onClick={() => setSelectedLiveEvent(item)}
                      className="cursor-pointer rounded-xl border border-slate-800 bg-slate-950/60 p-4 transition hover:border-cyan-700 hover:bg-cyan-950/10"
                      title="Click to investigate this security event"
                    >

                      <div className="flex flex-wrap items-center justify-between gap-4">

                        <div className="min-w-0">

                          <div className="flex flex-wrap items-center gap-2">

                            <span
                              className={`h-2 w-2 rounded-full ${
                                risk === "CRITICAL"
                                  ? "bg-red-500"
                                  : risk === "HIGH"
                                  ? "bg-orange-500"
                                  : risk === "MEDIUM"
                                  ? "bg-yellow-400"
                                  : "bg-emerald-400"
                              }`}
                            />

                            <p className="text-sm font-semibold text-white">
                              {attacks}
                            </p>

                          </div>

                          <p className="mt-1 text-xs text-slate-400">

                            Source:{" "}

                            <span className="font-mono text-cyan-300">
                              {source}
                            </span>

                          </p>

                        </div>

                        <div className="flex flex-wrap items-center gap-3">

                          <span
                            className={`rounded-full px-3 py-1 text-xs font-semibold ${
                              risk === "CRITICAL"
                                ? "bg-red-500/20 text-red-400"
                                : risk === "HIGH"
                                ? "bg-orange-500/20 text-orange-400"
                                : risk === "MEDIUM"
                                ? "bg-yellow-500/20 text-yellow-400"
                                : "bg-emerald-500/20 text-emerald-400"
                            }`}
                          >
                            {risk}
                          </span>

                          <span className="text-sm text-slate-300">
                            Risk {score}/100
                          </span>

                          <span className="rounded-full border border-slate-700 px-3 py-1 text-xs text-slate-400">
                            {responseAction}
                          </span>

                        </div>

                      </div>

                    </div>
                  );
                }
              )}

              {filteredLiveEvents.length === 0 && liveEvents.length > 0 && (
                <div className="rounded-xl border border-dashed border-slate-700 p-6 text-center text-sm text-slate-500">
                  No live events match the current search/filter.
                </div>
              )}

            </div>

          )}

        </section>

        {/* =================================================
            LIVE EVENT INVESTIGATION
        ================================================= */}

        {selectedLiveEvent && (
          <section className="overflow-hidden rounded-2xl border border-cyan-500/30 bg-slate-900">

            <div className="flex items-center justify-between border-b border-slate-800 p-6">

              <div className="flex items-center gap-3">
                <div className="rounded-xl bg-cyan-500/10 p-3">
                  <Eye className="h-6 w-6 text-cyan-400" />
                </div>
                <div>
                  <h2 className="text-lg font-semibold">
                    Live Event Investigation
                  </h2>
                  <p className="text-sm text-slate-400">
                    Detailed analysis from the SentinelX detection pipeline
                  </p>
                </div>
              </div>

              <button
                onClick={() => setSelectedLiveEvent(null)}
                className="rounded-lg border border-slate-700 p-2 text-slate-400 transition hover:bg-slate-800 hover:text-white"
                title="Close investigation"
              >
                <X className="h-5 w-5" />
              </button>

            </div>

            <div className="grid gap-4 p-6 md:grid-cols-2 lg:grid-cols-3">

              <InvestigationItem
                label="Source IP"
                value={selectedLiveEvent.event?.source_ip || "Unknown"}
                copyable
                onCopy={copyValue}
              />

              <InvestigationItem
                label="Event Type"
                value={selectedLiveEvent.event?.event_type || "Unknown"}
              />

              <InvestigationItem
                label="Agent Status"
                value={selectedLiveEvent.event?.agent_status || "Unknown"}
              />

              <InvestigationItem
                label="ML Status"
                value={selectedLiveEvent.ml_analysis?.ml_status || "Unknown"}
              />

              <InvestigationItem
                label="Risk Level"
                value={selectedLiveEvent.risk_analysis?.risk_level || "LOW"}
              />

              <InvestigationItem
                label="Risk Score"
                value={`${selectedLiveEvent.risk_analysis?.risk_score ?? 0}/100`}
              />

              <div className="md:col-span-2 lg:col-span-3">
                <InvestigationItem
                  label="ML Reason"
                  value={selectedLiveEvent.ml_analysis?.ml_reason || "No ML explanation available."}
                />
              </div>

              <div className="md:col-span-2 lg:col-span-3">
                <InvestigationItem
                  label="Risk Factors"
                  value={
                    selectedLiveEvent.risk_analysis?.risk_factors?.length
                      ? selectedLiveEvent.risk_analysis.risk_factors.join(" • ")
                      : "No additional risk factors."
                  }
                />
              </div>

              <div className="md:col-span-2">
                <InvestigationItem
                  label="Detected Attacks"
                  value={
                    selectedLiveEvent.threat_analysis?.detections?.length
                      ? selectedLiveEvent.threat_analysis.detections
                          .map((detection) => `${detection.attack_type} (${detection.severity})`)
                          .join(" • ")
                      : "NORMAL / No rule-based threat detected"
                  }
                />
              </div>

              <InvestigationItem
                label="Response"
                value={selectedLiveEvent.response?.response_action || "NONE"}
              />

              <div className="md:col-span-2 lg:col-span-3 rounded-xl border border-slate-800 bg-slate-950 p-4">

                <div className="mb-3 flex items-center justify-between">
                  <div>
                    <p className="text-xs uppercase tracking-wide text-slate-500">
                      Response Explanation
                    </p>
                    <p className="mt-1 text-sm text-slate-300">
                      {selectedLiveEvent.response?.response_description || "No response description available."}
                    </p>
                  </div>

                  <span className={`rounded-full px-3 py-1 text-xs font-semibold ${
                    selectedLiveEvent.response?.automatic_response
                      ? "bg-cyan-500/10 text-cyan-400"
                      : "bg-slate-800 text-slate-400"
                  }`}>
                    {selectedLiveEvent.response?.automatic_response
                      ? "AUTOMATIC"
                      : "MANUAL / MONITOR"}
                  </span>
                </div>

                <div className="flex items-center gap-2 text-xs text-slate-500">
                  <Clock className="h-3.5 w-3.5" />
                  Investigation opened from live WebSocket event
                </div>

              </div>

              {selectedLiveEvent.blockchain && (
                <div className="md:col-span-2 lg:col-span-3 rounded-xl border border-emerald-500/20 bg-emerald-500/5 p-4">

                  <div className="flex items-center gap-3">
                    <CheckCircle className="h-5 w-5 text-emerald-400" />
                    <div>
                      <p className="font-semibold text-emerald-400">
                        Blockchain Record
                      </p>
                      <p className="text-xs text-slate-400">
                        {selectedLiveEvent.blockchain.blockchain_status || "Recorded"}
                      </p>
                    </div>
                  </div>

                  {selectedLiveEvent.blockchain.transaction_hash && (
                    <div className="mt-3 flex items-start gap-2 rounded-lg border border-slate-800 bg-slate-950 p-3">
                      <p className="min-w-0 flex-1 break-all font-mono text-xs text-slate-400">
                        {selectedLiveEvent.blockchain.transaction_hash}
                      </p>
                      <button
                        onClick={() => copyValue(selectedLiveEvent.blockchain.transaction_hash)}
                        className="rounded-lg border border-slate-700 p-2 text-slate-400 hover:bg-slate-800 hover:text-white"
                        title="Copy transaction hash"
                      >
                        <Copy className="h-4 w-4" />
                      </button>
                    </div>
                  )}

                </div>
              )}

            </div>

          </section>
        )}

        {/* =================================================
            SECURITY EVENT SIMULATOR
        ================================================= */}

        <section className="rounded-2xl border border-cyan-900/50 bg-slate-900 p-6">

          <div className="mb-6 flex items-center gap-3">

            <div className="rounded-xl bg-cyan-500/10 p-3">
              <Zap className="h-6 w-6 text-cyan-400" />
            </div>

            <div>

              <h2 className="text-lg font-semibold">
                Security Event Simulator
              </h2>

              <p className="text-sm text-slate-400">
                Generate controlled local events to test the SentinelX detection pipeline
              </p>

            </div>

          </div>

          {/* SIMULATOR BUTTONS */}

          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">

            <SimulatorButton
              label="Normal Activity"
              description="Safe"
              onClick={() =>
                simulateEvent(normalEvent)
              }
              disabled={simulating}
            />

            <SimulatorButton
              label="Brute Force"
              description="Login attack"
              onClick={() =>
                simulateEvent(bruteForceEvent)
              }
              disabled={simulating}
            />

            <SimulatorButton
              label="Port Scan"
              description="Scanning"
              onClick={() =>
                simulateEvent(portScanEvent)
              }
              disabled={simulating}
            />

            <SimulatorButton
              label="Traffic Spike"
              description="Abnormal traffic"
              onClick={() =>
                simulateEvent(trafficSpikeEvent)
              }
              disabled={simulating}
            />

            <SimulatorButton
              label="Critical Multi-Threat"
              description="Combined threat"
              onClick={() =>
                simulateEvent(criticalEvent)
              }
              disabled={simulating}
              critical
            />

          </div>

          {/* ANALYZING */}

          {simulating && (
            <div className="mt-5 flex items-center gap-3 rounded-xl border border-cyan-900 bg-cyan-950/30 p-4 text-sm text-cyan-300">

              <RefreshCw className="h-4 w-4 animate-spin" />

              SentinelX is analyzing the simulated event...

            </div>
          )}

          {/* SIMULATION RESULT */}

          {simulationResult &&
            !simulationResult.error && (

              <div className="mt-5 rounded-xl border border-slate-700 bg-slate-950 p-5">

                <div className="mb-4 flex items-center gap-2">

                  <Play className="h-4 w-4 text-emerald-400" />

                  <h3 className="font-semibold">
                    Simulation Result
                  </h3>

                </div>

                <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">

                  <ResultItem
                    label="ML Detection"
                    value={
                      simulationResult
                        .ml_analysis
                        ?.ml_status ||
                      "UNKNOWN"
                    }
                  />

                  <ResultItem
                    label="Risk"
                    value={`${
                      simulationResult
                        .risk_analysis
                        ?.risk_score || 0
                    }/100`}
                  />

                  <ResultItem
                    label="Risk Level"
                    value={
                      simulationResult
                        .risk_analysis
                        ?.risk_level ||
                      "UNKNOWN"
                    }
                  />

                  <ResultItem
                    label="Response"
                    value={
                      simulationResult
                        .response
                        ?.response_action ||
                      "NONE"
                    }
                  />

                </div>

                {/* BLOCKCHAIN RESULT */}

                {simulationResult.blockchain && (

                  <div className="mt-4 rounded-lg border border-emerald-900 bg-emerald-950/20 p-4">

                    <p className="text-sm font-semibold text-emerald-400">
                      Blockchain Status
                    </p>

                    <p className="mt-1 text-sm text-slate-300">
                      {
                        simulationResult
                          .blockchain
                          .blockchain_status
                      }
                    </p>

                    {simulationResult.blockchain.transaction_hash && (

                      <p className="mt-2 break-all font-mono text-xs text-slate-500">

                        TX:{" "}

                        {
                          simulationResult
                            .blockchain
                            .transaction_hash
                        }

                      </p>

                    )}

                  </div>

                )}

              </div>

            )}

          {/* ERROR */}

          {simulationResult?.error && (

            <div className="mt-5 rounded-xl border border-red-900 bg-red-950/20 p-4 text-sm text-red-400">
              {simulationResult.error}
            </div>

          )}

        </section>

        {/* =================================================
            SOC ANALYTICS
        ================================================= */}

        <section className="space-y-4">

          <div className="flex items-center gap-3">

            <div className="rounded-xl bg-cyan-500/10 p-3">
              <BarChart3 className="h-6 w-6 text-cyan-400" />
            </div>

            <div>

              <h2 className="text-lg font-semibold">
                SOC Analytics
              </h2>

              <p className="text-sm text-slate-400">
                Security threat intelligence and risk overview
              </p>

            </div>

          </div>

          {/* ATTACK COUNTERS */}

          <div className="grid gap-4 md:grid-cols-3">

            <AnalyticsCard
              title="Brute Force"
              value={
                attackCounts.BRUTE_FORCE
              }
              description="Detected attacks"
            />

            <AnalyticsCard
              title="Port Scans"
              value={
                attackCounts.PORT_SCAN
              }
              description="Scanning events"
            />

            <AnalyticsCard
              title="Traffic Spikes"
              value={
                attackCounts.TRAFFIC_SPIKE
              }
              description="Abnormal traffic events"
            />

          </div>

          {/* CHARTS */}

          <div className="grid gap-6 lg:grid-cols-2">

            {/* ATTACK DISTRIBUTION */}

            <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6">

              <h3 className="mb-1 text-lg font-semibold">
                Attack Distribution
              </h3>

              <p className="mb-5 text-sm text-slate-400">
                Detected attack categories
              </p>

              <div className="h-72">

                <ResponsiveContainer
                  width="100%"
                  height="100%"
                >

                  <BarChart
                    data={attackChartData}
                  >

                    <CartesianGrid
                      strokeDasharray="3 3"
                      stroke="#1e293b"
                    />

                    <XAxis
                      dataKey="name"
                      stroke="#94a3b8"
                      tick={{
                        fontSize: 12,
                      }}
                    />

                    <YAxis
                      allowDecimals={false}
                      stroke="#94a3b8"
                    />

                    <Tooltip
                      contentStyle={{
                        backgroundColor:
                          "#020617",
                        border:
                          "1px solid #334155",
                        borderRadius:
                          "8px",
                        color: "#fff",
                      }}
                    />

                    <Bar
                      dataKey="count"
                      fill="#22d3ee"
                      radius={[
                        6,
                        6,
                        0,
                        0,
                      ]}
                    />

                  </BarChart>

                </ResponsiveContainer>

              </div>

            </div>

            {/* RISK DISTRIBUTION */}

            <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6">

              <h3 className="mb-1 text-lg font-semibold">
                Risk Distribution
              </h3>

              <p className="mb-5 text-sm text-slate-400">
                Threat severity across the registry
              </p>

              <div className="h-72">

                {riskChartData.length === 0 ? (

                  <div className="flex h-full items-center justify-center text-slate-500">
                    No threat data available
                  </div>

                ) : (

                  <ResponsiveContainer
                    width="100%"
                    height="100%"
                  >

                    <PieChart>

                      <Pie
                        data={riskChartData}
                        dataKey="value"
                        nameKey="name"
                        cx="50%"
                        cy="50%"
                        outerRadius={95}
                        label
                      >

                        {riskChartData.map(
                          (entry, index) => (

                            <Cell
                              key={`cell-${index}`}
                              fill={
                                entry.name ===
                                "Critical"
                                  ? "#ef4444"
                                  : entry.name ===
                                    "High"
                                  ? "#f97316"
                                  : entry.name ===
                                    "Medium"
                                  ? "#eab308"
                                  : "#22c55e"
                              }
                            />

                          )
                        )}

                      </Pie>

                      <Tooltip />

                    </PieChart>

                  </ResponsiveContainer>

                )}

              </div>

            </div>

          </div>

        </section>

        {/* =================================================
            SECURITY ANALYTICS
        ================================================= */}

        <section className="rounded-2xl border border-slate-800 bg-slate-900 p-6">

          <div className="mb-6">

            <h2 className="text-lg font-semibold">
              Security Analytics
            </h2>

            <p className="text-sm text-slate-400">
              Live analysis of recent SentinelX security events
            </p>

          </div>

          <div className="grid gap-6 lg:grid-cols-2">

            {/* ATTACK DISTRIBUTION */}

            <div className="rounded-xl border border-slate-800 bg-slate-950 p-5">

              <h3 className="mb-1 font-semibold">
                Attack Distribution
              </h3>

              <p className="mb-4 text-xs text-slate-500">
                Detected attack types in the live event feed
              </p>

              <div className="h-64">

                {attackChartData.every(
                  (item) => item.count === 0
                ) ? (

                  <div className="flex h-full items-center justify-center text-sm text-slate-500">
                    Waiting for detected threats
                  </div>

                ) : (

                  <ResponsiveContainer
                    width="100%"
                    height="100%"
                  >

                    <BarChart data={attackChartData}>

                      <CartesianGrid
                        strokeDasharray="3 3"
                        stroke="#1e293b"
                      />

                      <XAxis
                        dataKey="name"
                        tick={{ fill: "#94a3b8", fontSize: 12 }}
                      />

                      <YAxis
                        allowDecimals={false}
                        tick={{ fill: "#94a3b8" }}
                      />

                      <Tooltip />

                      <Bar
                        dataKey="count"
                        fill="#22d3ee"
                        radius={[6, 6, 0, 0]}
                      />

                    </BarChart>

                  </ResponsiveContainer>

                )}

              </div>

            </div>

            {/* RISK TIMELINE */}

            <div className="rounded-xl border border-slate-800 bg-slate-950 p-5">

              <h3 className="mb-1 font-semibold">
                Risk Timeline
              </h3>

              <p className="mb-4 text-xs text-slate-500">
                Risk score from the latest live events
              </p>

              <div className="h-64">

                {riskHistory.length === 0 ? (

                  <div className="flex h-full items-center justify-center text-sm text-slate-500">
                    Waiting for live security events
                  </div>

                ) : (

                  <ResponsiveContainer
                    width="100%"
                    height="100%"
                  >

                    <BarChart
                      data={[...riskHistory].reverse()}
                    >

                      <CartesianGrid
                        strokeDasharray="3 3"
                        stroke="#1e293b"
                      />

                      <XAxis
                        dataKey="time"
                        tick={{ fill: "#94a3b8", fontSize: 10 }}
                      />

                      <YAxis
                        domain={[0, 100]}
                        tick={{ fill: "#94a3b8" }}
                      />

                      <Tooltip />

                      <Bar
                        dataKey="risk"
                        fill="#f97316"
                        radius={[6, 6, 0, 0]}
                      />

                    </BarChart>

                  </ResponsiveContainer>

                )}

              </div>

            </div>

            {/* RISK LEVEL SUMMARY */}

            <div className="rounded-xl border border-slate-800 bg-slate-950 p-5 lg:col-span-2">

              <h3 className="mb-4 font-semibold">
                Risk Level Summary
              </h3>

              <div className="grid gap-3 md:grid-cols-4">

                <div className="rounded-xl border border-red-900/40 bg-red-950/20 p-4">
                  <p className="text-xs text-slate-500">
                    Critical
                  </p>
                  <p className="mt-2 text-2xl font-bold text-red-400">
                    {riskCounts.CRITICAL}
                  </p>
                </div>

                <div className="rounded-xl border border-orange-900/40 bg-orange-950/20 p-4">
                  <p className="text-xs text-slate-500">
                    High
                  </p>
                  <p className="mt-2 text-2xl font-bold text-orange-400">
                    {riskCounts.HIGH}
                  </p>
                </div>

                <div className="rounded-xl border border-yellow-900/40 bg-yellow-950/20 p-4">
                  <p className="text-xs text-slate-500">
                    Medium
                  </p>
                  <p className="mt-2 text-2xl font-bold text-yellow-400">
                    {riskCounts.MEDIUM}
                  </p>
                </div>

                <div className="rounded-xl border border-emerald-900/40 bg-emerald-950/20 p-4">
                  <p className="text-xs text-slate-500">
                    Low
                  </p>
                  <p className="mt-2 text-2xl font-bold text-emerald-400">
                    {riskCounts.LOW}
                  </p>
                </div>

              </div>

            </div>

          </div>

        </section>

        <section className="overflow-hidden rounded-2xl border border-slate-800 bg-slate-900">

          <div className="flex items-center justify-between border-b border-slate-800 px-6 py-5">

            <div>

        {/* =================================================
            MONGODB SECURITY EVENT HISTORY
        ================================================= */}

        <section className="rounded-2xl border border-slate-800 bg-slate-900 p-6">
          <div className="mb-5 flex flex-wrap items-center justify-between gap-4">
            <div>
              <h2 className="text-lg font-semibold">Security Event History</h2>
              <p className="text-sm text-slate-400">Persistent events from MongoDB Atlas</p>
            </div>
            <div className="flex items-center gap-2">
              <select value={historyRiskFilter} onChange={(e) => { setHistoryRiskFilter(e.target.value); refreshHistory(e.target.value); }} className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-slate-300">
                <option value="ALL">All Risk</option><option value="CRITICAL">Critical</option><option value="HIGH">High</option><option value="MEDIUM">Medium</option><option value="LOW">Low</option>
              </select>
              <button onClick={() => refreshHistory()} disabled={historyLoading} className="flex items-center gap-2 rounded-lg border border-slate-700 px-3 py-2 text-xs text-slate-300 hover:border-cyan-700 disabled:opacity-50">
                <RefreshCw className={`h-4 w-4 ${historyLoading ? "animate-spin" : ""}`} /> Refresh
              </button>
            </div>
          </div>

          {dashboardStats && (
            <div className="mb-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-6">
              <CommandMetric icon={<Activity />} label="Stored" value={dashboardStats.events_processed ?? dashboardStats.total_events ?? 0} detail="MongoDB events" />
              <CommandMetric icon={<AlertTriangle />} label="Threats" value={dashboardStats.threats_detected ?? 0} detail="Detected" />
              <CommandMetric icon={<Shield />} label="Critical" value={dashboardStats.critical_events ?? 0} detail="Critical events" />
              <CommandMetric icon={<Zap />} label="Responses" value={dashboardStats.automated_responses ?? 0} detail="Automatic" />
              <CommandMetric icon={<Brain />} label="ML Anomalies" value={dashboardStats.ml_anomalies ?? 0} detail="Detected" />
              <CommandMetric icon={<Link />} label="On-chain" value={dashboardStats.blockchain_records ?? 0} detail="Recorded" />
            </div>
          )}

          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-slate-950 text-slate-400"><tr><th className="px-4 py-3">Time</th><th className="px-4 py-3">Source</th><th className="px-4 py-3">Attack</th><th className="px-4 py-3">Risk</th><th className="px-4 py-3">Score</th><th className="px-4 py-3">Status</th></tr></thead>
              <tbody>
                {historyEvents.map((item) => {
                  const risk = item.risk_analysis?.risk_level || "LOW";
                  const attacks = item.threat_analysis?.detections?.map((d) => d.attack_type).join(", ") || "NORMAL";
                  return <tr key={item._id} onClick={() => openHistoryEvent(item._id)} className="cursor-pointer border-t border-slate-800 hover:bg-cyan-950/20">
                    <td className="whitespace-nowrap px-4 py-3 text-xs text-slate-400">{item.created_at ? new Date(item.created_at).toLocaleString() : "—"}</td>
                    <td className="px-4 py-3 font-mono text-cyan-300">{item.source_ip}</td>
                    <td className="px-4 py-3">{attacks}</td>
                    <td className="px-4 py-3"><span className={`rounded-full px-2.5 py-1 text-xs font-semibold ${risk === "CRITICAL" ? "bg-red-500/10 text-red-400" : risk === "HIGH" ? "bg-orange-500/10 text-orange-400" : risk === "MEDIUM" ? "bg-yellow-500/10 text-yellow-400" : "bg-emerald-500/10 text-emerald-400"}`}>{risk}</span></td>
                    <td className="px-4 py-3 font-semibold">{item.risk_analysis?.risk_score ?? 0}/100</td>
                    <td className="px-4 py-3 text-xs text-slate-400">{item.status || "NEW"}</td>
                  </tr>;
                })}
              </tbody>
            </table>
            {historyEvents.length === 0 && <div className="p-8 text-center text-slate-500">No stored events found.</div>}
          </div>
        </section>

        {selectedHistoryEvent && (
          <section className="rounded-2xl border border-cyan-500/30 bg-slate-900 p-6">
            <div className="mb-5 flex items-center justify-between"><div><h2 className="text-lg font-semibold">SOC Event Investigation</h2><p className="text-sm text-slate-400">MongoDB event details and safe response controls</p></div><button onClick={() => setSelectedHistoryEvent(null)} className="rounded-lg border border-slate-700 px-3 py-2 text-xs">Close</button></div>
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
              <InvestigationItem label="Event ID" value={selectedHistoryEvent._id || "—"} />
              <InvestigationItem label="Source IP" value={selectedHistoryEvent.source_ip || "—"} />
              <InvestigationItem label="Event Type" value={selectedHistoryEvent.event_type || "—"} />
              <InvestigationItem label="Agent" value={selectedHistoryEvent.agent_status || "—"} />
              <InvestigationItem label="ML Status" value={selectedHistoryEvent.ml_analysis?.ml_status || "—"} />
              <InvestigationItem label="Risk" value={`${selectedHistoryEvent.risk_analysis?.risk_level || "LOW"} (${selectedHistoryEvent.risk_analysis?.risk_score ?? 0}/100)`} />
              <InvestigationItem label="Status" value={selectedHistoryEvent.status || "NEW"} />
              <InvestigationItem label="Action" value={selectedHistoryEvent.action || "—"} />
            </div>
            <div className="mt-5 grid gap-4 lg:grid-cols-2">
              <div className="rounded-xl border border-slate-800 bg-slate-950 p-5"><h3 className="font-semibold">Detection & ML</h3><p className="mt-3 text-sm text-slate-400">{selectedHistoryEvent.ml_analysis?.ml_reason || "No ML reason available."}</p><div className="mt-4 space-y-2">{(selectedHistoryEvent.threat_analysis?.detections || []).map((d, i) => <div key={`${d.attack_type}-${i}`} className="rounded-lg border border-slate-800 p-3"><span className="font-semibold text-cyan-300">{d.attack_type}</span><span className="ml-2 text-xs text-slate-400">{d.severity}</span><p className="mt-1 text-xs text-slate-500">{d.reason}</p></div>)}</div></div>
              <div className="rounded-xl border border-slate-800 bg-slate-950 p-5"><h3 className="font-semibold">SOC Controls</h3><p className="mt-3 text-sm text-slate-400">{selectedHistoryEvent.response?.response_description || "No response description."}</p><div className="mt-4 flex flex-wrap gap-2">
                <button disabled={actionLoading} onClick={() => acknowledgeHistoryEvent(selectedHistoryEvent._id)} className="rounded-lg border border-cyan-700 px-3 py-2 text-xs text-cyan-300 disabled:opacity-50">Acknowledge</button>
                <button disabled={actionLoading} onClick={() => executeHistoryAction(selectedHistoryEvent._id, "MONITOR")} className="rounded-lg border border-slate-700 px-3 py-2 text-xs disabled:opacity-50">Monitor</button>
                <button disabled={actionLoading} onClick={() => executeHistoryAction(selectedHistoryEvent._id, "ISOLATE_SIMULATED_SOURCE")} className="rounded-lg border border-yellow-700 px-3 py-2 text-xs text-yellow-300 disabled:opacity-50">Simulate Isolation</button>
                <button disabled={actionLoading} onClick={() => executeHistoryAction(selectedHistoryEvent._id, "BLOCK_SIMULATED_SOURCE")} className="rounded-lg border border-red-700 px-3 py-2 text-xs text-red-300 disabled:opacity-50">Simulate Block</button>
                <button disabled={actionLoading} onClick={() => executeHistoryAction(selectedHistoryEvent._id, "MARK_TRUSTED")} className="rounded-lg border border-emerald-700 px-3 py-2 text-xs text-emerald-300 disabled:opacity-50">Mark Trusted</button>
              </div>{operationMessage && <p className="mt-4 text-xs text-cyan-300">{operationMessage}</p>}</div>
            </div>
            {selectedHistoryEvent.blockchain && <div className="mt-4 rounded-xl border border-emerald-500/20 bg-emerald-500/5 p-5"><h3 className="font-semibold text-emerald-400">Blockchain Record</h3><div className="mt-3 grid gap-3 md:grid-cols-3"><InvestigationItem label="Status" value={selectedHistoryEvent.blockchain.blockchain_status || "—"} /><InvestigationItem label="Transaction" value={selectedHistoryEvent.blockchain.transaction_hash || "—"} /><InvestigationItem label="Block" value={selectedHistoryEvent.blockchain.block_number ?? "—"} /><InvestigationItem label="Threat Hash" value={selectedHistoryEvent.blockchain.threat_hash || "—"} /><InvestigationItem label="Contract" value={selectedHistoryEvent.blockchain.contract_address || "—"} /></div></div>}
          </section>
        )}

        {/* =================================================
            BLOCKCHAIN THREAT REGISTRY
        ================================================= */}

              <h2 className="text-lg font-semibold">
                Blockchain Threat Registry
              </h2>

              <p className="text-sm text-slate-400">
                Verified security threats recorded on-chain
              </p>

            </div>

            <Server className="h-5 w-5 text-cyan-400" />

          </div>

          {threats.length === 0 ? (

            <div className="p-8 text-center text-slate-400">
              No threats recorded.
            </div>

          ) : (

            <div className="overflow-x-auto">

              <table className="w-full text-left text-sm">

                <thead className="bg-slate-950 text-slate-400">

                  <tr>

                    <th className="px-6 py-4">
                      ID
                    </th>

                    <th className="px-6 py-4">
                      Source IP
                    </th>

                    <th className="px-6 py-4">
                      Attack
                    </th>

                    <th className="px-6 py-4">
                      Risk
                    </th>

                    <th className="px-6 py-4">
                      Score
                    </th>

                    <th className="px-6 py-4">
                      Threat Hash
                    </th>

                  </tr>

                </thead>

                <tbody>

                  {threats.map(
                    (threat) => (

                      <tr
                        key={
                          threat.threat_id
                        }
                        onClick={() =>
                          viewThreatDetails(
                            threat.threat_id
                          )
                        }
                        className="cursor-pointer border-t border-slate-800 transition hover:bg-cyan-950/30"
                        title="Click to view blockchain details"
                      >

                        <td className="px-6 py-4 font-medium">
                          #{threat.threat_id}
                        </td>

                        <td className="px-6 py-4 font-mono text-cyan-300">
                          {threat.source_ip}
                        </td>

                        <td className="px-6 py-4">
                          {threat.attack_type}
                        </td>

                        <td className="px-6 py-4">

                          <span
                            className={`rounded-full px-3 py-1 text-xs font-semibold ${
                              threat.risk_level ===
                              "CRITICAL"
                                ? "bg-red-500/10 text-red-400"
                                : threat.risk_level ===
                                  "HIGH"
                                ? "bg-orange-500/10 text-orange-400"
                                : threat.risk_level ===
                                  "MEDIUM"
                                ? "bg-yellow-500/10 text-yellow-400"
                                : "bg-emerald-500/10 text-emerald-400"
                            }`}
                          >
                            {threat.risk_level}
                          </span>

                        </td>

                        <td className="px-6 py-4 font-semibold">
                          {threat.risk_score}/100
                        </td>

                        <td className="max-w-xs truncate px-6 py-4 font-mono text-xs text-slate-400">
                          {threat.threat_hash}
                        </td>

                      </tr>

                    )
                  )}

                </tbody>

              </table>

            </div>

          )}

        </section>

        {/* =================================================
            THREAT DETAILS
        ================================================= */}

        {selectedThreat && (

          <section className="overflow-hidden rounded-2xl border border-cyan-500/30 bg-slate-900">

            <div className="flex items-center justify-between border-b border-slate-800 p-6">

              <div className="flex items-center gap-3">

                <div className="rounded-xl bg-cyan-500/10 p-3">
                  <Eye className="h-6 w-6 text-cyan-400" />
                </div>

                <div>

                  <h2 className="text-lg font-semibold">
                    Threat Details
                  </h2>

                  <p className="text-sm text-slate-400">
                    Blockchain-verified security threat
                  </p>

                </div>

              </div>

              <button
                onClick={() =>
                  setSelectedThreat(null)
                }
                className="rounded-lg border border-slate-700 p-2 text-slate-400 transition hover:bg-slate-800 hover:text-white"
                title="Close details"
              >
                <X className="h-5 w-5" />
              </button>

            </div>

            <div className="grid gap-4 p-6 md:grid-cols-2">

              <DetailCard
                label="Threat ID"
                value={`#${selectedThreat.threat_id}`}
              />

              <DetailCard
                label="Source IP"
                value={
                  selectedThreat.source_ip
                }
              />

              <DetailCard
                label="Attack Type"
                value={
                  selectedThreat.attack_type
                }
              />

              <DetailCard
                label="Risk Level"
                value={
                  selectedThreat.risk_level
                }
              />

              <DetailCard
                label="Risk Score"
                value={`${selectedThreat.risk_score}/100`}
              />

              <DetailCard
                label="Reporter"
                value={
                  selectedThreat.reporter
                }
              />

              <div className="md:col-span-2">

                <DetailCard
                  label="Threat Hash"
                  value={
                    selectedThreat.threat_hash
                  }
                />

              </div>

              <div className="md:col-span-2">

                <DetailCard
                  label="Smart Contract"
                  value={
                    selectedThreat.contract_address
                  }
                />

              </div>

              <div className="md:col-span-2">

                <DetailCard
                  label="Blockchain Timestamp"
                  value={
                    selectedThreat.timestamp
                      ? new Date(
                          selectedThreat.timestamp *
                            1000
                        ).toLocaleString()
                      : "Unavailable"
                  }
                />

              </div>

              <div className="md:col-span-2">

                <div className="rounded-xl border border-emerald-500/20 bg-emerald-500/5 p-5">

                  <div className="flex items-center gap-3">

                    <CheckCircle className="h-6 w-6 text-emerald-400" />

                    <div>

                      <p className="font-semibold text-emerald-400">
                        Blockchain Verified
                      </p>

                      <p className="mt-1 text-sm text-slate-400">
                        This threat record was retrieved directly from the SentinelX blockchain registry.
                      </p>

                    </div>

                  </div>

                </div>

              </div>

            </div>

          </section>

        )}

        {/* =================================================
            DETECTION PIPELINE
        ================================================= */}

        <section className="rounded-2xl border border-slate-800 bg-slate-900 p-6">

          <h2 className="mb-5 text-lg font-semibold">
            SentinelX Detection Pipeline
          </h2>

          <div className="grid gap-3 md:grid-cols-6">

            {[
              "Security Event",
              "Rule Engine",
              "ML Detection",
              "Risk Engine",
              "Response",
              "Blockchain",
            ].map(
              (item, index) => (

                <div
                  key={item}
                  className="rounded-xl border border-slate-700 bg-slate-950 p-4 text-center"
                >

                  <div className="mb-2 text-xs text-cyan-400">
                    STEP {index + 1}
                  </div>

                  <div className="font-medium">
                    {item}
                  </div>

                </div>

              )
            )}

          </div>

        </section>


      </main>

      {showUserManagement && user?.role === "admin" && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm">
          <div className="w-full max-w-4xl rounded-2xl border border-slate-700 bg-slate-900 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 px-6 py-4">
              <div>
                <h2 className="text-lg font-bold text-white">
                  User Management
                </h2>
                <p className="text-xs text-slate-400">
                  Admin-only SOC account management
                </p>
              </div>

              <button
                onClick={() => setShowUserManagement(false)}
                className="rounded-lg px-3 py-2 text-slate-400 hover:bg-slate-800 hover:text-white"
              >
                ✕
              </button>
            </div>

            <div className="grid gap-6 p-6 lg:grid-cols-2">
              <form
                onSubmit={handleCreateUser}
                className="rounded-xl border border-slate-800 bg-slate-950/60 p-5"
              >
                <h3 className="mb-4 font-semibold text-white">
                  Create SOC User
                </h3>

                <div className="space-y-4">
                  <input
                    value={newUsername}
                    onChange={(e) => setNewUsername(e.target.value)}
                    placeholder="Username"
                    className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-white outline-none focus:border-cyan-500"
                    required
                  />

                  <input
                    type="password"
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    placeholder="Password (8+ characters)"
                    minLength={8}
                    className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-white outline-none focus:border-cyan-500"
                    required
                  />

                  <select
                    value={newRole}
                    onChange={(e) => setNewRole(e.target.value)}
                    className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-white outline-none focus:border-cyan-500"
                  >
                    <option value="analyst">Analyst</option>
                    <option value="admin">Admin</option>
                  </select>

                  <button
                    type="submit"
                    disabled={userBusy}
                    className="w-full rounded-lg bg-cyan-500 px-4 py-2 font-semibold text-slate-950 hover:bg-cyan-400 disabled:opacity-50"
                  >
                    {userBusy ? "Saving..." : "Create User"}
                  </button>

                  {userMessage && (
                    <p className="text-xs text-slate-400">
                      {userMessage}
                    </p>
                  )}
                </div>
              </form>

              <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-5">
                <div className="mb-4 flex items-center justify-between">
                  <h3 className="font-semibold text-white">
                    Existing Users
                  </h3>

                  <span className="text-xs text-slate-500">
                    {users.length} account{users.length === 1 ? "" : "s"}
                  </span>
                </div>

                <div className="max-h-80 space-y-2 overflow-y-auto">
                  {users.map((account) => (
                    <div
                      key={account.id}
                      className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-900 px-3 py-3"
                    >
                      <div>
                        <p className="text-sm font-medium text-white">
                          {account.username}
                        </p>

                        <p className="text-[10px] uppercase text-slate-500">
                          {account.role}
                        </p>
                      </div>

                      {account.username !== user?.username && (
                        <button
                          onClick={() => handleDeleteUser(account.username)}
                          disabled={userBusy}
                          className="rounded-lg border border-red-900/60 px-3 py-1.5 text-xs text-red-300 hover:bg-red-950/40 disabled:opacity-50"
                        >
                          Delete
                        </button>
                      )}
                    </div>
                  ))}

                  {!users.length && (
                    <p className="py-8 text-center text-sm text-slate-500">
                      No users found.
                    </p>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}

// =====================================================
// COMMAND CENTER METRIC
// =====================================================

function CommandMetric({ icon, label, value, detail }) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">
      <div className="flex items-center justify-between">
        <p className="text-xs text-slate-500">{label}</p>
        <div className="text-cyan-400">{icon}</div>
      </div>
      <p className="mt-2 text-2xl font-bold">{value}</p>
      <p className="mt-1 text-xs text-slate-500">{detail}</p>
    </div>
  );
}

// =====================================================
// HEALTH ITEM
// =====================================================

function HealthItem({ label, online, detail }) {
  return (
    <div className="flex items-center justify-between rounded-xl border border-slate-800 bg-slate-950 px-4 py-3">
      <div className="min-w-0">
        <p className="text-sm font-medium text-slate-200">{label}</p>
        <p className="mt-0.5 truncate text-xs text-slate-500">{detail}</p>
      </div>
      <div className="ml-3 flex shrink-0 items-center gap-2">
        <span className={`h-2.5 w-2.5 rounded-full ${
          online ? "bg-emerald-400" : "bg-red-500"
        }`} />
        <span className={`text-xs font-semibold ${
          online ? "text-emerald-400" : "text-red-400"
        }`}>
          {online ? "ONLINE" : "OFFLINE"}
        </span>
      </div>
    </div>
  );
}

// =====================================================
// INVESTIGATION ITEM
// =====================================================

function InvestigationItem({
  label,
  value,
  copyable = false,
  onCopy,
}) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="text-xs uppercase tracking-wide text-slate-500">
            {label}
          </p>
          <p className="mt-2 break-words text-sm text-cyan-300">
            {value}
          </p>
        </div>
        {copyable && (
          <button
            onClick={() => onCopy(value)}
            className="shrink-0 rounded-lg border border-slate-700 p-2 text-slate-400 hover:bg-slate-800 hover:text-white"
            title={`Copy ${label}`}
          >
            <Copy className="h-4 w-4" />
          </button>
        )}
      </div>
    </div>
  );
}

// =====================================================
// SIMULATOR BUTTON
// =====================================================

function SimulatorButton({
  label,
  description,
  onClick,
  disabled,
  critical = false,
}) {
  return (

    <button
      onClick={onClick}
      disabled={disabled}
      className={`rounded-xl border p-4 text-left transition ${
        critical
          ? "border-red-800 bg-red-950/20 hover:bg-red-950/40"
          : "border-slate-700 bg-slate-950 hover:border-cyan-700 hover:bg-slate-800"
      } ${
        disabled
          ? "cursor-not-allowed opacity-50"
          : "cursor-pointer"
      }`}
    >

      <div className="flex items-center gap-2">

        <Play
          className={`h-4 w-4 ${
            critical
              ? "text-red-400"
              : "text-cyan-400"
          }`}
        />

        <span className="font-semibold">
          {label}
        </span>

      </div>

      <p className="mt-2 text-xs text-slate-500">
        {description}
      </p>

    </button>

  );
}

// =====================================================
// RESULT ITEM
// =====================================================

function ResultItem({
  label,
  value,
}) {
  return (

    <div className="rounded-lg border border-slate-800 bg-slate-900 p-3">

      <p className="text-xs text-slate-500">
        {label}
      </p>

      <p className="mt-1 text-sm font-semibold text-cyan-300">
        {value}
      </p>

    </div>

  );
}

// =====================================================
// DETAIL CARD
// =====================================================

function DetailCard({
  label,
  value,
}) {
  return (

    <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">

      <p className="text-xs uppercase tracking-wide text-slate-500">
        {label}
      </p>

      <p className="mt-2 break-all text-sm text-cyan-300">
        {value}
      </p>

    </div>

  );
}

// =====================================================
// ANALYTICS CARD
// =====================================================

function AnalyticsCard({
  title,
  value,
  description,
}) {
  return (

    <div className="rounded-2xl border border-slate-800 bg-slate-900 p-5">

      <p className="text-sm text-slate-400">
        {title}
      </p>

      <p className="mt-2 text-3xl font-bold text-cyan-400">
        {value}
      </p>

      <p className="mt-1 text-xs text-slate-500">
        {description}
      </p>

    </div>

  );
}

// =====================================================
// STAT CARD
// =====================================================

function StatCard({
  icon,
  title,
  value,
}) {
  return (

    <div className="rounded-2xl border border-slate-800 bg-slate-900 p-5">

      <div className="mb-4 flex items-center justify-between">

        <div className="text-cyan-400">
          {icon}
        </div>

        <span className="text-xs text-slate-500">
          {title}
        </span>

      </div>

      <div className="text-3xl font-bold">
        {value}
      </div>

    </div>

  );
}

// =====================================================
// STATUS CARD
// =====================================================

function StatusCard({
  icon,
  title,
  status,
}) {
  return (

    <div className="flex items-center gap-4 rounded-2xl border border-slate-800 bg-slate-900 p-5">

      <div className="rounded-xl bg-slate-800 p-3 text-cyan-400">
        {icon}
      </div>

      <div>

        <p className="text-sm text-slate-400">
          {title}
        </p>

        <p className="mt-1 font-semibold text-emerald-400">
          ● {status}
        </p>

      </div>

    </div>

  );
}


function LoginScreen({ onLogin }) {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("SentinelX@123");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const submit = async (event) => {
    event.preventDefault();
    setBusy(true);
    setError("");

    try {
      const response = await axios.post(`${API}/auth/login`, {
        username,
        password,
      });

      onLogin(response.data);
    } catch (err) {
      setError(
        err?.response?.data?.detail ||
        "Login failed. Check the backend and credentials."
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-950 px-4 text-white">
      <div className="w-full max-w-md rounded-3xl border border-slate-800 bg-slate-900 p-8 shadow-2xl">
        <div className="mb-8 text-center">
          <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-2xl bg-cyan-500/10">
            <Shield className="h-9 w-9 text-cyan-400" />
          </div>
          <h1 className="text-3xl font-bold">SentinelX</h1>
          <p className="mt-2 text-sm text-slate-400">
            Security Operations Center
          </p>
        </div>

        <form onSubmit={submit} className="space-y-5">
          <div>
            <label className="mb-2 block text-sm text-slate-300">
              Username
            </label>
            <input
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full rounded-xl border border-slate-700 bg-slate-950 px-4 py-3 outline-none focus:border-cyan-500"
              autoComplete="username"
            />
          </div>

          <div>
            <label className="mb-2 block text-sm text-slate-300">
              Password
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full rounded-xl border border-slate-700 bg-slate-950 px-4 py-3 outline-none focus:border-cyan-500"
              autoComplete="current-password"
            />
          </div>

          {error && (
            <div className="rounded-xl border border-red-900/60 bg-red-950/30 px-4 py-3 text-sm text-red-300">
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={busy}
            className="w-full rounded-xl bg-cyan-500 px-4 py-3 font-semibold text-slate-950 transition hover:bg-cyan-400 disabled:opacity-50"
          >
            {busy ? "Authenticating..." : "Enter SOC"}
          </button>
        </form>

        <div className="mt-6 rounded-xl border border-slate-800 bg-slate-950/70 p-4 text-xs text-slate-500">
          Demo admin: <span className="text-slate-300">admin</span> /{" "}
          <span className="text-slate-300">SentinelX@123</span>
          <br />
          Change these through your backend environment before deployment.
        </div>
      </div>
    </div>
  );
}

function App() {
  const [session, setSession] = useState(() => {
    try {
      return JSON.parse(localStorage.getItem("sentinelx_session") || "null");
    } catch {
      return null;
    }
  });

  const handleLogin = (data) => {
    const nextSession = {
      token: data.access_token,
      user: data.user,
    };
    localStorage.setItem("sentinelx_session", JSON.stringify(nextSession));
    setSession(nextSession);
  };

  const handleLogout = () => {
    localStorage.removeItem("sentinelx_session");
    delete axios.defaults.headers.common.Authorization;
    setSession(null);
  };

  if (!session?.token) {
    return <LoginScreen onLogin={handleLogin} />;
  }

  return (
    <DashboardApp
      token={session.token}
      user={session.user}
      onLogout={handleLogout}
    />
  );
}

export default App;
