import React from 'react';

export default function Dashboard() {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold tracking-tight">Dashboard</h1>
        <div className="flex items-center space-x-4">
          <button className="px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90">
            New Scan
          </button>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="bg-card rounded-lg p-6 border">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-muted-foreground">Total Targets</p>
              <p className="text-2xl font-bold">24</p>
            </div>
            <div className="h-8 w-8 bg-primary/10 rounded-full flex items-center justify-center">
              <span className="text-primary text-sm">🎯</span>
            </div>
          </div>
        </div>

        <div className="bg-card rounded-lg p-6 border">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-muted-foreground">Subdomains</p>
              <p className="text-2xl font-bold">1,247</p>
            </div>
            <div className="h-8 w-8 bg-blue-500/10 rounded-full flex items-center justify-center">
              <span className="text-blue-500 text-sm">🌐</span>
            </div>
          </div>
        </div>

        <div className="bg-card rounded-lg p-6 border">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-muted-foreground">Vulnerabilities</p>
              <p className="text-2xl font-bold">89</p>
            </div>
            <div className="h-8 w-8 bg-red-500/10 rounded-full flex items-center justify-center">
              <span className="text-red-500 text-sm">🔍</span>
            </div>
          </div>
        </div>

        <div className="bg-card rounded-lg p-6 border">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-muted-foreground">Active Scans</p>
              <p className="text-2xl font-bold">3</p>
            </div>
            <div className="h-8 w-8 bg-green-500/10 rounded-full flex items-center justify-center">
              <span className="text-green-500 text-sm">⚡</span>
            </div>
          </div>
        </div>
      </div>

      {/* Recent Activity */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-card rounded-lg p-6 border">
          <h3 className="text-lg font-semibold mb-4">Recent Scans</h3>
          <div className="space-y-3">
            <div className="flex items-center justify-between py-2">
              <div className="flex items-center space-x-3">
                <div className="h-2 w-2 bg-green-500 rounded-full"></div>
                <span className="text-sm">example.com - Full Scan</span>
              </div>
              <span className="text-xs text-muted-foreground">2 hours ago</span>
            </div>
            <div className="flex items-center justify-between py-2">
              <div className="flex items-center space-x-3">
                <div className="h-2 w-2 bg-blue-500 rounded-full animate-pulse"></div>
                <span className="text-sm">target.com - Subdomain Scan</span>
              </div>
              <span className="text-xs text-muted-foreground">Running</span>
            </div>
            <div className="flex items-center justify-between py-2">
              <div className="flex items-center space-x-3">
                <div className="h-2 w-2 bg-green-500 rounded-full"></div>
                <span className="text-sm">demo.com - Port Scan</span>
              </div>
              <span className="text-xs text-muted-foreground">1 day ago</span>
            </div>
          </div>
        </div>

        <div className="bg-card rounded-lg p-6 border">
          <h3 className="text-lg font-semibold mb-4">Recent Vulnerabilities</h3>
          <div className="space-y-3">
            <div className="flex items-center justify-between py-2">
              <div className="flex items-center space-x-3">
                <div className="h-2 w-2 bg-red-500 rounded-full"></div>
                <span className="text-sm">SQL Injection - admin.example.com</span>
              </div>
              <span className="text-xs bg-red-500/10 text-red-500 px-2 py-1 rounded">Critical</span>
            </div>
            <div className="flex items-center justify-between py-2">
              <div className="flex items-center space-x-3">
                <div className="h-2 w-2 bg-orange-500 rounded-full"></div>
                <span className="text-sm">XSS - api.target.com</span>
              </div>
              <span className="text-xs bg-orange-500/10 text-orange-500 px-2 py-1 rounded">High</span>
            </div>
            <div className="flex items-center justify-between py-2">
              <div className="flex items-center space-x-3">
                <div className="h-2 w-2 bg-yellow-500 rounded-full"></div>
                <span className="text-sm">Open Redirect - www.demo.com</span>
              </div>
              <span className="text-xs bg-yellow-500/10 text-yellow-500 px-2 py-1 rounded">Medium</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}