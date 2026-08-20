import { Link, useLocation } from "react-router-dom";
import { Shield, LayoutDashboard, PlusCircle } from "lucide-react";

export default function Layout({ children }) {
  const location = useLocation();

  const isActive = (path) => location.pathname === path;

  return (
    <div className="min-h-screen bg-gray-950 text-white">
      {/* Navbar */}
      <nav className="border-b border-gray-800 bg-gray-900/70 backdrop-blur sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 py-3.5 flex items-center justify-between">
          <Link to="/" className="flex items-center gap-2.5">
            <div className="bg-emerald-500/10 p-1.5 rounded-lg">
              <Shield className="w-5 h-5 text-emerald-400" />
            </div>
            <span className="text-lg font-bold tracking-tight">Vuln Scanner</span>
          </Link>

          <div className="flex items-center gap-1 text-sm">
            <Link
              to="/"
              className={`flex items-center gap-2 px-3 py-2 rounded-lg transition ${
                isActive("/")
                  ? "bg-gray-800 text-white"
                  : "text-gray-400 hover:text-white hover:bg-gray-800/50"
              }`}
            >
              <LayoutDashboard className="w-4 h-4" />
              Dashboard
            </Link>
            <Link
              to="/new-scan"
              className={`flex items-center gap-2 px-3 py-2 rounded-lg transition ${
                isActive("/new-scan")
                  ? "bg-gray-800 text-white"
                  : "text-gray-400 hover:text-white hover:bg-gray-800/50"
              }`}
            >
              <PlusCircle className="w-4 h-4" />
              New Scan
            </Link>
          </div>
        </div>
      </nav>

      {/* Page Content */}
      <main className="max-w-7xl mx-auto px-4 py-8">{children}</main>
    </div>
  );
}