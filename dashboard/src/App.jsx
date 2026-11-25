import React, { useState } from 'react';
import { AppProvider, useApp } from './contexts/AppContext';
import { Sidebar } from './components/Sidebar';
import { Header } from './components/Header';
import { Toasts } from './components/Toasts';
import { GlobalSearch } from './components/GlobalSearch';
import { useGlobalSearch } from './hooks/useGlobalSearch';
import { OverviewPage } from './pages/OverviewPage';
import { EndpointsPage } from './pages/EndpointsPage';
import { AlertsPage } from './pages/AlertsPage';
import { BlockedPage } from './pages/BlockedPage';
import { UsersPage } from './pages/UsersPage';
import { ReportsPage } from './pages/ReportsPage';
import { SetupPage } from './pages/SetupPage';

function DashboardContent() {
  const { activeTab } = useApp();
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const { open: searchOpen, query: searchQuery, setQuery: setSearchQuery, toggle: toggleSearch, close: closeSearch } = useGlobalSearch();

  // Keyboard shortcut Ctrl+K or / to open search
  React.useEffect(() => {
    const handleKeyDown = (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        toggleSearch();
      } else if (e.key === '/' && !['INPUT', 'TEXTAREA'].includes(document.activeElement?.tagName)) {
        e.preventDefault();
        toggleSearch();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [toggleSearch]);

  const renderPage = () => {
    switch (activeTab) {
      case 'overview':
        return <OverviewPage />;
      case 'endpoints':
        return <EndpointsPage />;
      case 'alerts':
        return <AlertsPage />;
      case 'blocked':
        return <BlockedPage />;
      case 'users':
        return <UsersPage />;
      case 'reports':
        return <ReportsPage />;
      case 'setup':
        return <SetupPage />;
      default:
        return <OverviewPage />;
    }
  };

  return (
    <div className="app-shell">
      {/* Skip to main content for accessibility */}
      <a href="#main-content" className="skip-link">Skip to content</a>

      {/* Sidebar */}
      <Sidebar collapsed={sidebarCollapsed} />

      {/* Main Outer Card Container */}
      <div className="app-inner">
        {/* Header */}
        <Header
          onSearchOpen={toggleSearch}
          sidebarCollapsed={sidebarCollapsed}
          setSidebarCollapsed={setSidebarCollapsed}
        />

        {/* Scrollable Page Content */}
        <main id="main-content" className="main-content" role="main">
          {renderPage()}
        </main>
      </div>

      {/* Global Notifications */}
      <Toasts />

      {/* Global Search Modal */}
      <GlobalSearch
        open={searchOpen}
        query={searchQuery}
        setQuery={setSearchQuery}
        onClose={closeSearch}
      />
    </div>
  );
}

export default function App() {
  return (
    <AppProvider>
      <DashboardContent />
    </AppProvider>
  );
}
