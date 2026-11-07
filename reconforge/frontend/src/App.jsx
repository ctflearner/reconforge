import React from 'react';
import { Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import Dashboard from './pages/Dashboard';
import NewScan from './pages/NewScan';
import ScanDetail from './pages/ScanDetail';
import Findings from './pages/Findings';
import Assets from './pages/Assets';
import Reports from './pages/Reports';
import Results from './pages/Results';
import Settings from './pages/Settings';

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route path="/" element={<Dashboard />} />
        <Route path="/scans/new" element={<NewScan />} />
        <Route path="/scans/:id" element={<ScanDetail />} />
        <Route path="/findings" element={<Findings />} />
        <Route path="/assets" element={<Assets />} />
        <Route path="/reports" element={<Reports />} />
        <Route path="/results" element={<Results />} />
        <Route path="/settings" element={<Settings />} />
      </Route>
    </Routes>
  );
}
