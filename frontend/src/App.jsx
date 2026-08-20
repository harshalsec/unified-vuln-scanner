import { Routes, Route } from "react-router-dom";
import Layout from "./components/Layout";
import Dashboard from "./pages/Dashboard";
import NewScan from "./pages/NewScan";
import JobDetail from "./pages/JobDetail";

function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/new-scan" element={<NewScan />} />
        <Route path="/jobs/:id" element={<JobDetail />} />
      </Routes>
    </Layout>
  );
}

export default App;