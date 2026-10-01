import { Routes, Route } from "react-router-dom";
import Layout from "./components/Layout";
import Dashboard from "./pages/Dashboard";
import NewScan from "./pages/NewScan";
import JobDetail from "./pages/JobDetail";
import ChatScan from "./pages/ChatScan";

function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/new-scan" element={<NewScan />} />
        <Route path="/jobs/:id" element={<JobDetail />} />
        <Route path="/chat" element={<ChatScan />} />
      </Routes>
    </Layout>
  );
}

export default App;