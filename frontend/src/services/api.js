import axios from "axios";

const API_BASE = "http://localhost:8000/api/v1";

const api = axios.create({
  baseURL: API_BASE,
  headers: {
    "Content-Type": "application/json",
  },
});

export const createJob = async (jobData) => {
  const response = await api.post("/jobs/", jobData);
  return response.data;
};

export const getJobs = async () => {
  const response = await api.get("/jobs/");
  return response.data;
};

export const getJob = async (jobId) => {
  const response = await api.get(`/jobs/${jobId}`);
  return response.data;
};

export const runJob = async (jobId) => {
  const response = await api.post(`/jobs/${jobId}/run`);
  return response.data;
};

export default api;