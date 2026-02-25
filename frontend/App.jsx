import { BrowserRouter, Routes, Route } from "react-router-dom";
import LandingPage from "./pages/LandingPage";
import Login from "./pages/Login";
import Register from "./pages/Register";
import Dashboard from "./pages/Dashboard";
import Recovery from "./pages/Recovery";

function App() {
    return (
        <BrowserRouter>
            <Routes>
                <Route path="/" element={<LandingPage />} />
                <Route path="/login" element={<Login />} />
                <Route path="/register" element={<Register />} />
                {/* The Dashboard holds the File Upload logic now */}
                <Route path="/dashboard" element={<Dashboard />} />
                <Route path="/recovery" element={<Recovery />} />
            </Routes>
        </BrowserRouter>
    );
}

export default App;

