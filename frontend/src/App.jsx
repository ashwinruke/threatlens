import Header from "./components/Header";
import HistoryPage from "./pages/HistoryPage";
import HomePage from "./pages/HomePage";
import ReportPage from "./pages/ReportPage";
import StatusPage from "./pages/StatusPage";
import { Link, usePath } from "./lib/router";

function NotFound() {
  return (
    <main className="page">
      <h1 className="page-title">Page not found</h1>
      <p className="notice">
        <Link to="/">Go to the investigate page</Link>.
      </p>
    </main>
  );
}

export default function App() {
  const path = usePath();
  let page;
  const report = path.match(/^\/i\/([^/]+)\/?$/);
  if (path === "/") page = <HomePage />;
  else if (report) page = <ReportPage id={decodeURIComponent(report[1])} />;
  else if (path === "/history") page = <HistoryPage />;
  else if (path === "/status") page = <StatusPage />;
  else page = <NotFound />;

  if (!report) document.title = "ThreatLens — See the threat before it sees you";

  return (
    <>
      <Header />
      {page}
      <footer className="footer">
        ThreatLens checks public threat intelligence passively. It never connects to the indicators you investigate.
      </footer>
    </>
  );
}
