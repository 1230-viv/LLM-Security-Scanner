import { useNavigate } from "react-router-dom";

import ScanForm from "@/components/ScanForm";

function HomePage(): JSX.Element {
  const navigate = useNavigate();

  return (
    <>
      <section className="panel">
        <h2>Security Program Launchpad</h2>
        <p>
          Configure endpoint authentication, attack categories, and execution controls, then launch
          an asynchronous red-team run.
        </p>
      </section>
      <ScanForm onScanCreated={(scanId) => navigate(`/scan/${scanId}`)} />
    </>
  );
}

export default HomePage;
