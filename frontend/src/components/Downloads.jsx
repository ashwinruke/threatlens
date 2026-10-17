import { API_URL } from "../lib/api";

// Download buttons for a report or a bulk lookup. path is "investigations/<id>" or "bulk/<id>".
// STIX 2.1 is the standard format threat intelligence tools import (OpenCTI, MISP, many SIEMs);
// CSV opens in any spreadsheet.
export default function Downloads({ path, label = "Download" }) {
  const base = `${API_URL}/api/${path}/export`;
  return (
    <span className="downloads">
      <span className="downloads__label">{label}:</span>
      <a className="downloads__link" href={`${base}/stix`} download
        title="STIX 2.1: the standard format threat intelligence platforms import">STIX 2.1</a>
      <a className="downloads__link" href={`${base}/csv`} download title="A spreadsheet file">CSV</a>
    </span>
  );
}
