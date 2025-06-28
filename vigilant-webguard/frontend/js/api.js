// frontend/js/api.js

export async function startScan(target, engine) {
  const res = await fetch('/api/scan/', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target, engine })
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.detail || 'Error al iniciar el escaneo');
  }
  return res.json(); // { scan_id, status }
}

export async function getScanResult(scanId) {
  const res = await fetch(`/api/scan/${scanId}`);
  if (!res.ok) {
    throw new Error('Scan ID no encontrado');
  }
  return res.json(); // ScanResult
}
