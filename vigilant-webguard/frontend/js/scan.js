// frontend/js/scan.js

import { startScan, getScanResult } from './api.js';

let currentScanId = null;
let polling = null;

document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('scan-form');
  const status = document.getElementById('scan-status');
  const scannerSec = document.getElementById('scanner-section');
  const scannerRes = document.getElementById('scanner-result');

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const target = form.target.value.trim();
    const engine = form.engine.value;

    status.textContent = '⏳ Iniciando escaneo...';
    scannerRes.textContent = '';
    scannerSec.classList.add('hidden');

    try {
      const { scan_id } = await startScan(target, engine);
      currentScanId = scan_id;
      status.textContent = `🔄 Escaneando... ID ${scan_id}`;

      polling = setInterval(async () => {
        try {
          const result = await getScanResult(currentScanId);
          if (result.status === 'completed' || result.status === 'error') {
            clearInterval(polling);
            status.textContent = result.status === 'completed'
              ? '✅ Escaneo completado'
              : `❌ Escaneo falló: ${result.error}`;

            scannerRes.textContent = JSON.stringify(result, null, 2);
            scannerSec.classList.remove('hidden');
          }
        } catch (err) {
          clearInterval(polling);
          status.textContent = '⚠️ Error consultando resultados';
        }
      }, 2000);
    } catch (err) {
      status.textContent = `❌ ${err.message}`;
    }
  });
});
