<div align="center">
  <img src="https://raw.githubusercontent.com/Centinell2025/the-last-evidence-standing/main/branding/BEACON_SEAL.png" alt="Beacon of the Eagle LLC — logotipo corporativo" width="165" />
  <p><strong>BEACON OF THE EAGLE LLC</strong><br/><strong>CENTINELL SUITE DEFENSE</strong></p>
</div>

# ia-centinell


## Regression checks

Run `npm test` from the repository root with Node.js 20 or later. The test suite uses Node's built-in test runner, Web Crypto, and File APIs; it requires no installed dependencies and makes no external API calls.

The tests cover UTF-8 text hashes, original file bytes, distinct file contents, typed-array slices, scanner/baseline hash handling, and the AI remediation-guide control. Provider calls are stubbed during tests. Both demo key markers are rejected before a provider request. Regression tests also ensure empty bytes and the common "quick brown fox" sentence are not classified as EICAR or WannaCry in either scanner. The guide is advisory and executes no remediation actions.

These targeted fixes do not validate the simulated protection metrics, signature catalogue, live infrastructure integrations, authentication/storage model, or production readiness. The Anthropic integration and backend configuration remain separate from these checks.
