import { useState } from 'react'
import './App.css'

function App() {
  const [scanSwaggerUrl, setScanSwaggerUrl] = useState('')
  const [scanBaseUrl, setScanBaseUrl] = useState('')
  const [scanReport, setScanReport] = useState(null)
  const [scanError, setScanError] = useState(null)
  const [scanLoading, setScanLoading] = useState(false)
  const [reportAction, setReportAction] = useState('') // '', 'html-tech-dl', 'html-tech-open'
  const [showTechDoc, setShowTechDoc] = useState(false)
  const [destructive, setDestructive] = useState(false)
  const [includePaths, setIncludePaths] = useState('')


  const handleScan = async (e) => {
    e.preventDefault()
    setScanError(null)
    setScanReport(null)
    const u = scanSwaggerUrl.trim()
    if (!u) {
      setScanError('Informe a URL do OpenAPI/Swagger')
      return
    }

    if (destructive) {
      const ok = window.confirm('ATENÇÃO: o Destructive Scan pode criar/alterar/excluir recursos de teste. Use somente em ambientes controlados e com paths restritos. Deseja continuar?')
      if (!ok) return
    }
    try {
      setScanLoading(true)
      const res = await fetch('http://localhost:8000/scan-openapi', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          swagger_url: scanSwaggerUrl,
          base_url_override: scanBaseUrl || null,
          destructive_mode: destructive ? 'confirmed' : 'safe',
          include_paths: includePaths
            .split('\n')
            .map(s => s.trim())
            .filter(Boolean),
        }),
      })
      const data = await res.json()
      if (!res.ok) {
        throw new Error(typeof data.detail === 'string' ? data.detail : JSON.stringify(data.detail))
      }
      setScanReport(data)
      window.__lastScanReport = data
    } catch (err) {
      setScanError(err.message)
    } finally {
      setScanLoading(false)
    }
  }

  // Helpers para abrir/baixar relatórios HTML (escopo do componente)
  const openHtmlReportInNewTab = async () => {
    try {
      console.log('[openHtmlReportInNewTab] start')
      setReportAction('html-tech-open')
      const res = await fetch('http://localhost:8000/scan-openapi/html', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          swagger_url: scanSwaggerUrl,
          base_url_override: scanBaseUrl || null,
          destructive_mode: destructive ? 'confirmed' : 'safe',
          include_paths: includePaths
            .split('\n')
            .map(s => s.trim())
            .filter(Boolean),
        }),
      })
      const text = await res.text()
      if (!res.ok) throw new Error(text || 'Falha ao gerar HTML')
      const blob = new Blob([text], { type: 'text/html;charset=utf-8' })
      const url = URL.createObjectURL(blob)
      window.open(url, '_blank', 'noopener,noreferrer')
      setTimeout(() => URL.revokeObjectURL(url), 30000)
    } catch (err) {
      setScanError(err.message)
      console.error('[openHtmlReportInNewTab] error', err)
    }
    finally { setReportAction('') }
  }

  const downloadHtmlReport = async () => {
    try {
      console.log('[downloadHtmlReport] start')
      setReportAction('html-tech-dl')
      const res = await fetch('http://localhost:8000/scan-openapi/html', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          swagger_url: scanSwaggerUrl,
          base_url_override: scanBaseUrl || null,
          destructive_mode: destructive ? 'confirmed' : 'safe',
          include_paths: includePaths
            .split('\n')
            .map(s => s.trim())
            .filter(Boolean),
        }),
      })
      const text = await res.text()
      if (!res.ok) {
        throw new Error(text || 'Falha ao gerar HTML')
      }
      const blob = new Blob([text], { type: 'text/html;charset=utf-8' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      const ts = new Date().toISOString().replace(/[:.]/g, '-')
      a.download = `scan-report-${ts}.html`
      a.style.display = 'none'
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      setTimeout(() => URL.revokeObjectURL(url), 0)
    } catch (err) {
      setScanError(err.message)
    }
    finally { setReportAction('') }
  }

  const downloadReport = () => {
    if (!scanReport) return
    const blob = new Blob([JSON.stringify(scanReport, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'scan-report.json'
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="container">
      <h1>API Validation Service</h1>

      <section id="entenda" className="hero">
        <h2>Entenda a Ferramenta</h2>
        <p className="subtitle">Compreenda o que é, para que serve e por que tem valor.</p>
        <div className="cards">
          <div className="card">
            <h3>O que é</h3>
            <p>
              É um scanner de segurança e conformidade para APIs descritas em Swagger/OpenAPI. Você informa a URL do
              Swagger/OpenAPI (arquivo .json/.yaml ou página do Swagger UI), a aplicação carrega o spec, gera mocks
              automáticos e executa requisições em todos os endpoints, validando segurança, respostas e schemas.
              Gera um relatório resumido no front e um relatório completo em HTML/JSON para auditoria.
            </p>
          </div>
          <div className="card">
            <h3>Para que serve</h3>
            <ul>
              <li>Encontrar endpoints potencialmente expostos (2xx sem credencial ou com credencial inválida).</li>
              <li>Verificar documentação (status não documentados).</li>
              <li>Checar compatibilidade de schema (JSON fora do esperado).</li>
              <li>Exercitar cenários de autenticação para estressar a API.</li>
            </ul>
          </div>
          {/** Card 'Por que tem valor' removido conforme solicitado **/}
        </div>
        <div className="tech-doc">
          <button type="button" className="secondary" onClick={() => setShowTechDoc(!showTechDoc)}>
            {showTechDoc ? 'Ocultar Documentação Técnica' : 'Ver Documentação Técnica'}
          </button>
          {showTechDoc && (
            <div className="tech-panel">
              <h3>Documentação Técnica</h3>
              <ul>
                <li><strong>Backend:</strong> FastAPI. Endpoints: POST /scan-openapi (JSON), POST /scan-openapi/html (HTML), GET /health.</li>
                <li><strong>Scanner:</strong> Geração de mocks a partir dos schemas, cenários de autenticação: none, invalid_bearer, bearer_wrong_prefix, bearer_empty, invalid_api_key, api_key_empty.</li>
                <li><strong>Validações:</strong> exposição sem/with credencial inválida, status não documentado, validação de schema JSON.</li>
                <li><strong>Relatórios:</strong> resumo no front, download JSON/HTML completos.</li>
                <li><strong>Config:</strong> ALLOWED_SERVER_HOSTS para whitelist de domínios; Base URL deduzida do spec ou informada.</li>
              </ul>
            </div>
          )}
        </div>
      </section>
      <section id="scan" className="scan-section">
        <h2>Scan OpenAPI</h2>
        <form onSubmit={handleScan}>
          <div className="form-group">
            <label>Swagger/OpenAPI URL:</label>
            <input type="text" value={scanSwaggerUrl} onChange={(e) => setScanSwaggerUrl(e.target.value)} placeholder="https://example.com/openapi.json" required />
          </div>
          <div className="form-group">
            <label>Base URL Override (opcional):</label>
            <input type="text" value={scanBaseUrl} onChange={(e) => setScanBaseUrl(e.target.value)} placeholder="https://api.example.com" />
          </div>
          <div className="form-group">
            <label>
              <input type="checkbox" checked={destructive} onChange={(e) => setDestructive(e.target.checked)} />{' '}
              Executar Destructive Scan (Confirmado)
            </label>
            <div style={{ fontSize: '0.9rem', color: '#555', marginTop: '6px' }}>
              ATENÇÃO: este modo pode criar/alterar/excluir registros de teste. Use apenas em ambientes controlados e restrinja os paths abaixo.
            </div>
          </div>
          <div className="form-group">
            <label>Incluir paths (um por linha, glob):</label>
            <textarea rows="3" value={includePaths} onChange={(e) => setIncludePaths(e.target.value)} placeholder="/v1/objetos-wfl*&#10;/v1/**/contadores*"></textarea>
            <div style={{ fontSize: '0.9rem', color: '#555', marginTop: '6px' }}>
              Somente os paths informados serão varridos. Suporta curingas glob: <code>*</code> (segmento) e <code>**</code> (recursivo). Exemplos: <code>/v1/objetos-wfl*</code>, <code>/v1/**/contadores*</code>.
            </div>
          </div>
          <button type="submit" disabled={scanLoading}>{scanLoading ? 'Executando...' : 'Executar Scan'}</button>
        </form>
        {scanError && <div className="error">Erro no Scan: {scanError}</div>}
        {reportAction && (
          <div className="small section-muted" style={{ marginTop: 8 }}>
            {reportAction === 'html-tech-dl' && 'Gerando relatório técnico (download)...'}
            {reportAction === 'html-tech-open' && 'Abrindo relatório técnico em nova aba...'}
          </div>
        )}
        {scanReport && (
          <div className="response">
            <h3>Relatório do Scan</h3>
            {scanReport.summary && (
              <ul>
                <li><strong>Total de operações:</strong> {scanReport.summary.total_operations}</li>
                <li><strong>Potenciais exposições:</strong> {scanReport.summary.potential_exposures}</li>
                <li><strong>Acesso de fora possível?</strong> {scanReport.summary.outsider_can_access ? 'SIM' : 'NÃO'} (leituras expostas: {scanReport.summary.read_exposures || 0})</li>
                <li><strong>Ações de fora possíveis?</strong> {scanReport.summary.outsider_can_perform_actions ? 'SIM' : 'NÃO'} (operações de escrita expostas: {scanReport.summary.write_exposures || 0})</li>
                <li><strong>Status inválidos:</strong> {scanReport.summary.invalid_status}</li>
                <li><strong>Incompatibilidades de schema:</strong> {scanReport.summary.schema_mismatches}</li>
              </ul>
            )}
            <button type="button" onClick={downloadReport} disabled={!!reportAction}>Baixar JSON completo</button>
            <button type="button" onClick={downloadHtmlReport} disabled={!!reportAction} style={{ marginLeft: '8px' }}>Baixar HTML</button>
            <button type="button" onClick={openHtmlReportInNewTab} disabled={!!reportAction} style={{ marginLeft: '8px' }}>Abrir HTML</button>
          </div>
        )}
      </section>
    </div>
  )
}


export default App

