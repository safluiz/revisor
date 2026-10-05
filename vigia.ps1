# Vigia de revisão de matérias
# Roda no PC (Agendador de Tarefas, a cada 2 minutos) e, como reserva, no GitHub Actions
# quando o PC está desligado. Configuração, regras, memória e documentos ficam numa pasta
# do Google Drive (subpasta "code"), acessada por uma conta de serviço.
# Sem matéria nova, não chama o Claude (não gasta créditos).

param(
    [ValidateSet('pc', 'github')][string]$Modo = 'pc',
    [switch]$SoChecar,        # github: sai com código 10 se deve agir, 0 se não
    [switch]$SemNotificacao,
    [switch]$ForcarDoc
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$EhCore    = $PSVersionTable.PSEdition -eq 'Core'
$EhWindows = (-not $EhCore) -or $IsWindows
$Utf8      = New-Object System.Text.UTF8Encoding($false)

$PastaApp    = $PSScriptRoot
$PastaChaves = Join-Path $PastaApp 'Chaves - NAO EXCLUIR'
$ArqLog      = Join-Path $PastaApp 'log.txt'
$ArqTrava    = Join-Path $PastaApp 'trava.lock'
$PastaTmp    = [IO.Path]::GetTempPath()
$PcAusenteMin = 10      # o GitHub assume se o PC ficar este tempo sem dar sinal
$PrazoExecMin = 15      # duração máxima de uma execução (trava compartilhada)
$EuSou       = $Modo

$script:registros = New-Object System.Collections.ArrayList
function Log($msg) {
    $linha = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '  [' + $EuSou + ']  ' + $msg
    [void]$script:registros.Add($linha)
    if ($Modo -eq 'pc') {
        try {
            Add-Content -Path $ArqLog -Value $linha -Encoding UTF8
            if ((Get-Item $ArqLog).Length -gt 2MB) { Set-Content $ArqLog (Get-Content $ArqLog -Tail 3000 -Encoding UTF8) -Encoding UTF8 }
        } catch {}
    }
}

# ---------------- Segredos ----------------
function LerSegredos() {
    $s = @{}
    if ($Modo -eq 'github') {
        $s.chaveGoogle = $env:GOOGLE_KEY
        $s.tgToken = $env:TELEGRAM_TOKEN
        $s.tgChat = $env:TELEGRAM_CHAT_ID
        $s.claude = 'claude'
    } else {
        $s.chaveGoogle = [IO.File]::ReadAllText((Join-Path $PastaChaves 'google-conta-de-servico.json'))
        $arqTg = Join-Path $PastaChaves 'telegram.txt'
        if (Test-Path $arqTg) {
            foreach ($l in (Get-Content $arqTg -Encoding UTF8)) {
                if ($l -match '^\s*TOKEN\s*=\s*(\S+)') { $s.tgToken = $Matches[1] }
                if ($l -match '^\s*CHAT_ID\s*=\s*(\S+)') { $s.tgChat = $Matches[1] }
            }
        }
        $s.claude = Join-Path $env:USERPROFILE '.local\bin\claude.exe'
    }
    return $s
}

# ---------------- Google Drive ----------------
function B64U([byte[]]$b) { return [Convert]::ToBase64String($b).TrimEnd('=').Replace('+', '-').Replace('/', '_') }

function TokenGoogle($chaveJson) {
    $k = $chaveJson | ConvertFrom-Json
    $agoraU = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $cab = B64U ($Utf8.GetBytes('{"alg":"RS256","typ":"JWT"}'))
    $dados = B64U ($Utf8.GetBytes((@{ iss = $k.client_email; scope = 'https://www.googleapis.com/auth/drive'; aud = 'https://oauth2.googleapis.com/token'; iat = $agoraU; exp = $agoraU + 3600 } | ConvertTo-Json -Compress)))
    $msg = $Utf8.GetBytes("$cab.$dados")
    if ($EhWindows) {
        $der = [Convert]::FromBase64String(($k.private_key -replace '-----[^-]+-----', '' -replace '\s', ''))
        $rsa = New-Object System.Security.Cryptography.RSACng([System.Security.Cryptography.CngKey]::Import($der, [System.Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob))
        $assin = $rsa.SignData($msg, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    } else {
        $id = [guid]::NewGuid().ToString('N')
        $aChave = Join-Path $PastaTmp "$id.pem"; $aMsg = Join-Path $PastaTmp "$id.msg"; $aSig = Join-Path $PastaTmp "$id.sig"
        try {
            [IO.File]::WriteAllText($aChave, $k.private_key); [IO.File]::WriteAllBytes($aMsg, $msg)
            & openssl dgst -sha256 -sign $aChave -out $aSig $aMsg 2>$null
            $assin = [IO.File]::ReadAllBytes($aSig)
        } finally { Remove-Item $aChave, $aMsg, $aSig -Force -ErrorAction SilentlyContinue }
    }
    $r = Invoke-RestMethod -Method Post 'https://oauth2.googleapis.com/token' -Body @{ grant_type = 'urn:ietf:params:oauth:grant-type:jwt-bearer'; assertion = "$cab.$dados.$(B64U $assin)" }
    return $r.access_token
}

function NovoWc() {
    $wc = New-Object System.Net.WebClient
    $wc.Headers['Authorization'] = 'Bearer ' + $script:tokenG
    $wc.Encoding = [System.Text.Encoding]::UTF8
    return $wc
}
function DriveJson($url) { $wc = NovoWc; try { return ($wc.DownloadString($url) | ConvertFrom-Json) } finally { $wc.Dispose() } }
function DriveBaixar($id) { $wc = NovoWc; try { return $wc.DownloadData("https://www.googleapis.com/drive/v3/files/$($id)?alt=media") } finally { $wc.Dispose() } }
function DriveTexto($id) { return $Utf8.GetString((DriveBaixar $id)).TrimStart([char]0xFEFF) }
function DriveGravar($id, [byte[]]$bytes, $tipo) {
    $wc = NovoWc; $wc.Headers['Content-Type'] = $tipo
    try { [void]$wc.UploadData("https://www.googleapis.com/upload/drive/v3/files/$($id)?uploadType=media", 'PATCH', $bytes) } finally { $wc.Dispose() }
}
function DriveGravarTexto($id, $texto, $tipo = 'text/plain') { DriveGravar $id ($Utf8.GetBytes($texto)) $tipo }
function DriveFilhos($pai) {
    $q = [uri]::EscapeDataString("'$pai' in parents and trashed=false")
    $r = DriveJson "https://www.googleapis.com/drive/v3/files?q=$q&fields=files(id,name)&pageSize=200"
    $h = @{}; foreach ($f in $r.files) { $h[$f.name] = $f.id }; return $h
}

# ---------------- Utilidades ----------------
function ParaHash($o) {
    if ($null -eq $o) { return $null }
    if ($o -is [System.Management.Automation.PSCustomObject]) {
        $h = [ordered]@{}
        foreach ($p in $o.PSObject.Properties) { $h[$p.Name] = ParaHash $p.Value }
        return $h
    }
    if ($o -is [System.Collections.IEnumerable] -and $o -isnot [string]) {
        $l = New-Object System.Collections.ArrayList
        foreach ($i in $o) { [void]$l.Add((ParaHash $i)) }
        return ,$l
    }
    return $o
}

# (o PowerShell 7 converte datas ISO do JSON em DateTime automaticamente; o 5.1 mantém texto)
function DataIso($s) {
    if ($s -is [datetime]) { return $s }
    return [datetime]::Parse([string]$s, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind)
}
function DiaTexto($d) { if ($d -is [datetime]) { return $d.ToString('yyyy-MM-dd') } else { return [string]$d } }

# Trava compartilhada (controle.json no Drive): quem está executando e quando o PC deu sinal
function LerControle() {
    $t = DriveTexto $script:ids.controle
    $c = if ($t.Trim()) { ParaHash ($t | ConvertFrom-Json) } else { $null }
    if (-not $c) { $c = [ordered]@{} }
    foreach ($campo in 'pcVistoEm', 'execucao', 'registros') { if (-not $c.Contains($campo)) { $c[$campo] = $null } }
    if (-not $c.registros) { $c.registros = New-Object System.Collections.ArrayList }
    return $c
}
function GravarControle($c) { DriveGravarTexto $script:ids.controle ($c | ConvertTo-Json -Depth 6) 'application/json' }
function ExecucaoDeOutro($c) {
    return ($c.execucao -and $c.execucao.por -ne $EuSou -and (DataIso $c.execucao.ate) -gt (Get-Date))
}
function PcAtivo($c) {
    return ($c.pcVistoEm -and (DataIso $c.pcVistoEm) -gt (Get-Date).AddMinutes(-$PcAusenteMin))
}

# ---------------- Início ----------------
if ($Modo -eq 'pc') {
    if (Test-Path $ArqTrava) {
        if ((Get-Item $ArqTrava).LastWriteTime -gt (Get-Date).AddMinutes(-20)) { exit 0 }
        Remove-Item $ArqTrava -Force
    }
    Set-Content $ArqTrava $PID
}

$script:controle = $null
$temTrava = $false
try {

$seg = LerSegredos
$script:tokenG = TokenGoogle $seg.chaveGoogle

# Localiza a pasta do sistema e a pasta principal (a conta de serviço só enxerga a pasta compartilhada)
$q = [uri]::EscapeDataString("name='code' and mimeType='application/vnd.google-apps.folder' and trashed=false")
$pastaSis = (DriveJson "https://www.googleapis.com/drive/v3/files?q=$q&fields=files(id,parents)").files | Select-Object -First 1
if (-not $pastaSis) { throw 'Pasta code não encontrada no Drive.' }
$filhosSis = DriveFilhos $pastaSis.id
$script:ids = @{ controle = $filhosSis['controle.json']; estado = $filhosSis['estado.json']; config = $filhosSis['config.json']; regras = $filhosSis['regras.md']; principal = $pastaSis.parents[0] }

# ---------------- Quem trabalha agora: PC ou GitHub ----------------
$c = LerControle
if ($Modo -eq 'github') {
    if ((PcAtivo $c) -or (ExecucaoDeOutro $c)) { exit 0 }
    if ($SoChecar) { exit 10 }
} else {
    $c.pcVistoEm = (Get-Date).ToString('o')
    if (ExecucaoDeOutro $c) { GravarControle $c; exit 0 }   # GitHub terminando um trabalho: aguarda o próximo ciclo
}
$c.execucao = [ordered]@{ por = $EuSou; ate = (Get-Date).AddMinutes($PrazoExecMin).ToString('o') }
GravarControle $c
$temTrava = $true
Start-Sleep -Seconds 3
$c = LerControle
if (-not $c.execucao -or $c.execucao.por -ne $EuSou) { $temTrava = $false; exit 0 }   # o outro pegou a vez
$script:controle = $c

# ---------------- Configuração ----------------
$Cfg = ParaHash ((DriveTexto $script:ids.config) | ConvertFrom-Json)
$Base = ([string]$Cfg.site).TrimEnd('/')
$HostSite = ([uri]$Base).Host -replace '^www\.', ''
$Leitura = $Cfg.leitura   # (nome único: o PowerShell não diferencia $L de $l)
$LinksWpp = @($Cfg.gruposWhatsApp)
$Modelo = $Cfg.modelo; $Esforco = $Cfg.esforco
$EsperaMin = [double]$Cfg.esperaMinutos; $MaxPorLote = [int]$Cfg.maxPorLote
$ArqRegrasLocal = Join-Path $PastaTmp ('regras-' + [guid]::NewGuid().ToString('N') + '.md')
[IO.File]::WriteAllText($ArqRegrasLocal, (DriveTexto $script:ids.regras), $Utf8)
# Documentos: na pasta principal ou em qualquer subpasta dela (um nível)
$filhosPrincipal = DriveFilhos $script:ids.principal
$qSub = [uri]::EscapeDataString("'$($script:ids.principal)' in parents and mimeType='application/vnd.google-apps.folder' and trashed=false")
foreach ($sub in (DriveJson "https://www.googleapis.com/drive/v3/files?q=$qSub&fields=files(id,name)").files) {
    $fs = DriveFilhos $sub.id
    foreach ($k in $fs.Keys) { if (-not $filhosPrincipal.ContainsKey($k)) { $filhosPrincipal[$k] = $fs[$k] } }
}
$script:ids.documento = $filhosPrincipal[$Cfg.arquivos.documento]
$script:ids.historico = $filhosPrincipal[$Cfg.arquivos.historico]
$script:ids.ciencia   = $filhosPrincipal[$Cfg.arquivos.ciencia]

function Baixar($url) {
    $wc = New-Object System.Net.WebClient
    $wc.Encoding = [System.Text.Encoding]::UTF8
    $wc.Headers['User-Agent'] = 'Mozilla/5.0 (Revisor)'
    try { return $wc.DownloadString($url) } catch { return $null } finally { $wc.Dispose() }
}

function HtmlParaTexto($html) {
    if (-not $html) { return '' }
    $t = $html
    $t = [regex]::Replace($t, '(?is)<(script|style|blockquote|iframe|figure|ul)[^>]*>.*?</\1>', ' ')
    $t = [regex]::Replace($t, '(?i)<br\s*/?>', "`n")
    $t = [regex]::Replace($t, '(?i)</?(p|div|h\d|li)[^>]*>', "`n")
    $t = [regex]::Replace($t, '<[^>]+>', '')
    $t = [System.Net.WebUtility]::HtmlDecode($t)
    $t = $t -replace [char]0xA0, ' '
    $ignorar = @($Leitura.linhasIgnorar)
    $linhas = foreach ($l in ($t -split "`n")) {
        $l = ($l -replace '[ \t]+', ' ').Trim()
        if ($l -eq '') { continue }
        $pular = $false; foreach ($ig in $ignorar) { if ($ig -and $l.StartsWith($ig)) { $pular = $true } }
        if ($pular) { continue }
        $l
    }
    return ($linhas -join "`n")
}

function Normalizar($s) {
    if (-not $s) { return '' }
    return (($s -replace [char]0xA0, ' ') -replace '\s+', ' ').Trim()
}

function UrlMateria($cod) {
    $coluna = $cod.StartsWith('C')
    $modelo = if ($coluna) { $Leitura.urlColuna } else { $Leitura.urlNoticia }
    return $modelo.Replace('{site}', $Base).Replace('{id}', $cod.TrimStart('C'))
}

# Lê uma matéria. $cod = "25836" (notícia) ou "C2667" (coluna). Retorna $null se não existir.
function LerMateria($cod) {
    $coluna = $cod.StartsWith('C')
    $url = UrlMateria $cod
    $html = Baixar $url
    if (-not $html) { return $null }
    $ini = if ($coluna) { $html.IndexOf($Leitura.inicioColuna) } else { $html.IndexOf($Leitura.inicioNoticia) }
    if ($ini -lt 0) { return $null }
    $marcaFim = if ($coluna) { $Leitura.fimColuna } else { $Leitura.fimNoticia }
    $fim = $html.Length
    $p = $html.IndexOf($marcaFim, $ini); if ($p -gt 0) { $p = $html.LastIndexOf('<', $p) }; if ($p -gt 0 -and $p -lt $fim) { $fim = $p }
    $bloco = $html.Substring($ini, $fim - $ini)

    $mt = [regex]::Match($bloco, '(?is)<h1[^>]*>(.*?)</h1>')
    if (-not $mt.Success) { return $null }
    $titulo = Normalizar (HtmlParaTexto $mt.Groups[1].Value)
    if (-not $titulo) { return $null }
    $md = [regex]::Match($bloco, '(?is)class="' + [regex]::Escape($Leitura.classeData) + '"[^>]*>(.*?)</div>')
    $data = Normalizar (HtmlParaTexto $md.Groups[1].Value)
    $padraoLinha = '(?is)<p class="' + [regex]::Escape($Leitura.classeLinhaFina) + '"[^>]*>(.*?)</p>'
    $ml = [regex]::Match($bloco, $padraoLinha)
    $linha = if ($ml.Success) { Normalizar (HtmlParaTexto $ml.Groups[1].Value) } else { '' }

    # Corpo: tudo depois do bloco de compartilhamento/imagem
    $corpoHtml = $bloco
    $pc = $bloco.IndexOf('class="' + $Leitura.classeCompartilhar + '"')
    if ($pc -ge 0) {
        $corpoHtml = $bloco.Substring($pc)
        $pi = [regex]::Match($corpoHtml, '(?is)<img[^>]*>\s*</div>')
        if ($pi.Success) { $corpoHtml = $corpoHtml.Substring($pi.Index + $pi.Length) }
        else { $corpoHtml = [regex]::Replace($corpoHtml, '(?is)^.*?</div>', '', 1) }
    }
    $corpoHtml = [regex]::Replace($corpoHtml, $padraoLinha, '')
    $corpo = HtmlParaTexto $corpoHtml

    # Links dos "clique aqui" (chamada final do WhatsApp, "leia outras colunas" etc.)
    $ctas = New-Object System.Collections.ArrayList
    foreach ($ma in [regex]::Matches($corpoHtml, '(?is)<a\b([^>]*)>((?:(?!</?a\b).)*?)</a>')) {
        $txtA = Normalizar ([System.Net.WebUtility]::HtmlDecode(($ma.Groups[2].Value -replace '<[^>]+>', '')))
        $antes = Normalizar ([System.Net.WebUtility]::HtmlDecode((($corpoHtml.Substring([Math]::Max(0, $ma.Index - 60), [Math]::Min(60, $ma.Index))) -replace '<[^>]+>', ' ')))
        if ($txtA -match '(?i)clique aqui' -or ($txtA -match '(?i)^aqui\b' -and $antes -match '(?i)clique\s*$')) {
            $mh = [regex]::Match($ma.Groups[1].Value, '(?i)href\s*=\s*"([^"]*)"')
            [void]$ctas.Add($(if ($mh.Success) { $mh.Groups[1].Value.Trim() } else { '' }))
        }
    }
    # Defeitos visuais por parágrafo: tamanho de letra diferente ou parágrafo longo inteiro em negrito
    $visuais = New-Object System.Collections.ArrayList
    foreach ($trechoHtml in [regex]::Split($corpoHtml, '(?i)</p>|<br\s*/?>\s*<br\s*/?>')) {
        $txtSeg = Normalizar ([System.Net.WebUtility]::HtmlDecode(($trechoHtml -replace '<[^>]+>', ' ')))
        if ($txtSeg.Length -lt 20) { continue }
        $inicio = (($txtSeg -split ' ') | Select-Object -First 8) -join ' '
        if ($trechoHtml -match '(?i)font-size\s*:|<small\b|<font\b[^>]*\bsize\s*=') {
            [void]$visuais.Add([ordered]@{ trecho = $inicio; problema = 'parágrafo com tamanho de letra diferente do restante do texto (defeito visual)' })
            continue
        }
        # chamadas em negrito de propósito (para vídeo, foto, link) não são defeito
        $ehChamada = $txtSeg -match '[:：]\s*$' -or $txtSeg -match '(?i)^(confira|veja|assista|leia|saiba|clique|receba|acompanhe|ouça)\b'
        if ($txtSeg.Length -ge 60 -and -not $ehChamada) {
            $semNegrito = [regex]::Replace($trechoHtml, '(?is)<(b|strong)\b[^>]*>.*?</\1>', ' ')
            $semNegrito = [regex]::Replace($semNegrito, '(?is)<(\w+)\b[^>]*font-weight\s*:\s*(bold|bolder|[6-9]00)[^>]*>.*?</\1>', ' ')
            $resto = Normalizar ([System.Net.WebUtility]::HtmlDecode(($semNegrito -replace '<[^>]+>', ' ')))
            $pNegrito = $trechoHtml -match '(?i)^\s*<p[^>]*font-weight\s*:\s*(bold|bolder|[6-9]00)'
            if ($pNegrito -or $resto.Length -lt 5) {
                [void]$visuais.Add([ordered]@{ trecho = $inicio; problema = 'parágrafo inteiro em negrito (defeito visual)' })
            }
        }
    }
    $autor = ''
    if ($coluna -and $Leitura.regexAutorColuna) {
        $ma = [regex]::Match($html, $Leitura.regexAutorColuna)
        if ($ma.Success) { $autor = Normalizar (HtmlParaTexto $ma.Groups[1].Value) }
    }
    $link = $url
    if ($coluna) {
        $og = [regex]::Match($html, 'property="og:url" content="([^"]+)"')
        if ($og.Success) { $link = $og.Groups[1].Value -replace '(?<!:)//', '/' }
    }

    $dia = $null
    $mdia = [regex]::Match($data, '(\d{2})/(\d{2})/(\d{4})')
    if ($mdia.Success) { $dia = '{0}-{1}-{2}' -f $mdia.Groups[3].Value, $mdia.Groups[2].Value, $mdia.Groups[1].Value }

    return [ordered]@{
        cod = $cod; tipo = $(if ($coluna) { 'coluna' } else { 'noticia' }); url = $link
        titulo = $titulo; linha = $linha; corpo = $corpo; autor = $autor
        publicado = $data; diaPub = $dia; ctas = @($ctas); visuais = @($visuais)
    }
}

function TextoCompleto($m) { return (Normalizar ($m.titulo + ' ' + $m.linha + ' ' + $m.corpo)) }

function EhDoSite($url) { return ($url -match ('^https?://(www\.)?' + [regex]::Escape($HostSite) + '(/|$)')) }
function EhCapa($url) { return ($url.TrimEnd('/') -match ('^https?://(www\.)?' + [regex]::Escape($HostSite) + '$')) }

# Links do próprio site: o site pode não devolver erro para página inexistente
# (redireciona para a capa ou mostra página sem matéria), então é preciso conferir o conteúdo.
function LinkInternoOk($url, $saltos = 0) {
    try {
        $req = [System.Net.HttpWebRequest]::Create($url)
        $req.AllowAutoRedirect = $false; $req.Timeout = 20000; $req.UserAgent = 'Mozilla/5.0 (Revisor)'
        try { $resp = $req.GetResponse() } catch [System.Net.WebException] { $resp = $_.Exception.Response; if (-not $resp) { return $false } }
        $cod = [int]$resp.StatusCode; $loc = $resp.Headers['Location']
        $corpo = ''
        if ($cod -eq 200) { $sr = New-Object System.IO.StreamReader($resp.GetResponseStream(), [System.Text.Encoding]::UTF8); $corpo = $sr.ReadToEnd(); $sr.Close() }
        $resp.Close()
        if ($cod -ge 300 -and $cod -lt 400) {
            if (-not $loc -or $saltos -ge 3) { return $false }
            $dest = if ($loc -match '^https?://') { $loc } else { $Base + '/' + $loc.TrimStart('/') }
            if ((EhCapa $dest) -and -not (EhCapa $url)) { return $false }
            return (LinkInternoOk $dest ($saltos + 1))
        }
        if ($cod -ne 200) { return $false }
        if ($url -match $Leitura.regexUrlMateria) { return [bool]($corpo -match '<h1' -and $corpo -match $Leitura.regexPaginaMateria) }
        return $true
    } catch { return $false }
}

# Confere (no máximo 1 vez por hora por link) se um link abre.
# Convites do WhatsApp: precisam abrir um grupo com o nome configurado.
$script:cacheLinks = @{}
function LinkFunciona($url) {
    if ($script:cacheLinks.ContainsKey($url)) { return $script:cacheLinks[$url] }
    $ok = $false
    $reg = @($estado.wppLinks | Where-Object { $_.url -eq $url }) | Select-Object -First 1
    if ($reg -and (DataIso $reg.em) -gt (Get-Date).AddHours(-1)) { $ok = [bool]$reg.ok }
    else {
        if ($url -match 'chat\.whatsapp\.com') { $h = Baixar $url; $ok = [bool]($h -and $h -match ('og:title" content="[^"]*' + [regex]::Escape($Cfg.nomeGrupoWhatsApp))) }
        elseif (EhDoSite $url) { $ok = LinkInternoOk $url }
        else { $ok = [bool](Baixar $url) }
        $estado.wppLinks = [System.Collections.ArrayList]@(@($estado.wppLinks | Where-Object { $_.url -ne $url }) + [ordered]@{ url = $url; ok = $ok; em = (Get-Date).ToString('o') })
        if (-not $ok) { Log "Link não está funcionando: $url" }
    }
    $script:cacheLinks[$url] = $ok
    return $ok
}

# Retorna $null se os links dos "clique aqui" estiverem ok; senão, a explicação do problema.
# Matéria sem "clique aqui" não é problema.
function ProblemaWpp($m) {
    $msgs = @()
    foreach ($l in @($m.ctas)) {
        if (-not $l -or $l -eq '#') { $msgs += 'o “clique aqui” está sem link'; continue }
        $abs = if ($l -match '^https?://') { $l } elseif ($l.StartsWith('//')) { 'https:' + $l } else { $Base + '/' + $l.TrimStart('/') }
        if ($abs -match 'chat\.whatsapp\.com') {
            $base = ($abs -split '\?')[0].TrimEnd('/')
            if ($LinksWpp -notcontains $base) { $msgs += ('o “clique aqui” leva a um grupo de WhatsApp que não é do portal (' + $abs + ')') }
            elseif (-not (LinkFunciona $base)) { $msgs += ('o link do grupo de WhatsApp (' + $base + ') não está funcionando') }
        } elseif (-not (LinkFunciona $abs)) { $msgs += ('o link do “clique aqui” (' + $abs + ') não está funcionando') }
    }
    if ($msgs.Count -eq 0) { return $null }
    return ((@($msgs | Select-Object -Unique) -join '; ') + '.')
}
function AlteracaoWpp($n, $problema) {
    return [ordered]@{ n = $n; tipo = 'whatsapp'; original = ''; corrigido = ''; destaque = 'clique aqui'; explicacao = $problema; estado = 'pendente' }
}

# Defeitos visuais: uma alteração por parágrafo afetado
function AlteracoesVisuais($m, $n) {
    $lst = @()
    foreach ($v in @($m.visuais)) {
        $n++
        $lst += [ordered]@{ n = $n; tipo = 'visual'; original = ''; corrigido = ''; destaque = ($v.trecho + '...'); explicacao = $v.problema; estado = 'pendente' }
    }
    return ,$lst
}
function VisualAindaExiste($a, $m) {
    foreach ($v in @($m.visuais)) { if (($v.trecho + '...') -eq $a.destaque -and $v.problema -eq $a.explicacao) { return $true } }
    return $false
}
function CodigosDaCapa() {
    $html = Baixar $Base
    $cods = New-Object System.Collections.Generic.HashSet[string]
    if (-not $html) { return ,@() }
    $dom = [regex]::Escape($HostSite)
    foreach ($m in [regex]::Matches($html, $dom + $Leitura.regexCapaColuna)) { [void]$cods.Add('C' + $m.Groups[1].Value) }
    foreach ($m in [regex]::Matches($html, $dom + $Leitura.regexCapaNoticia)) { [void]$cods.Add($m.Groups[1].Value) }
    return ,@($cods)
}

function MaxNum($cods, [bool]$coluna) {
    $nums = @($cods | Where-Object { $_.StartsWith('C') -eq $coluna } | ForEach-Object { [int]($_.TrimStart('C')) })
    if ($nums.Count -eq 0) { return 0 }
    return ($nums | Measure-Object -Maximum).Maximum
}

# ---------------- Estado ----------------
$hoje = (Get-Date).ToString('yyyy-MM-dd')
$agora = Get-Date
$mudou = $false
$novasRevisadas = New-Object System.Collections.ArrayList

$estadoOriginal = DriveTexto $script:ids.estado
$estado = if ($estadoOriginal.Trim() -and $estadoOriginal.Trim() -ne '{}') { ParaHash ($estadoOriginal | ConvertFrom-Json) } else { $null }

function NovaEntrada($m) {
    return [ordered]@{
        cod = $m.cod; tipo = $m.tipo; url = $m.url; titulo = $m.titulo; autor = $m.autor
        publicado = $m.publicado; vistoEm = (Get-Date).ToString('o'); status = 'aguardando'
        tentativas = 0; texto = [ordered]@{ titulo = $m.titulo; linha = $m.linha; corpo = $m.corpo }
        alteracoes = (New-Object System.Collections.ArrayList); fechadaEm = $null
    }
}

if (-not $estado) {
    # Primeira execução: as matérias publicadas hoje entram para revisão; as antigas ficam como já vistas.
    Log 'Primeira execução: montando a base.'
    $estado = [ordered]@{
        dia = $hoje; maxNoticia = 0; maxColuna = 0
        vistos = (New-Object System.Collections.ArrayList)
        lacunas = (New-Object System.Collections.ArrayList)
        materias = (New-Object System.Collections.ArrayList)
        anteriores = (New-Object System.Collections.ArrayList)
        historico = (New-Object System.Collections.ArrayList)
    }
    $capa = CodigosDaCapa
    $estado.maxNoticia = MaxNum $capa $false
    $estado.maxColuna  = MaxNum $capa $true
    foreach ($tipo in @($false, $true)) {
        $id = if ($tipo) { $estado.maxColuna } else { $estado.maxNoticia }
        $faltas = 0; $antigas = 0
        while ($id -gt 0 -and $faltas -lt 5 -and $antigas -lt 3) {
            $cod = if ($tipo) { "C$id" } else { "$id" }
            $m = LerMateria $cod
            if (-not $m) { $faltas++ }
            elseif ($m.diaPub -eq $hoje) { [void]$estado.materias.Add((NovaEntrada $m)); [void]$estado.vistos.Add($cod); $faltas = 0 }
            else { $antigas++; [void]$estado.vistos.Add($cod) }
            $id--
        }
    }
    foreach ($cc in $capa) { if (-not $estado.vistos.Contains($cc)) { [void]$estado.vistos.Add($cc) } }
    foreach ($e in $estado.materias) { $e.vistoEm = $agora.AddMinutes(-10).ToString('o') }
    $mudou = $true
}
foreach ($campo in 'vistos', 'lacunas', 'materias', 'anteriores', 'historico', 'wppLinks') {
    if (-not $estado.Contains($campo) -or $null -eq $estado[$campo]) { $estado[$campo] = New-Object System.Collections.ArrayList }
}
$estado.dia = DiaTexto $estado.dia
foreach ($d in $estado.historico) { $d.dia = DiaTexto $d.dia }

# ---------------- Virada do dia ----------------
$script:gerarHistorico = $false
if ($estado.dia -ne $hoje) {
    Log "Virada do dia: $($estado.dia) -> $hoje"
    $pendAnt = New-Object System.Collections.ArrayList
    $registro = [ordered]@{ dia = $estado.dia; materias = (New-Object System.Collections.ArrayList) }
    foreach ($e in $estado.materias) {
        if ($e.status -eq 'aguardando') { [void]$pendAnt.Add($e); continue }
        [void]$registro.materias.Add($e)
        if ($e.status -eq 'pendente') { [void]$pendAnt.Add($e) }
    }
    # pendências de dois dias atrás que ainda estavam abertas saem da lista
    foreach ($e in $estado.anteriores) { if ($e.status -eq 'pendente') { $e.fechadaEm = 'nao_corrigida' } }
    [void]$estado.historico.Add($registro)
    $estado.anteriores = $pendAnt
    $estado.materias = New-Object System.Collections.ArrayList
    $estado.dia = $hoje
    $script:gerarHistorico = $true
    $mudou = $true
}

# ---------------- Descoberta de matérias novas ----------------
$candidatos = New-Object System.Collections.ArrayList
foreach ($cc in (CodigosDaCapa)) { if (-not $estado.vistos.Contains($cc)) { [void]$candidatos.Add($cc) } }
foreach ($l in @($estado.lacunas)) { [void]$candidatos.Add($l.cod) }

$lidas = @{}
foreach ($tipo in @($false, $true)) {
    $max = if ($tipo) { [int]$estado.maxColuna } else { [int]$estado.maxNoticia }
    $id = $max + 1; $faltas = 0; $buracos = New-Object System.Collections.ArrayList
    while ($faltas -lt 3) {
        $cod = if ($tipo) { "C$id" } else { "$id" }
        if ($estado.vistos.Contains($cod)) { $id++; continue }
        $m = LerMateria $cod
        if ($m) {
            $lidas[$cod] = $m
            foreach ($b in $buracos) { [void]$estado.lacunas.Add([ordered]@{ cod = $b; ate = $agora.AddDays(2).ToString('o') }) }
            $buracos.Clear(); $faltas = 0
            if ($tipo) { $estado.maxColuna = $id } else { $estado.maxNoticia = $id }
            [void]$candidatos.Add($cod)
        } else { [void]$buracos.Add($cod); $faltas++ }
        $id++
    }
}

$lacunasNovas = New-Object System.Collections.ArrayList
foreach ($l in $estado.lacunas) { if ((DataIso $l.ate) -gt $agora) { [void]$lacunasNovas.Add($l) } }
$estado.lacunas = $lacunasNovas

foreach ($cod in ($candidatos | Select-Object -Unique)) {
    if ($estado.vistos.Contains($cod)) { continue }
    $m = if ($lidas.ContainsKey($cod)) { $lidas[$cod] } else { LerMateria $cod }
    if (-not $m) { continue }
    $estado.lacunas = [System.Collections.ArrayList]@($estado.lacunas | Where-Object { $_.cod -ne $cod })
    [void]$estado.vistos.Add($cod)
    $n = [int]($cod.TrimStart('C'))
    if ($cod.StartsWith('C')) { if ($n -gt $estado.maxColuna) { $estado.maxColuna = $n } } else { if ($n -gt $estado.maxNoticia) { $estado.maxNoticia = $n } }
    # ignora matérias antigas que reapareçam
    if ($m.diaPub -and ([datetime]::ParseExact($m.diaPub, 'yyyy-MM-dd', $null)) -lt $agora.Date.AddDays(-2)) { continue }
    [void]$estado.materias.Add((NovaEntrada $m))
    Log "Nova matéria: $cod - $($m.titulo)"
    $mudou = $true
}
while ($estado.vistos.Count -gt 3000) { $estado.vistos.RemoveAt(0) }

# ---------------- Dar ciência ----------------
$ciencias = @()
if ($script:ids.ciencia) {
    $ciencias = @((DriveTexto $script:ids.ciencia) -split "`n" | ForEach-Object { ($_ -replace '\s', '').ToUpper() } | Where-Object { $_ -match '^C?\d+(-\d+)?$' })
}

function AtualizarSituacao($e, $m) {
    # retorna $true se algo mudou. $m = matéria lida agora do site ($null se não foi possível ler)
    if ($e.status -ne 'pendente') { return $false }
    $alterou = $false
    $norm = if ($m) { TextoCompleto $m } else { '' }
    foreach ($a in $e.alteracoes) {
        if ($a.estado -ne 'pendente') { continue }
        $codA = ($e.cod + '-' + $a.n).ToUpper()
        if ($ciencias -contains $e.cod.ToUpper() -or $ciencias -contains $codA) { $a.estado = 'dispensada'; $alterou = $true; continue }
        if ($a.tipo -eq 'visual') {
            if ($m -and -not (VisualAindaExiste $a $m)) { $a.estado = 'aplicada'; $alterou = $true }
            continue
        }
        if ($a.tipo -eq 'whatsapp') {
            if ($m) {
                $prob = ProblemaWpp $m
                if (-not $prob) { $a.estado = 'aplicada'; $alterou = $true }
                elseif ($prob -ne $a.explicacao) { $a.explicacao = $prob; $alterou = $true }
            }
            continue
        }
        if ($norm) {
            $orig = Normalizar $a.original; $corr = Normalizar $a.corrigido
            if (($corr -and $norm.Contains($corr)) -or ($orig -and -not $norm.Contains($orig))) { $a.estado = 'aplicada'; $alterou = $true }
        }
    }
    $abertas = @($e.alteracoes | Where-Object { $_.estado -eq 'pendente' }).Count
    if ($abertas -eq 0) {
        $dispensadas = @($e.alteracoes | Where-Object { $_.estado -eq 'dispensada' }).Count
        $e.status = if ($dispensadas -gt 0) { 'dispensada' } else { 'corrigida' }
        $e.fechadaEm = (Get-Date).ToString('o')
        Log "Matéria $($e.cod) agora sem pendências ($($e.status))."
        $alterou = $true
    }
    return $alterou
}

# ---------------- Reverificar pendências ----------------
foreach ($lista in @($estado.materias, $estado.anteriores)) {
    foreach ($e in $lista) {
        if ($e.status -ne 'pendente') { continue }
        $m = LerMateria $e.cod
        if ($m) {
            $e.texto = [ordered]@{ titulo = $m.titulo; linha = $m.linha; corpo = $m.corpo }
            $e.titulo = $m.titulo
            if (AtualizarSituacao $e $m) { $mudou = $true }
        } else {
            if (AtualizarSituacao $e $null) { $mudou = $true }
        }
    }
}

# ---------------- Revisão pelo Claude ----------------
function ArgWin($s) {
    if ($s -notmatch '[\s"]' -and $s -ne '') { return $s }
    $r = [regex]::Replace($s, '(\\*)"', '$1$1\"')
    $r = [regex]::Replace($r, '(\\+)$', '$1$1')
    return '"' + $r + '"'
}

function Revisar($entradas) {
    $payload = @{ materias = @($entradas | ForEach-Object {
        [ordered]@{ cod = $_.cod; tipo = $_.tipo; autor = $_.autor; titulo = $_.texto.titulo; linha_fina = $_.texto.linha; corpo = $_.texto.corpo }
    }) } | ConvertTo-Json -Depth 6
    $entrada = "Revise com atenção, uma a uma, as matérias abaixo. Responda somente com um JSON neste formato: {""materias"":[{""cod"":""..."",""alteracoes"":[{""original"":""..."",""corrigido"":""..."",""destaque"":""..."",""explicacao"":""...""}]}]}`n`n" + $payload

    $argsCl = @('-p', '--model', $Modelo, '--effort', $Esforco, '--tools', '', '--no-session-persistence',
                '--strict-mcp-config', '--output-format', 'json', '--system-prompt-file', $ArqRegrasLocal)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $seg.claude
    if ($EhCore) { foreach ($a in $argsCl) { $psi.ArgumentList.Add([string]$a) } }
    else { $psi.Arguments = (($argsCl | ForEach-Object { if ($_ -eq '') { '""' } else { ArgWin $_ } }) -join ' ') }
    $psi.WorkingDirectory = $PastaTmp
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
    $psi.StandardErrorEncoding = [System.Text.Encoding]::UTF8
    $p = [System.Diagnostics.Process]::Start($psi)
    $sw = New-Object System.IO.StreamWriter($p.StandardInput.BaseStream, $Utf8)
    $sw.Write($entrada); $sw.Close()
    $errTask = $p.StandardError.ReadToEndAsync()
    $saida = $p.StandardOutput.ReadToEnd()
    if (-not $p.WaitForExit(600000)) { try { $p.Kill() } catch {}; throw 'Claude demorou demais.' }
    $erro = $errTask.Result

    $res = $saida | ConvertFrom-Json
    if ($res.is_error) { throw ('Claude retornou erro: ' + $res.result + ' ' + $erro) }
    $txt = [string]$res.result
    $i = $txt.IndexOf('{'); $f = $txt.LastIndexOf('}')
    if ($i -lt 0 -or $f -le $i) { throw 'Resposta sem JSON.' }
    $obj = $txt.Substring($i, $f - $i + 1) | ConvertFrom-Json
    Log ('Revisão feita: {0} matéria(s), custo estimado US$ {1}' -f @($entradas).Count, $res.total_cost_usd)
    return (ParaHash $obj)
}

$prontas = @($estado.materias | Where-Object { $_.status -eq 'aguardando' -and (DataIso $_.vistoEm) -le $agora.AddMinutes(-$EsperaMin + 0.2) })
$prontas += @($estado.anteriores | Where-Object { $_.status -eq 'aguardando' })
$probWpp = @{}; $visPorCod = @{}
if ($prontas.Count -gt 0) {
    for ($i = 0; $i -lt $prontas.Count; $i += $MaxPorLote) {
        $lote = @($prontas[$i..([Math]::Min($i + $MaxPorLote, $prontas.Count) - 1)])
        # relê o texto atual antes de revisar
        $validas = New-Object System.Collections.ArrayList
        foreach ($e in $lote) {
            $m = LerMateria $e.cod
            if ($m) { $e.texto = [ordered]@{ titulo = $m.titulo; linha = $m.linha; corpo = $m.corpo }; $e.titulo = $m.titulo; $e.publicado = $m.publicado; $probWpp[$e.cod] = (ProblemaWpp $m); $visPorCod[$e.cod] = $m; [void]$validas.Add($e) }
        }
        if ($validas.Count -eq 0) { continue }
        try {
            $r = Revisar $validas
            foreach ($e in $validas) {
                $item = @($r.materias | Where-Object { $_.cod -eq $e.cod }) | Select-Object -First 1
                if (-not $item) { $e.tentativas++; continue }
                $lst = New-Object System.Collections.ArrayList
                $n = 0
                foreach ($a in $item.alteracoes) {
                    if ((Normalizar $a.original) -eq (Normalizar $a.corrigido)) { continue }
                    $n++
                    $dest = if ($a.destaque -and ([string]$a.corrigido).Contains([string]$a.destaque)) { $a.destaque } else { $a.corrigido }
                    [void]$lst.Add([ordered]@{ n = $n; original = $a.original; corrigido = $a.corrigido; destaque = $dest; explicacao = $a.explicacao; estado = 'pendente' })
                }
                if ($probWpp[$e.cod]) { $n++; [void]$lst.Add((AlteracaoWpp $n $probWpp[$e.cod])) }
                foreach ($av in (AlteracoesVisuais $visPorCod[$e.cod] $n)) { $n++; [void]$lst.Add($av) }
                $e.alteracoes = $lst
                $e.status = if ($lst.Count -gt 0) { 'pendente' } else { 'ok' }
                $e.revisadaEm = (Get-Date).ToString('o')
                [void]$novasRevisadas.Add($e)
                $mudou = $true
            }
        } catch {
            Log ('Falha na revisão: ' + $_.Exception.Message)
            foreach ($e in $validas) { $e.tentativas++; if ($e.tentativas -ge 6) { $e.status = 'erro'; $mudou = $true } }
        }
    }
}

# ---------------- Geração dos documentos Word ----------------
function Esc($s) { return [System.Security.SecurityElement]::Escape([string]$s) }

$script:rels = $null
function Run($t, [switch]$b, [switch]$i, $cor, $tam) {
    $rpr = ''
    if ($b) { $rpr += '<w:b/>' }
    if ($i) { $rpr += '<w:i/>' }
    if ($cor) { $rpr += "<w:color w:val=""$cor""/>" }
    if ($tam) { $rpr += "<w:sz w:val=""$tam""/>" }
    if ($rpr) { $rpr = "<w:rPr>$rpr</w:rPr>" }
    return "<w:r>$rpr<w:t xml:space=""preserve"">$(Esc $t)</w:t></w:r>"
}
function Link($t, $url, [switch]$b, $tam, $cor = '1F4E79') {
    $id = 'rId' + (100 + $script:rels.Count)
    [void]$script:rels.Add("<Relationship Id=""$id"" Type=""http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink"" Target=""$(Esc $url)"" TargetMode=""External""/>")
    $rpr = "<w:color w:val=""$cor""/>" + $(if ($b) { '<w:b/>' } else { '' }) + $(if ($tam) { "<w:sz w:val=""$tam""/>" } else { '' })
    return "<w:hyperlink r:id=""$id""><w:r><w:rPr>$rpr</w:rPr><w:t xml:space=""preserve"">$(Esc $t)</w:t></w:r></w:hyperlink>"
}
function Par($runs, $espAntes = 0, $espDepois = 120, [switch]$quebraPagina, $fundo, $recuo) {
    $ppr = "<w:spacing w:before=""$espAntes"" w:after=""$espDepois""/>"
    if ($quebraPagina) { $ppr = '<w:pageBreakBefore/>' + $ppr }
    if ($fundo) { $ppr += "<w:shd w:val=""clear"" w:color=""auto"" w:fill=""$fundo""/>" }
    if ($recuo) { $ppr += "<w:ind w:left=""$recuo""/>" }
    return "<w:p><w:pPr>$ppr</w:pPr>$($runs -join '')</w:p>"
}

# Texto com as correções pendentes aplicadas; só as palavras corrigidas (destaque) em negrito
function RunsCorrigidos($texto, $alts) {
    $s = [string]$texto
    foreach ($a in $alts) {
        $o = [string]$a.original
        if (-not $o) { continue }
        $p = $s.IndexOf($o)
        if ($p -lt 0) {
            $s2 = Normalizar $s; $o2 = Normalizar $o; $p2 = $s2.IndexOf($o2)
            if ($p2 -lt 0) { continue }
            $s = $s2; $o = $o2; $p = $p2
        }
        $corr = [string]$a.corrigido; $dest = [string]$a.destaque
        $pd = if ($dest) { $corr.IndexOf($dest) } else { -1 }
        $novo = if ($pd -ge 0) { $corr.Substring(0, $pd) + [char]1 + $dest + [char]2 + $corr.Substring($pd + $dest.Length) } else { [string][char]1 + $corr + [char]2 }
        $s = $s.Substring(0, $p) + $novo + $s.Substring($p + $o.Length)
    }
    $runs = @()
    foreach ($parte in [regex]::Split($s, "([\x01][^\x02]*[\x02])")) {
        if ($parte -eq '') { continue }
        if ($parte[0] -eq [char]1) { $runs += Run ($parte.Trim([char]1, [char]2)) -b }
        else { $runs += Run $parte }
    }
    return $runs
}

function Plural($n, $sing, $plur) { if ($n -eq 1) { return "1 $sing" } else { return "$n $plur" } }

function Secao($texto, $fundo) {
    return @((Par @() 120 60), (Par @((Run $texto -b -tam 28)) 120 60 -fundo $fundo))
}

function BlocoMateria($e, [switch]$detalhado) {
    $x = @()
    $meta = @()
    $meta += $(if ($e.tipo -eq 'coluna') { 'Coluna' + $(if ($e.autor) { ' · ' + $e.autor } else { '' }) } else { 'Notícia' })
    if ($e.publicado) { $meta += 'publicada ' + $e.publicado }
    $meta += 'cód. ' + $e.cod
    $pend = @($e.alteracoes | Where-Object { $_.estado -eq 'pendente' })
    if ($e.status -eq 'pendente' -and $detalhado) {
        $x += Par @((Run $e.titulo -b -tam 26)) 280 40
        $x += Par @((Run ('⚠️ PENDENTE  ·  ' + ($meta -join '  ·  ') + ' – ') -b -cor 'C00000' -tam 18), (Link 'Acesso aqui' $e.url -b -tam 18 -cor '77206D')) 0 160
        $x += Par (RunsCorrigidos $e.texto.titulo $pend) 0 80 -fundo 'F7F7F7' -recuo 0
        if ($e.texto.linha) { $x += Par (@(Run '') + (RunsCorrigidos $e.texto.linha $pend | ForEach-Object { $_ -replace '<w:r>(?!<w:rPr>)', '<w:r><w:rPr><w:i/></w:rPr>' })) 0 120 }
        foreach ($l in ($e.texto.corpo -split "`n")) { if ($l.Trim()) { $x += Par (RunsCorrigidos $l $pend) 0 120 } }
        $x += Par @((Run 'Alterações' -b -tam 22)) 160 60
        foreach ($a in $e.alteracoes) {
            $sit = switch ($a.estado) { 'aplicada' { '  (já corrigida)' } 'dispensada' { '  (dispensada)' } default { '' } }
            $dest = if ($a.destaque) { $a.destaque } else { $a.corrigido }
            $x += Par @((Run '. ' -b), (Run ('“' + $dest + '”') -b), (Run (' — ' + $a.explicacao)), (Run $sit -i -cor '7F7F7F')) 0 120
        }
    } else {
        $txt = switch ($e.status) {
            'aguardando' { '⏳ Em revisão...' }
            'erro'       { '❗ Não foi possível revisar automaticamente. Revise manualmente.' }
            'pendente'   { '⚠️ PENDENTE' }
            default      { '✅ Ok, sem alterações.' }
        }
        $cor = if ($e.status -in @('aguardando')) { '7F7F7F' } elseif ($e.status -in @('erro', 'pendente')) { 'C00000' } else { '2E7D32' }
        $x += Par @((Run $e.titulo -b -tam 24)) 200 20
        $x += Par @((Run $txt -b -cor $cor -tam 20), (Run ('   ' + ($meta -join '  ·  ')) -cor '7F7F7F' -tam 16)) 0 80
    }
    return $x
}

function SalvarDocx($idArquivo, $corpoXml) {
    if (-not $idArquivo) { throw 'Documento não encontrado na pasta do Drive.' }
    $doc = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><w:body>' + ($corpoXml -join '') + '<w:sectPr><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1134" w:right="1134" w:bottom="1134" w:left="1134" w:header="708" w:footer="708" w:gutter="0"/></w:sectPr></w:body></w:document>'
    $estilos = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:eastAsia="Calibri" w:cs="Calibri"/><w:sz w:val="22"/><w:lang w:val="pt-BR"/></w:rPr></w:rPrDefault><w:pPrDefault><w:pPr><w:spacing w:after="120" w:line="276" w:lineRule="auto"/></w:pPr></w:pPrDefault></w:docDefaults></w:styles>'
    $tipos = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/></Types>'
    $relsRaiz = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>'
    $relsDoc = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>' + ($script:rels -join '') + '</Relationships>'

    Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
    $tmp = Join-Path $PastaTmp ('doc-' + [guid]::NewGuid().ToString('N') + '.docx')
    try {
        $zip = [System.IO.Compression.ZipFile]::Open($tmp, 'Create')
        foreach ($par in @(@('[Content_Types].xml', $tipos), @('_rels/.rels', $relsRaiz), @('word/document.xml', $doc), @('word/styles.xml', $estilos), @('word/_rels/document.xml.rels', $relsDoc))) {
            $en = $zip.CreateEntry($par[0])
            $st = $en.Open(); $b = $Utf8.GetBytes($par[1]); $st.Write($b, 0, $b.Length); $st.Close()
        }
        $zip.Dispose()
        DriveGravar $idArquivo ([IO.File]::ReadAllBytes($tmp)) 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    } finally { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
}

function DataBr($dia) { return ([datetime]::ParseExact((DiaTexto $dia), 'yyyy-MM-dd', $null)).ToString('dd/MM/yyyy') }

function GerarDocDia() {
    $script:rels = New-Object System.Collections.ArrayList
    $x = @()
    $todas = @($estado.materias)
    $pend = @($todas | Where-Object { $_.status -in @('pendente', 'erro') })
    $resto = @($todas | Where-Object { $_.status -notin @('pendente', 'erro') })
    $x += Par @((Run ('Correções — ' + $Cfg.nome) -b -tam 36)) 0 40
    $x += Par @((Run ((DataBr $hoje) + '  ·  atualizado às ' + (Get-Date -Format "HH'h'mm")) -cor '7F7F7F' -tam 20)) 0 120
    $resumo = if ($todas.Count -eq 0) { 'Nenhuma matéria publicada hoje até agora.' }
              elseif ($pend.Count -eq 0) { (Plural $todas.Count 'matéria' 'matérias') + ' hoje  ·  nenhuma pendência' }
              else { (Plural $todas.Count 'matéria' 'matérias') + ' hoje  ·  ' + $pend.Count + ' com correção pendente' }
    $x += Par @((Run $resumo -b -cor $(if ($pend.Count) { 'C00000' } else { '2E7D32' }) -tam 24)) 0 240 -fundo $(if ($pend.Count) { 'FDECEA' } else { 'E8F5E9' })
    if ($pend.Count) {
        $x += Secao 'Pendentes' 'FAE2D5'
        foreach ($e in ($pend | Sort-Object { $_.vistoEm })) { $x += BlocoMateria $e -detalhado }
    }
    if ($resto.Count) {
        $x += Par @() 240 0
        $x += Secao 'Matérias do dia' 'D9F2D0'
        foreach ($e in ($resto | Sort-Object { $_.vistoEm } -Descending)) { $x += BlocoMateria $e }
    }
    $x += Par @() 600 0
    $x += Par @((Run 'Pendências do dia anterior' -b -tam 28)) 120 120
    $ant = @($estado.anteriores | Where-Object { $_.status -in @('pendente', 'aguardando', 'erro') })
    if ($ant.Count -eq 0) { $x += Par @((Run 'Não há pendências do dia anterior.' -b -cor '2E7D32')) }
    else { foreach ($e in $ant) { $x += BlocoMateria $e -detalhado } }
    SalvarDocx $script:ids.documento $x
}

function GerarDocHistorico() {
    $script:rels = New-Object System.Collections.ArrayList
    $x = @()
    $x += Par @((Run ('Histórico de Correções — ' + $Cfg.nome) -b -tam 36)) 0 240
    foreach ($d in (@($estado.historico) | Sort-Object { $_.dia } -Descending)) {
        $ms = @($d.materias)
        $nPend = @($ms | Where-Object { $_.alteracoes.Count -gt 0 }).Count
        $x += Par @((Run (DataBr $d.dia) -b -tam 28), (Run "   $($ms.Count) matéria(s) · $nPend com correção sugerida" -cor '7F7F7F' -tam 20)) 360 80
        foreach ($e in $ms) {
            $sit = switch ($e.status) {
                'ok'         { 'Ok, sem alterações.' }
                'corrigida'  { 'Corrigida.' }
                'dispensada' { 'Pendência dispensada (ciência).' }
                'pendente'   { 'Não corrigida até o fim do dia.' }
                'erro'       { 'Não revisada (erro).' }
                default      { $e.status }
            }
            $x += Par @((Link $e.titulo $e.url -b), (Run "  ·  cód. $($e.cod)  ·  $sit" -cor '7F7F7F' -tam 18)) 60 20
            foreach ($a in $e.alteracoes) {
                $desc = if ($a.tipo -eq 'whatsapp') { 'Link: ' + $a.explicacao } elseif ($a.tipo -eq 'visual') { 'Visual: ' + $a.destaque + ' ' + $a.explicacao } else { '"' + $a.original + '" → "' + $a.corrigido + '": ' + $a.explicacao }
                $x += Par @((Run "$($a.n). " -b -tam 18), (Run ($desc + ' [' + $a.estado + ']') -tam 18)) 0 20 -recuo 284
            }
        }
    }
    SalvarDocx $script:ids.historico $x
}

# Remove do estado as pendências antigas já encerradas
$estado.anteriores = [System.Collections.ArrayList]@($estado.anteriores | Where-Object { $_.fechadaEm -ne 'nao_corrigida' })
while ($estado.historico.Count -gt 120) { $estado.historico.RemoveAt(0) }

if ($mudou -or $ForcarDoc) {
    try { GerarDocDia } catch { Log ('Não consegui gravar o documento do dia: ' + $_.Exception.Message) }
}
if ($script:gerarHistorico -or $ForcarDoc) {
    try { GerarDocHistorico } catch { Log ('Não consegui gravar o histórico: ' + $_.Exception.Message) }
}

# ---------------- Salvar estado (antes de avisar, para nunca avisar duas vezes) ----------------
$json = $estado | ConvertTo-Json -Depth 12
if ($json -ne $estadoOriginal) { DriveGravarTexto $script:ids.estado $json 'application/json' }

# ---------------- Avisos (só quando há correção a fazer) ----------------
$comErro = @($novasRevisadas | Where-Object { $_.status -eq 'pendente' })
if ($comErro.Count -gt 0 -and -not $SemNotificacao) {
    # Notificação do Windows (só no PC)
    if ($Modo -eq 'pc' -and $EhWindows) {
        try {
            $titulo = '⚠️ ' + $Cfg.nome + ' – ' + $(if ($comErro.Count -eq 1) { '1 matéria precisa de correção' } else { "$($comErro.Count) matérias precisam de correção" })
            $corpo = ($comErro | Select-Object -First 4 | ForEach-Object { '• ' + $_.titulo }) -join "`n"
            $nomePasta = (DriveJson "https://www.googleapis.com/drive/v3/files/$($script:ids.principal)?fields=name").name
            $local = Join-Path (Join-Path 'G:\Meu Drive' $nomePasta) $Cfg.arquivos.documento
            $abrir = if (Test-Path $local) { ([System.Uri]$local).AbsoluteUri } else { "https://drive.google.com/file/d/$($script:ids.documento)/view" }
            $xmlToast = "<toast activationType=""protocol"" launch=""$(Esc $abrir)""><visual><binding template=""ToastGeneric""><text>$(Esc $titulo)</text><text>$(Esc $corpo)</text></binding></visual></toast>"
            [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
            [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
            $xd = New-Object Windows.Data.Xml.Dom.XmlDocument
            $xd.LoadXml($xmlToast)
            $appId = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
            [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($appId).Show([Windows.UI.Notifications.ToastNotification]::new($xd))
        } catch { Log ('Falha na notificação: ' + $_.Exception.Message) }
    }

    # Telegram (celular), em HTML (<b> = negrito)
    try {
        if ($seg.tgToken -and $seg.tgChat) {
            function EscTg($s) { return ([string]$s).Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;') }
            $linhas = @()
            $linhas += $(if ($comErro.Count -eq 1) { '⚠️ 1 matéria precisa de correção' } else { "⚠️ $($comErro.Count) matérias precisam de correção" })
            foreach ($e in $comErro) {
                $linhas += ''
                $linhas += ('<b>' + (EscTg $e.titulo) + '</b>')
                foreach ($a in @($e.alteracoes | Where-Object { $_.estado -eq 'pendente' })) {
                    $linhas += ''
                    $linhas += ('   – <b>“' + (EscTg $a.destaque) + '”</b>: ' + (EscTg $a.explicacao))
                }
                $linhas += ''
                $linhas += ('   ' + (EscTg $e.url))
            }
            $ok = @($novasRevisadas | Where-Object { $_.status -ne 'pendente' })
            if ($ok.Count) { $linhas += ''; $linhas += ('✅ Sem alterações: ' + $ok.Count) }
            if ($Cfg.linkFimTelegram) { $linhas += ''; $linhas += (EscTg $Cfg.linkFimTelegram) }
            $texto = ($linhas -join "`n")
            if ($texto.Length -gt 3900) { $texto = $texto.Substring(0, 3900) + "`n…" }
            $corpoTg = @{ chat_id = $seg.tgChat; text = $texto; parse_mode = 'HTML'; disable_web_page_preview = $true } | ConvertTo-Json
            Invoke-RestMethod -Method Post "https://api.telegram.org/bot$($seg.tgToken)/sendMessage" -ContentType 'application/json; charset=utf-8' -Body ([System.Text.Encoding]::UTF8.GetBytes($corpoTg)) | Out-Null
        }
    } catch { Log ('Falha no aviso do Telegram: ' + $_.Exception.Message) }
}

} catch {
    Log ('ERRO: ' + $_.Exception.Message + ' @ linha ' + $_.InvocationInfo.ScriptLineNumber)
    $script:falhou = $true; $script:msgFalha = $_.Exception.Message
} finally {
    # Libera a trava compartilhada e guarda os registros desta execução
    if ($temTrava -and $script:ids -and $script:ids.controle) {
        try {
            $c = LerControle
            if ($c.execucao -and $c.execucao.por -eq $EuSou) { $c.execucao = $null }
            # Alarme: 3 falhas seguidas geram um aviso no Telegram (uma vez só, até voltar a funcionar)
            $c['falhasSeguidas'] = $(if ($script:falhou) { [int]$c.falhasSeguidas + 1 } else { 0 })
            if ($c.falhasSeguidas -eq 3 -and $seg -and $seg.tgToken -and $seg.tgChat) {
                try {
                    $txtAlarme = '❗ O revisor automático está falhando (' + $EuSou + ') há 3 verificações seguidas. As matérias novas não estão sendo revisadas. Erro: ' + $script:msgFalha
                    $corpoAl = @{ chat_id = $seg.tgChat; text = $txtAlarme } | ConvertTo-Json
                    Invoke-RestMethod -Method Post "https://api.telegram.org/bot$($seg.tgToken)/sendMessage" -ContentType 'application/json; charset=utf-8' -Body ([System.Text.Encoding]::UTF8.GetBytes($corpoAl)) | Out-Null
                } catch {}
            }
            if ($Modo -eq 'pc') { $c.pcVistoEm = (Get-Date).ToString('o') } else { $c['githubVistoEm'] = (Get-Date).ToString('o') }
            foreach ($r in $script:registros) { [void]$c.registros.Add($r) }
            while ($c.registros.Count -gt 300) { $c.registros.RemoveAt(0) }
            GravarControle $c
        } catch {}
    }
    if ($ArqRegrasLocal) { Remove-Item $ArqRegrasLocal -Force -ErrorAction SilentlyContinue }
    if ($Modo -eq 'pc') { Remove-Item $ArqTrava -Force -ErrorAction SilentlyContinue }
}
