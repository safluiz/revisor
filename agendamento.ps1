# Liga, pausa ou remove o agendamento do vigia.
# Uso (no PowerShell):
#   .\agendamento.ps1 ligar     -> cria/ativa a tarefa (a cada 2 minutos, 24h por dia)
#   .\agendamento.ps1 pausar    -> desativa sem apagar
#   .\agendamento.ps1 retomar   -> reativa
#   .\agendamento.ps1 remover   -> apaga a tarefa
#   .\agendamento.ps1 status    -> mostra a situação
param([ValidateSet('ligar', 'pausar', 'retomar', 'remover', 'status')][string]$acao = 'status')

$Nome = 'Revisor'
$Vbs = Join-Path $PSScriptRoot 'executar-oculto.vbs'

switch ($acao) {
    'ligar' {
        $acaoTarefa = New-ScheduledTaskAction -Execute 'wscript.exe' -Argument "`"$Vbs`"" -WorkingDirectory $PSScriptRoot
        $gatilho = New-ScheduledTaskTrigger -Once -At (Get-Date).Date -RepetitionInterval (New-TimeSpan -Minutes 2)
        $config = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                    -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 30)
        $quem = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Limited
        Register-ScheduledTask -TaskName $Nome -Action $acaoTarefa -Trigger $gatilho -Settings $config -Principal $quem `
            -Description 'Verifica o site a cada 2 minutos e revisa matérias novas.' -Force | Out-Null
        Write-Host 'Agendamento ligado: verificação a cada 2 minutos.'
    }
    'pausar'  { Disable-ScheduledTask -TaskName $Nome | Out-Null; Write-Host 'Agendamento pausado.' }
    'retomar' { Enable-ScheduledTask -TaskName $Nome | Out-Null; Write-Host 'Agendamento retomado.' }
    'remover' { Unregister-ScheduledTask -TaskName $Nome -Confirm:$false; Write-Host 'Agendamento removido.' }
    'status'  {
        $t = Get-ScheduledTask -TaskName $Nome -ErrorAction SilentlyContinue
        if (-not $t) { Write-Host 'Agendamento não existe.'; break }
        $i = $t | Get-ScheduledTaskInfo
        Write-Host "Situação: $($t.State)  |  Última execução: $($i.LastRunTime)  |  Próxima: $($i.NextRunTime)"
    }
}
