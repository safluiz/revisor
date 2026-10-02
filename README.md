# Revisor

Verifica periodicamente um site de notícias, revisa as matérias novas com o Claude e mantém
um documento de correções numa pasta do Google Drive.

- `vigia.ps1`: o verificador (roda no Windows e no Linux).
- `agendamento.ps1` e `executar-oculto.vbs`: execução a cada 2 minutos no Windows.
- `.github/workflows/vigia.yml`: execução de reserva quando o computador principal está desligado.

Configuração, regras de revisão e dados ficam fora deste repositório.
