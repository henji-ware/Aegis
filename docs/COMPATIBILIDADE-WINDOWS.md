# Compatibilidade com o controle de aplicativos do Windows

## Resultado da investigação

No ambiente de teste, o Windows impediu a execução do pacote Aegis.exe.
A leitura dos eventos CodeIntegrity encontrou:

- Evento 3077: execução bloqueada pela política VerifiedAndReputableDesktop.
- Evento 3089, com o mesmo ActivityID: TotalSignatureCount = 0.
- Smart App Control em modo de imposição, confirmado pelo estado de registro 1.

A assinatura Authenticode do executável também foi consultada: NotSigned.
O nome da política identifica o Smart App Control. A mensagem genérica de
Device Guard não permite concluir, sozinha, que o computador seja gerenciado
por uma organização. VBS, HVCI e controle de aplicativos são recursos distintos.

A atualização 0.2.1 adiciona consultas de configuração ao diagnóstico dentro
do aplicativo. Ela continua sem assinatura digital e não resolve a confiança
do executável antes da inicialização. Uma alteração na interface não corrige
uma decisão de bloqueio do sistema operacional.

## Consultas do aplicativo

O diagnóstico usa Get-ItemProperty para ler VerifiedAndReputablePolicyState e
Get-CimInstance Win32_DeviceGuard para consultar VBS, HVCI em execução e
UsermodeCodeIntegrityPolicyEnforcementStatus. Ele não altera políticas, não
instala certificados e não solicita elevação para essas consultas.

Acesso negado e propriedades ausentes são apresentados como não verificados.
VBS configurada sem execução não é apresentada como proteção em execução.
Smart App Control em avaliação não é apresentado como bloqueio em imposição.
Uma observação positiva de controle de aplicativos não garante que um arquivo
específico poderá ser iniciado, nem representa um certificado de segurança.

## Distribuição futura

Uma release precisa de procedência verificável, processo de compilação e teste
de compatibilidade em máquinas com as políticas pretendidas. Assinatura digital
confiável pode ajudar a estabelecer confiança; não é garantia de aprovação por
toda política ou configuração. Não distribua chaves de assinatura no repositório.

## Referências

- [Microsoft: modo e teste de Smart App Control](https://learn.microsoft.com/en-us/windows/apps/develop/smart-app-control/test-your-app-with-smart-app-control)
- [Microsoft: eventos e diagnóstico do controle de aplicativos](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/appcontrol-debugging-and-troubleshooting)
- [Microsoft: VBS e integridade da memória](https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity)
- [SignPath Foundation](https://signpath.org/)
