# Validação 0.2.1

26 de outubro de 2026.

- 37 testes automatizados: todos passaram.
- Fluxos controlados de VPN em Windows, macOS e Linux: conexão, desconexão,
  falha conhecida, estado incerto, proteção de caminhos e exclusão mútua.
- Firewall: restauração da política Windows, recuperação de reforço parcial
  macOS e propriedade de regras UFW, sem alterar o firewall do host.
- Store: recuperação da cópia anterior, preservação do arquivo inválido,
  validação do schema e persistência.
- Antivírus: saídas longas, retenção de detecções anteriores, erros de leitura,
  análise parcial e concorrência na preparação.
- Rede: fixtures de ss Linux e lsof macOS com IPv4, IPv6, LISTEN, ESTABLISHED,
  SYN_SENT e entradas inválidas.
- API nativa DPAPI Windows: ida e volta com dados de teste inofensivos;
  descrição do blob confirmada no formato exigido pelo WireGuard.
- UI: navegação, textos sem slogans, parallax do cursor, inclinação dos cartões,
  movimento reduzido e navegação de teclado, sem exceções JavaScript.
- Compilação TypeScript e Vite concluída.
- Mecanismos Windows executados: ClamAV 1.5.4, FreshClam 1.5.4, Tor 0.4.9.14.

O teste empacotado verifica uma pasta inofensiva usando as bases oficiais do
ClamAV. A preparação das bases e o teste de detecção EICAR foram executados na
versão inicial e os scripts continuam disponíveis.

O ambiente de execução é um AppContainer Windows. Consultas WMI/CIM podem
falhar por restrições da sessão; isso aparece como não verificado. Os testes
Electron usam --no-sandbox apenas dentro desse ambiente já isolado. O aplicativo
distribuído mantém o sandbox do renderer e não recebe esse parâmetro.

Não foram aplicadas regras ao firewall do computador do usuário nem ativados
túneis VPN no host. Não houve homologação nativa macOS/Linux: seus adaptadores
foram exercitados com fixtures e operações controladas. A CI para esses sistemas
está preparada, mas não foi disparada em serviço externo nesta sessão.
Não foram anunciados kill switch, ausência de vazamentos ou proteção em tempo real.


## Bloqueio do executável 0.2.0

Smart App Control bloqueou Aegis.exe pela política VerifiedAndReputableDesktop.
Os eventos 3077 e 3089 correlacionados indicaram TotalSignatureCount = 0.
Não foi comprovada uma política de organização. O executável
não passou por execução final nesta sessão. A interface e a varredura foram
exercitadas no código-fonte pelo Electron oficial de desenvolvimento. Os módulos
empacotados em app.asar foram comparados byte a byte com os módulos testados.
Nenhuma política de segurança foi alterada.

## Diagnóstico Windows em 0.2.1

Testes adicionais cobrem estados de imposição, avaliação e auditoria, VBS
configurada sem execução, HVCI em execução, acesso negado e valores desconhecidos.
As três consultas são somente de leitura e não solicitam elevação.
