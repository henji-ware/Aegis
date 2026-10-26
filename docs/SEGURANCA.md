# Modelo de segurança e pontos de revisão

## Fronteiras de confiança

O renderer tem sandbox, contextIsolation e nodeIntegration desativado.
O preload expõe uma lista fixa de métodos, sem API genérica de execução.
O processo principal valida remetente, método, tamanho de payload e valores.
A navegação e a abertura de novas janelas são bloqueadas; sites oficiais abrem
no navegador externo por identificadores de uma lista fixa.

O main tem permissões do usuário. Tarefas administrativas são operações fixas,
com revisão em diálogo nativo e elevação pelo sistema. O app inteiro não pede
para executar como administrador. Nenhum comando é recebido de uma página web,
e perfis WireGuard não podem conter hooks de shell.

## Dados e mecanismos

ClamAV e FreshClam são processos separados, com argumentos em lista. Detecções
são apresentadas; não há remoção automática, upload, exclusão ou desativação de
outro antivírus. As bases oficiais são verificadas pelo próprio FreshClam.
UnRAR é excluído do pacote por ter licença restritiva.

Tor é cliente, não relay. O SOCKS só escuta em loopback, em porta exclusiva.
A configuração e os dados do Aegis são isolados da instalação Tor do usuário.
Uma inicialização em 100% não transforma o sistema inteiro em um ambiente anônimo.

VPN: chaves persistidas são criptografadas usando o cofre do sistema.
A opção basic_text do Linux é rejeitada. Os metadados públicos não contêm chaves.
No Windows, a configuração de serviço usa DPAPI LocalMachine no diretório privado
do usuário; em Unix o wg-quick exige um arquivo 0600 durante a conexão.
A pasta de dados deve permanecer privada e não deve ser sincronizada/publicada.

## Pontos que ainda exigem validação em VM

- Reforço e restauração com falhas intermediárias, UAC/PolicyKit cancelado e GPO.
- Túnel WireGuard com servidor de teste, reinício, falha de handshake, DNS e IPv6.
- Detecção e estado real da interface utun no macOS.
- Dylibs e assinatura de binários no macOS e dependências de distribuição Linux.
- Recuperação após interrupção de energia durante gravação do estado.
- Revisão independente do IPC, permissões e distribuição de mecanismos.

Este projeto demonstra integrações e decisões de segurança. Não passou por uma
auditoria independente e não deve ser apresentado como proteção certificada.

