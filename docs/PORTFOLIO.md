# Como apresentar o Aegis

O Aegis é um projeto pessoal. Apresente-o como experiência de desenvolvimento
e estudo de segurança, com os limites da versão visíveis.

## Demonstração em 3 minutos

1. Mostre o painel 3D e navegue até Diagnóstico.
2. Execute uma auditoria e explique um resultado não verificado: falta de
   evidência não significa segurança.
3. Mostre o ClamAV independente, a atualização de assinaturas e uma varredura
   personalizada em uma pasta de teste sem informações pessoais.
4. Abra o histórico e exporte o relatório.
5. Explique a separação entre interface isolada e comandos administrativos,
   a validação de perfis WireGuard e o alcance do proxy Tor.

Não altere o firewall de uma máquina de produção para uma demonstração.
Use uma VM com snapshot para testar bloqueios, restauração e VPN.

## Texto de currículo — use apenas após compreender e reproduzir

Desenvolvi o Aegis, central desktop de segurança em Electron, React e Three.js,
com integração ao ClamAV, diagnóstico local, controle de firewall, gerenciamento
de perfis WireGuard e proxy Tor. Implementei isolamento da interface, validação
de operações nativas, proteção de chaves com o cofre do sistema, relatórios e
histórico de auditorias.

Se o projeto foi feito com assistência de IA, seja transparente sobre isso.
Demonstre que consegue explicar, testar e manter o código.

## Melhorias que demonstram evolução

- Exercitar aplicação e rollback em VMs, incluindo falhas intermediárias.
- Testar binários nativos no macOS e Linux, com cobertura por plataforma.
- Testar rotas, handshake, IPv6 e DNS antes de oferecer um kill switch.
- Evoluir o antivírus com clamd e fila de tarefas, mantendo o estado real.
- Criar testes de integração para elevação sem usar o host do desenvolvedor.
- Publicar releases reproduzíveis com fontes/licenças dos componentes.
- Revisar acessibilidade com teclado e leitor de tela.

