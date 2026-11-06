# Validação desta versão

Versão 1.2.0, preparada em 6 de novembro de 2026.

## Verificado

- 70 testes automatizados aprovados: agente, validação de entradas, proteção administrativa, mudança de IP/MAC, persistência, rollback, transporte SSH, perfil de IA, perfis de fabricante, importação ZIP, download verificado, controle de portas e limites da interface. As respostas dos equipamentos nos testes são simuladas.
- Abertura real da interface Tk e navegação pelas sete telas com dados de demonstração; ativação/desativação do perfil IA; abertura da central de integrações, suas duas abas e visualização da saída de consulta. Verificação de resolução reduzida a 1024 × 700 no painel principal.
- Sintaxe dos scripts de instalação e inicialização e validação do JSON de configuração de exemplo.
- Estrutura das unidades de firewall e reconciliação pelo verificador systemd disponível.

Os testes do agente usam comandos de rede simulados. Nenhum equipamento do colégio foi acessado ou alterado.

## Pendente no ambiente de destino

Não foi executada instalação privilegiada, validação do nftables contra um kernel real, inicialização do dnsmasq nem passagem de tráfego por duas interfaces. Os executáveis de rede necessários não estavam disponíveis no ambiente de desenvolvimento.

Antes de usar com a turma, realize o teste com uma única máquina descrito em [INSTALACAO.md](INSTALACAO.md). Ele verifica DHCP, DNS, corte/restauração, exceções administrativas, reinício, IPv6, ausência de caminhos alternativos e ativação/desativação do catálogo de IA.

A política de IA usa bloqueio DNS por catálogo, sem prometer cobertura de toda inteligência artificial. Teste também que a desativação mantém os domínios manuais e que novos domínios cadastrados entram no filtro. Serviços locais, recursos em caminhos compartilhados, VPNs e DNS sobre HTTPS precisam das políticas complementares descritas em [ALCANCE.md](ALCANCE.md).

As integrações diretas precisam ser verificadas no equipamento real, com sua marca, modelo, firmware e API. A presença de um adaptador ou de leitura do inventário não valida automaticamente alterações de firewall. O alcance de cada integração está em [INTEGRACOES.md](INTEGRACOES.md).
