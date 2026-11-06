# Validação da versão 1.4.0

Preparada em 6 de novembro de 2026. A compilação e a validação dos pacotes 1.4.0 no GitHub Actions ainda estão pendentes. Este documento não declara aprovados os novos instaladores ou serviços nativos nas plataformas de destino.

## Evidências locais

A suíte automatizada local está em expansão para cobrir o dashboard, o gateway, os transportes administrativos, o banco de sites e a administração remota. Os testes usam respostas de rede simuladas; nenhum equipamento do colégio foi acessado ou alterado.

O servidor passou nos testes locais de configuração, autenticação, permissões de consulta/administração, verificação de Host/Origin, limites, estado recente do gateway e recursos estáticos. Foram verificadas operações do banco por HTTP local, revisão de registros, importação, exportação, edição com gateway indisponível e aplicação explícita em segundo plano, incluindo a preservação de regras externas. O autoteste do servidor identificou a versão 1.4.0 e os recursos empacotáveis sem iniciar Tk ou conectar a um gateway real.

O JavaScript do painel web passou na verificação de sintaxe e em testes simulados de login, permissões, cadastro, falha de conexão ao gateway e saída da sessão. Esses testes não substituem a inspeção visual em navegadores e resoluções do ambiente de destino.

As verificações anteriores da interface Tk em demonstração, das unidades systemd e dos scripts de instalação não comprovam a integração com todos os novos recursos ou com sistemas operacionais instalados no laboratório. O estado atualizado de cada pacote depende do fluxo correspondente no GitHub Actions.

## Pacotes em validação

| Pacote | Verificação prevista no fluxo 1.4.0 |
|---|---|
| `LabGuard-Setup.exe` e `LabGuard-Portable.zip` | Compilação Windows x64, instalação silenciosa, autoteste e abertura real da janela |
| `LabGuard-Linux-amd64.deb` e `LabGuard-Linux-x86_64.tar.gz` | Compilação Linux x86_64, instalação Debian, autoteste e janela real no Xvfb |
| `LabGuard-Server-Windows.zip` | Autoteste, instalação e resposta de saúde como serviço SCM em demonstração isolada |
| `LabGuard-Server-Linux-x86_64.tar.gz` | Autoteste, instalação e resposta de saúde como serviço systemd em demonstração isolada |

A publicação depende da aprovação dos fluxos Windows e Linux. Uma resposta HTTP 200 em `/healthz` comprova somente que o processo está ativo; não comprova comunicação com o gateway, aplicação de bloqueios ou administração de uma máquina real. A execução em demonstração não valida WinRM, SSH, certificados ou regras de firewall de um colégio.

## Pendente no ambiente de destino

Não foi executada neste ambiente a passagem de tráfego real por duas interfaces, a aplicação do nftables no kernel do laboratório ou a inicialização do dnsmasq dessa rede. Antes de usar com a turma, realize o teste com uma única máquina descrito em [INSTALACAO.md](INSTALACAO.md). Verifique DHCP, DNS, corte/restauração, exceções administrativas, reinício, IPv6 e ausência de caminhos alternativos.

Teste o [banco de sites](BANCO_DE_SITES.md) com um domínio controlado: salvar deve apenas editar o cadastro; **Aplicar lista** deve alterar a rede explicitamente. Confira ativação, desativação, exclusão, conflitos de revisão e a preservação de regras manuais ou do perfil de IA. Resultados incertos exigem revisão antes de repetir. Cada banco deve permanecer associado ao gateway correto. Faça backup do diretório de dados com o serviço parado.

A política de IA usa bloqueio DNS por catálogo, sem cobertura de toda inteligência artificial. Verifique que desativá-la mantém os domínios manuais e que novos domínios entram no filtro. Serviços locais, recursos em caminhos compartilhados, VPNs e DNS sobre HTTPS precisam das políticas complementares descritas em [ALCANCE.md](ALCANCE.md).

A [administração remota](ADMINISTRACAO_REMOTA.md) exige WinRM HTTPS ou SSH previamente habilitado e autorizado; não exige cliente LabGuard nos computadores dos alunos. Teste certificado, credenciais, escopo da conta e entrega de avisos em uma máquina de teste. O inventário pontual e os nomes de processos não comprovam uma partida. Remoções devem ser testadas somente em pacotes reconhecidos, com prévia e confirmação individual: Roblox clássico e Minecraft no Windows permanecem com remoção manual. A dependência `pywinrm` é opcional para quem executa o código-fonte e precisa de WinRM.

As integrações diretas precisam de verificação no equipamento real, com marca, modelo, firmware e API correspondentes. Um adaptador de inventário não valida alterações de firewall. Consulte [INTEGRACOES.md](INTEGRACOES.md), [SERVIDORES.md](SERVIDORES.md), [INSTALACAO_WINDOWS.md](INSTALACAO_WINDOWS.md) e [INSTALACAO_LINUX.md](INSTALACAO_LINUX.md).
