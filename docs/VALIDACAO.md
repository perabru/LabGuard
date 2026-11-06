# Validação da versão 1.4.0

Publicada em 6 de novembro de 2026. Os pacotes 1.4.0 passaram no [fluxo completo do GitHub Actions](https://github.com/perabru/LabGuard/actions/runs/42258536288), associado ao commit `1573bf51aeee16e1f6de52fd9f11f7bed5b957b9`. A [versão publicada](https://github.com/perabru/LabGuard/releases/tag/v1.4.0) inclui instaladores, pacotes de servidor, autotestes e somas SHA-256.

## Evidências locais

A suíte completa de 211 testes passou localmente e no Linux CI. Os componentes desktop, de servidor, banco, administração remota, mapa e relatórios também passaram nos testes correspondentes no Windows. A cobertura inclui validação, permissões, limites, preservação de regras, falhas parciais e concessões de sincronização. Os testes usam respostas de rede simuladas; nenhum equipamento do colégio foi acessado ou alterado.

O servidor passou nos testes locais de configuração, autenticação, permissões de consulta/administração, verificação de Host/Origin, limites, estado recente do gateway e recursos estáticos. Foram verificadas operações do banco por HTTP local, revisão de registros, importação, exportação, edição com gateway indisponível e aplicação explícita em segundo plano, incluindo a preservação de regras externas. O autoteste do servidor identificou a versão 1.4.0 e os recursos empacotáveis sem iniciar Tk ou conectar a um gateway real.

O JavaScript do painel web passou na verificação de sintaxe e em testes simulados de login, permissões, cadastro, falha de conexão ao gateway e saída da sessão. Esses testes não substituem a inspeção visual em navegadores e resoluções do ambiente de destino.

A interface Tk abriu e foi verificada nas sete telas, nos diálogos de banco, administração remota, integrações e mapa, incluindo resoluções reduzidas e exportação SVG/HTML/CSV/PDF. A remoção de jogos foi simulada; nenhum programa de uma máquina do colégio foi removido. O manual de 42 páginas foi renderizado e revisado, e a versão HTML foi inspecionada em navegador.

## Pacotes publicados

| Pacote | Verificação executada no fluxo 1.4.0 |
|---|---|
| `LabGuard-Setup.exe` e `LabGuard-Portable.zip` | Compilação Windows x64, instalação silenciosa, autoteste e abertura real da janela |
| `LabGuard-Linux-amd64.deb` e `LabGuard-Linux-x86_64.tar.gz` | Compilação Linux x86_64, instalação Debian, autoteste e janela real no Xvfb |
| `LabGuard-Server-Windows.zip` | Autoteste, instalação e resposta de saúde como serviço SCM em demonstração isolada |
| `LabGuard-Server-Linux-x86_64.tar.gz` | Autoteste, instalação e resposta de saúde como serviço systemd em demonstração isolada |

A publicação foi concluída após a aprovação dos fluxos Windows e Linux. O instalador Windows foi verificado também pelo SHA-256 publicado; os testes do serviço Windows usam PowerShell 5.1, caminhos com espaços e verificação das permissões de acesso. Uma resposta HTTP 200 em `/healthz` comprova somente que o processo está ativo; não comprova comunicação com o gateway, aplicação de bloqueios ou administração de uma máquina real. A execução em demonstração não valida WinRM, SSH, certificados ou regras de firewall de um colégio.

## Pendente no ambiente de destino

Não foi executada neste ambiente a passagem de tráfego real por duas interfaces, a aplicação do nftables no kernel do laboratório ou a inicialização do dnsmasq dessa rede. Antes de usar com a turma, realize o teste com uma única máquina descrito em [INSTALACAO.md](INSTALACAO.md). Verifique DHCP, DNS, corte/restauração, exceções administrativas, reinício, IPv6 e ausência de caminhos alternativos.

Teste o [banco de sites](BANCO_DE_SITES.md) com um domínio controlado: salvar deve apenas editar o cadastro; **Aplicar lista** deve alterar a rede explicitamente. Confira ativação, desativação, exclusão, conflitos de revisão e a preservação de regras manuais ou do perfil de IA. Resultados incertos exigem revisão antes de repetir. Cada banco deve permanecer associado ao gateway correto. Faça backup do diretório de dados com o serviço parado.

A política de IA usa bloqueio DNS por catálogo, sem cobertura de toda inteligência artificial. Verifique que desativá-la mantém os domínios manuais e que novos domínios entram no filtro. Serviços locais, recursos em caminhos compartilhados, VPNs e DNS sobre HTTPS precisam das políticas complementares descritas em [ALCANCE.md](ALCANCE.md).

A [administração remota](ADMINISTRACAO_REMOTA.md) exige WinRM HTTPS ou SSH previamente habilitado e autorizado; não exige cliente LabGuard nos computadores dos alunos. Teste certificado, credenciais, escopo da conta e entrega de avisos em uma máquina de teste. O inventário pontual e os nomes de processos não comprovam uma partida. Remoções devem ser testadas somente em pacotes reconhecidos, com prévia e confirmação individual: Roblox clássico e Minecraft no Windows permanecem com remoção manual. A dependência `pywinrm` é opcional para quem executa o código-fonte e precisa de WinRM.

As integrações diretas precisam de verificação no equipamento real, com marca, modelo, firmware e API correspondentes. Um adaptador de inventário não valida alterações de firewall. Consulte [INTEGRACOES.md](INTEGRACOES.md), [SERVIDORES.md](SERVIDORES.md), [INSTALACAO_WINDOWS.md](INSTALACAO_WINDOWS.md) e [INSTALACAO_LINUX.md](INSTALACAO_LINUX.md).
