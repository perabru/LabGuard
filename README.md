# LabGuard 1.4.0

Interface gráfica em Python para administrar o acesso à internet de um laboratório escolar. O painel abre em **demonstração identificada**, com dados fictícios, sem alterar a rede.

Identidade visual em roxo, azul e amarelo, com cards arredondados, botões visuais e atalhos para as tarefas do laboratório.

[Site promocional](https://perabru.github.io/LabGuard/) · [Versões e downloads](https://github.com/perabru/LabGuard/releases) · [Windows](docs/INSTALACAO_WINDOWS.md) · [Linux](docs/INSTALACAO_LINUX.md) · [Servidores](docs/SERVIDORES.md)

A versão 1.4.0 está em validação. Os pacotes desta versão serão disponibilizados após a conclusão do fluxo de compilação e testes; consulte o estado em [VALIDACAO.md](docs/VALIDACAO.md).

[Manual completo](docs/MANUAL_DO_USUARIO.html) · [Manual em PDF](docs/Manual_LabGuard_1.4.pdf) · [Mapa, IP e MAC](docs/REGRAS_IP_MAC.md)

![Painel do LabGuard com dados fictícios de demonstração](website/assets/app-preview.png)

Na operação completa, um gateway Linux dedicado aplica as regras entre o roteador e as máquinas. Essa estrutura funciona com um TP-Link comum porque o gateway controla o tráfego. As integrações diretas com equipamentos TP-Link, Cisco ou fornecidos pela Embratel dependem do modelo, firmware e API disponíveis; cada adaptador informa as operações que suporta. Consulte [integrações e compatibilidade](docs/INTEGRACOES.md).

## O que está incluído

| Recurso | Funcionamento |
|---|---|
| Mapa e relatórios | Mapa lógico de LAN/Wi-Fi, ações independentes por IP/MAC e exportação SVG, HTML, CSV e PDF |
| Máquinas observadas | Junta concessões DHCP e vizinhos de rede, com IP, MAC e nome disponível |
| Cortar/restaurar internet | Regra de encaminhamento por máquina; endereços de administração protegidos |
| Mudanças de IP | O gateway atualiza periodicamente a associação IP/MAC, mesmo com o painel fechado |
| Bloquear sites | Lista de domínios e subdomínios aplicada ao DNS de todo o laboratório |
| Bloquear serviços de IA | Controle global para ativar/desativar o catálogo de domínios de IA, preservando a lista manual |
| Novos domínios | Cadastro e remoção pela interface; não depende de recompilar o programa |
| Banco de sites | SQLite local, categorias Jogos/IA/Adultos/Outros, busca, ativação individual, notas, importação e exportação |
| Aplicar lista | Ação explícita em lotes; preserva regras manuais preexistentes e regras do perfil de IA |
| Histórico DNS | Consultas por IP, filtro por máquina e exportação CSV |
| Conexões | IP de destino, protocolo, porta e estado disponibilizados pelo conntrack |
| Auditoria | Registro das alterações efetuadas pelo painel |
| Acesso ao gateway | OpenSSH com chave, host previamente verificado e comando remoto limitado |
| Administração remota no desktop | Inventário pontual de jogos reconhecidos, avisos e remoção de pacotes suportados por WinRM HTTPS ou SSH já autorizados |
| Servidor administrativo | Serviço sem Tk no Windows/Linux, com painel web local e credenciais de consulta/administração separadas |

O [banco de sites](docs/BANCO_DE_SITES.md) guarda a política desejada. Editar o cadastro não altera a rede: use **Aplicar lista** e confira o resultado. Cada banco fica vinculado a um gateway na primeira sincronização.

## Escolher o pacote

| Plataforma | Pacote da versão 1.4.0 | Uso |
|---|---|---|
| Windows x64 | `LabGuard-Setup.exe` ou `LabGuard-Portable.zip` | Painel gráfico para o professor |
| Linux x86_64 | `LabGuard-Linux-amd64.deb` ou `LabGuard-Linux-x86_64.tar.gz` | Painel gráfico; veja a matriz de distribuições no guia Linux |
| Windows Server x64 | `LabGuard-Server-Windows.zip` | Serviço nativo LocalService e painel web local |
| Linux Server x86_64 | `LabGuard-Server-Linux-x86_64.tar.gz` | Serviço systemd e painel web local |

Os pacotes incluem o runtime Python. Compare o arquivo baixado com `SHA256SUMS.txt` da mesma versão. A disponibilidade e a validação dos pacotes dependem da publicação correspondente na [página de versões](https://github.com/perabru/LabGuard/releases).

## Instalar no Windows

Baixe `LabGuard-Setup.exe` na página de versões. O instalador inclui o Python e os recursos do painel; não é necessário instalar Python separadamente. Ele cria atalhos e oferece desinstalação. A versão portátil está em `LabGuard-Portable.zip`.

O instalador do painel não configura o gateway nem habilita automaticamente o acesso administrativo aos roteadores. Consulte [as instruções de instalação e uso no Windows](docs/INSTALACAO_WINDOWS.md).

## Instalar no Linux ou em servidores

No Ubuntu/Debian compatível, instale o painel com `sudo apt install ./LabGuard-Linux-amd64.deb`. O portátil precisa de ambiente gráfico X11/XWayland e deve ser extraído inteiro. Consulte [INSTALACAO_LINUX.md](docs/INSTALACAO_LINUX.md).

Para máquinas sem desktop, use o pacote de servidor correspondente. Os instaladores registram o serviço, mas a operação real exige configurar primeiro a conexão SSH ao gateway. O painel web escuta apenas em `127.0.0.1`; acesso remoto deve usar um túnel administrativo autenticado. O servidor Windows administra o gateway existente e não instala um firewall DNS nativo. Veja [SERVIDORES.md](docs/SERVIDORES.md).

## Executar pelo código-fonte

Instale Python 3.10 ou superior com Tcl/Tk. No Windows, abra `iniciar.bat`; no Linux, execute:

```bash
python3 main.py
```

No Debian/Ubuntu, caso o módulo Tk não esteja instalado:

```bash
sudo apt install python3-tk
```

O painel e o gateway usam a biblioteca padrão do Python. A conexão real também exige o cliente OpenSSH (`ssh`) no computador do professor. No Windows ele pode ser habilitado em Recursos opcionais → Cliente OpenSSH.

A administração remota de computadores Windows é opcional e usa `pywinrm` na máquina que executa o painel. Para habilitá-la ao executar pelo código-fonte:

```bash
python3 -m pip install -r requirements.txt
```

Essa dependência não é necessária para o filtro do gateway, para o banco de sites ou para a administração Linux por SSH. Os pacotes desktop compilados incluem os recursos necessários ao acesso WinRM; não instale Python nem um cliente LabGuard nas máquinas dos alunos.

Para executar o servidor pelo código-fonte, use `python3 server_main.py init --directory CAMINHO_PRIVADO` e siga a configuração em [SERVIDORES.md](docs/SERVIDORES.md). O modo real recusa iniciar sem gateway configurado; demonstração exige `--demo` explícito.

## Colocar em operação

Leia [o guia de instalação](docs/INSTALACAO.md). É necessário um computador Linux dedicado com duas interfaces de rede e uma sub-rede isolada para o laboratório. **Instalar somente o painel no Windows não permite cortar a internet dos outros computadores.**

A instalação deve começar com uma única máquina de teste. Depois de verificar DHCP, DNS, bloqueio e restauração, conecte as demais máquinas.

O bloqueio por catálogo de IA começa **desativado no gateway**. Ative-o pelo painel para aplicá-lo ao laboratório inteiro. A lista cobre os serviços cadastrados e pode receber novos domínios; ela não identifica toda IA incorporada em sites ou executada localmente.

## Administrar uma máquina sem instalar cliente

No painel desktop, selecione uma máquina e abra **Administração remota**. O Windows exige WinRM HTTPS previamente habilitado, certificado validado e conta autorizada; o Linux exige SSH já configurado, chave e `known_hosts` verificado. O programa não habilita esses serviços nem cria permissões nos computadores. Consulte [ADMINISTRACAO_REMOTA.md](docs/ADMINISTRACAO_REMOTA.md).

O inventário mostra somente processos e instalações reconhecidos pelo catálogo. Um launcher aberto não comprova uma partida. Avisos dependem da sessão remota e dos recursos disponíveis no sistema; consultas DNS são sinais de política, sem provar o que o aluno viu.

A remoção exige prévia recente, confirmação individual e nova verificação da identidade do pacote. Roblox da Microsoft Store pode ser removido quando a assinatura e o publicador correspondem ao catálogo. **Roblox clássico e Minecraft no Windows exigem remoção manual**; mundos e dados devem ser preservados conforme a política do colégio. No Linux, somente pacotes Debian/Flatpak explicitamente reconhecidos e autorizados permitem remoção. O programa não executa desinstaladores arbitrários nem apaga pastas pessoais por comandos próprios.

## Roteadores, switches e novos fabricantes

Use **Roteadores / switches** no menu lateral para abrir a central de integrações diretas. Ela oferece perfis com capacidades explícitas para Cisco IOS/IOS XE, TP-Link JetStream compatível, MikroTik RouterOS 7 e OpenWrt. Os perfis de consulta e os de controle de portas são identificados na própria central; não há promessa de suporte universal por marca.

Também é possível importar um perfil declarativo JSON/ZIP ou baixar um perfil por HTTPS com SHA-256 obrigatório. Não são executados instaladores, código Python ou dependências vindas de perfis. Equipamentos da Embratel exigem identificar o fabricante e modelo reais. Consulte [o guia de integrações](docs/INTEGRACOES.md) antes de operar uma porta.

## Entenda os dados

Uma consulta DNS pode vir de uma página, aplicativo ou serviço em segundo plano. Ela não comprova uma visita, não apresenta a URL completa e não mostra conteúdo HTTPS. O inventário reúne máquinas observadas, sem prometer detectar todos os equipamentos fisicamente conectados. Consulte [alcance e limitações](docs/ALCANCE.md).

## Verificação do código

```bash
python3 -m unittest discover -s tests -v
```

Os testes automatizados verificam validações e comportamento usando simulação. A validação de tráfego real precisa ser feita na topologia do laboratório, conforme o guia.

## Estrutura

| Caminho | Conteúdo |
|---|---|
| `main.py` | Inicia a interface |
| `server_main.py` | Inicia ou configura o servidor sem Tk |
| `labguard/` | Interface, demonstração, transporte SSH, banco de sites e administração remota |
| `server/` | Painel web local, instaladores de serviço e unidade systemd |
| `gateway/agent.py` | Aplicação das regras e coleta no Linux |
| `gateway/ai_services.json` | Catálogo de domínios usado pela política de IA |
| `gateway/install.sh` | Instalador do gateway Debian/Ubuntu |
| `gateway/config.example.json` | Modelo de configuração a adaptar |
| `docs/` | Instalação, operação, limites e recuperação |
| `tests/` | Testes automatizados sem alterar a rede |
| `website/` | Site promocional estático publicado no GitHub Pages |
| `packaging/` e `scripts/build_*` | Instaladores e compilação desktop/servidor Windows e Linux |
