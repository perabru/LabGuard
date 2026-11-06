# Instalar o LabGuard 2.0 no Windows

## Instalar e abrir

1. Baixe `LabGuard-Setup.exe` na [página de versões](https://github.com/perabru/LabGuard/releases/latest).
2. Execute o instalador. Ele instala o painel na pasta de programas do usuário, cria uma opção no menu Iniciar e permite criar um atalho na área de trabalho.
3. Abra o LabGuard. O desktop começa em **observação local da rede**. A demonstração com dados fictícios precisa ser selecionada explicitamente.

O instalador inclui o runtime Python, os componentes gráficos e a geração de relatórios. Não é necessário instalar Python para usar o painel. A instalação dos arquivos do desktop não exige privilégios de administrador e não aplica regras em equipamentos externos.

O painel é para Windows 10/11 x64, incluindo instalações de Windows Server com Desktop Experience compatível. Para um servidor sem desktop, existe um pacote separado. Não há assinatura de código comercial nesta versão; confira a origem do download e o SHA-256 publicado.

## Observar e conectar um equipamento

A observação local usa as informações que o Windows disponibiliza, como interfaces, rotas e vizinhos de rede. Ela não fornece um inventário completo de toda a escola nem prova que um endereço está conectado neste instante. Observar a rede não concede permissão para alterar um roteador.

Para controlar a rede, configure no painel uma conexão direta com um equipamento compatível. O adaptador direto exige **RouterOS 7 com REST por HTTPS**, serviço `www-ssl` habilitado e certificado TLS validável. A porta padrão é 443. Informe o endereço, usuário e senha de uma conta autorizada; se a rede utiliza uma autoridade certificadora própria, selecione o arquivo dessa CA. Não desative a verificação TLS. Use as permissões necessárias às funções escolhidas e valide primeiro em um equipamento ou estação de teste.

Esse acesso direto não exige OpenSSH nem a API binária RouterOS da porta 8729. O Cliente OpenSSH do Windows é usado somente pelas integrações SSH opcionais e pode ser habilitado em Configurações → Recursos opcionais.

O desktop não exige a instalação de um gateway Linux adicional. Bloquear sites ou endereços depende das funções efetivamente suportadas pelo equipamento conectado e do caminho do tráfego. Controle direto não significa compatibilidade universal com todos os modelos de uma marca. As demais integrações continuam apresentando seus recursos próprios; consulte [INTEGRACOES.md](INTEGRACOES.md).

O bloqueio de domínios exige que as consultas DNS dos clientes sejam tratadas pela infraestrutura configurada. VPN, DNS externo/criptografado, NAT intermediário e MAC privado podem limitar o alcance ou a identificação. O estado informado no painel deve ser conferido no equipamento antes de expandir uma política.

## Pacote portátil

`LabGuard-Portable.zip` contém a pasta `LabGuard`. Extraia a pasta inteira e abra `LabGuard.exe`. Mantenha `_internal` e os demais arquivos junto ao executável. O modo inicial é o mesmo do instalador: observação local, sem aplicar bloqueios automaticamente.

## Servidor Windows opcional

`LabGuard-Server-Windows.zip` contém `LabGuardServer.exe`, seu runtime e os scripts de instalação. Esta edição oferece administração por painel web local e pode iniciar com o Windows sob uma conta de serviço restrita. Ela não é necessária para usar o desktop com conexão direta.

Extraia todo o pacote. Em PowerShell elevado, na pasta `LabGuardServer`:

```powershell
./LabGuardServer.exe --self-test --output "$env:TEMP/labguard-server-check.json"
./server/install-server.ps1
```

A instalação registra o serviço. Ele pode iniciar em observação local, com alterações indisponíveis. A configuração administrativa deve ser concluída antes de habilitar o controle real de um equipamento. Guarde os tokens com os responsáveis. O servidor escuta em `127.0.0.1` por padrão e não instala automaticamente regras de firewall/DNS no Windows. Siga [SERVIDORES.md](SERVIDORES.md) para o backend suportado pela edição de servidor, credenciais, início, parada e remoção. O gateway Linux documentado continua sendo uma opção de implantação específica, sem ser requisito geral do desktop.

O CI valida a instalação como serviço nativo do SCM em um Windows descartável, em demonstração. As edições específicas de Windows Server usadas pelo colégio precisam de validação local; esse teste não certifica todas as versões.

## Integridade e remoção

Compare o SHA-256 do pacote com `SHA256SUMS.txt` da mesma versão. Para remover o desktop, use Configurações → Aplicativos → LabGuard → Desinstalar. A remoção dos arquivos e atalhos não desfaz políticas aplicadas em equipamentos externos. O pacote portátil pode ser removido apagando sua pasta após fechar o aplicativo.

## Compilar a versão 2.0.0

Em Windows x64 com Python 3.12 e Inno Setup instalado:

```powershell
python -m pip install -r requirements-build.txt
./scripts/build_windows.ps1 -Version 2.0.0
```

Os arquivos ficam em `dist/release/`: instalador, ZIP portátil e ZIP de servidor. O GitHub Actions executa os testes, verifica a instalação e a abertura da janela em demonstração e testa o serviço nativo. A publicação aguarda também a conclusão dos pacotes Linux. A compilação Windows precisa ser feita em Windows; PyInstaller não converte um build Linux em um aplicativo Windows.

Referências: [PyInstaller](https://pyinstaller.org/en/stable/usage.html), [Inno Setup — instalação por usuário](https://jrsoftware.org/ishelp/topic_setup_privilegesrequired.htm) e [instalação silenciosa](https://jrsoftware.org/ishelp/topic_setupcmdline.htm).
