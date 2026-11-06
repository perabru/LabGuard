# Instalar o LabGuard no Windows

## Para usar

1. Baixe `LabGuard-Setup.exe` na [página de versões](https://github.com/perabru/LabGuard/releases/latest).
2. Execute o instalador. Ele instala o painel na pasta de programas do seu usuário, cria a opção no menu Iniciar e permite criar um atalho na área de trabalho.
3. Abra o LabGuard. A primeira tela usa uma **demonstração identificada**, com dados fictícios e sem alterar a rede.

O instalador inclui o Python e os componentes gráficos necessários. Não é preciso instalar Python para executar o painel. A conexão SSH com gateway e equipamentos compatíveis usa o **Cliente OpenSSH do Windows**, que pode ser habilitado em Configurações → Recursos opcionais.

O painel é para Windows 10/11 x64, incluindo instalações de Windows Server com Desktop Experience compatível. Para execução em servidor sem interface gráfica, use o pacote próprio abaixo. Não há assinatura de código comercial nesta versão; confira a origem do download e o SHA-256 publicado. Não desative o antivírus ou as políticas do colégio para executar um arquivo.

## Conectar à rede do laboratório

Instalar o painel no Windows não aplica regras de rede nos demais computadores por si só. O filtro de jogos/IA e o corte de internet por máquina precisam do [gateway Linux configurado](INSTALACAO.md). A [central de integrações](INTEGRACOES.md) oferece as capacidades explicitamente indicadas para cada família de equipamentos.

O painel não instala o agente Linux no Windows, não altera o roteador durante a instalação e não precisa de privilégios de administrador para instalar seus próprios arquivos.

## Versão portátil

O arquivo `LabGuard-Portable.zip` contém a pasta `LabGuard`. Extraia a pasta inteira e abra `LabGuard.exe`. Mantenha a pasta `_internal` e os demais arquivos junto do executável. O pacote portátil também começa em demonstração.

## Desinstalar

Use Configurações → Aplicativos → LabGuard → Desinstalar. Isso remove o painel e os atalhos instalados, sem remover regras do gateway nem configurações de equipamentos externos. Perfis personalizados na pasta do usuário não são apagados automaticamente.

## Servidor Windows sem interface gráfica

O arquivo `LabGuard-Server-Windows.zip` contém `LabGuardServer.exe`, o runtime e os scripts de instalação de serviço. Ele oferece administração por um painel web local e pode iniciar automaticamente com o Windows, usando uma conta de serviço restrita.

Extraia todo o pacote. Em PowerShell elevado, na pasta `LabGuardServer`:

```powershell
./LabGuardServer.exe --self-test --output "$env:TEMP/labguard-server-check.json"
./server/install-server.ps1
```

A instalação não inicia a operação real antes de configurar o gateway. Os tokens de administração devem ser guardados somente pelos responsáveis. O servidor escuta em `127.0.0.1` por padrão e não instala automaticamente regras de firewall/DNS no Windows. Leia [o guia de servidores](SERVIDORES.md) para configurar credenciais, iniciar, parar e remover o serviço.

O pacote é compilado em Windows x64. A validação automatizada executa a instalação como serviço nativo do SCM em um Windows descartável, em modo de demonstração, sem atuar na rede de um colégio. As versões específicas de Windows Server usadas pelo colégio precisam de validação local; o CI não é uma certificação de todas as edições.

## Como o executável é gerado

O repositório inclui um fluxo de compilação no GitHub Actions. Ele executa os testes em Linux e Windows, empacota com PyInstaller, cria o instalador com Inno Setup e verifica a instalação em um ambiente Windows descartável. Só depois publica os arquivos na versão correspondente.

Para compilar manualmente em um Windows x64 com Python 3.12 e Inno Setup instalado:

```powershell
python -m pip install -r requirements-build.txt
./scripts/build_windows.ps1 -Version 1.4.0
```

Os resultados ficam em `dist/release/`: instalador, ZIP portátil do painel e ZIP de servidor. O fluxo publica as somas SHA-256 após os testes das duas plataformas. O empacotamento precisa ser feito em Windows; o PyInstaller não transforma uma compilação Linux em um aplicativo Windows.

## Referências de empacotamento

- [PyInstaller — uso e arquivos adicionais](https://pyinstaller.org/en/stable/usage.html).
- [Inno Setup — instalação por usuário](https://jrsoftware.org/ishelp/topic_setup_privilegesrequired.htm).
- [Inno Setup — parâmetros de instalação silenciosa](https://jrsoftware.org/ishelp/topic_setupcmdline.htm).
