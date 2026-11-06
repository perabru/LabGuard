# LabGuard 2.0 para Linux

## Escolher o pacote

| Pacote | Uso |
|---|---|
| `LabGuard-Linux-amd64.deb` | Desktop para Ubuntu 22.04+ e Debian 12+, em x86_64/amd64 |
| `LabGuard-Linux-x86_64.tar.gz` | Desktop portátil para Linux x86_64, glibc 2.35+ e sessão gráfica X11/XWayland |
| `LabGuard-Server-Linux-x86_64.tar.gz` | Serviço administrativo sem Tk, painel web local e instalação systemd |

Os pacotes incluem o runtime Python e a geração de relatórios. O acesso direto RouterOS usa HTTPS; as integrações SSH opcionais usam o cliente OpenSSH do sistema. Não há pacote ARM, 32 bits ou Alpine/musl nesta versão. Outras distribuições precisam de validação própria.

## Instalar o desktop

Baixe o pacote na [página de versões](https://github.com/perabru/LabGuard/releases/latest). Em Ubuntu/Debian:

```bash
sudo apt install ./LabGuard-Linux-amd64.deb
labguard
```

O aplicativo também aparece no menu como **LabGuard**; seus arquivos ficam em `/opt/labguard`. Ao abrir, ele inicia em **observação local da rede**, sem aplicar regras automaticamente. A demonstração com dados fictícios é uma escolha explícita.

Para usar o portátil:

```bash
tar -xzf LabGuard-Linux-x86_64.tar.gz
cd LabGuard
./iniciar.sh
```

Mantenha `_internal` e os demais arquivos junto ao executável. É necessário um ambiente gráfico ativo; para uso sem desktop, escolha a edição de servidor.

## Observar e controlar a rede

A observação local utiliza as informações disponíveis no sistema, como interfaces, rotas e vizinhos. Isso não descobre toda a rede escolar, não comprova presença atual e não concede controle sobre equipamentos externos.

O desktop permite configurar uma conexão direta com equipamento compatível. O adaptador direto exige **RouterOS 7 com REST por HTTPS**, serviço `www-ssl` habilitado e certificado TLS validável. A porta padrão é 443. Informe endereço, usuário e senha de uma conta autorizada, com permissões para as operações escolhidas. Para certificados de uma autoridade própria, selecione o arquivo da CA. Mantenha a validação TLS ativa e confira uma ação em um equipamento ou estação de teste.

O acesso direto não usa a API binária da porta 8729 e não exige OpenSSH. As integrações SSH opcionais usam `openssh-client` e a identidade do equipamento previamente verificada.

Não é obrigatório instalar um gateway Linux adicional nem encaminhar toda a rede pelo computador do painel. O alcance do bloqueio depende do modelo, das funções oferecidas pela integração e do caminho do tráfego. As demais famílias apresentam recursos próprios em [INTEGRACOES.md](INTEGRACOES.md); o suporte não é universal por marca.

O bloqueio de domínios depende do tratamento das consultas DNS pela infraestrutura configurada. VPN, DNS externo/criptografado, NAT intermediário e MAC privado podem limitar o alcance ou a identificação. O gateway Linux em [INSTALACAO.md](INSTALACAO.md) permanece uma opção para implantações que o escolham.

## Servidor Linux opcional

O pacote de servidor não é necessário para a conexão direta do desktop. Ele não abre janelas Tk e inclui `server/install-server.sh`, configuração systemd e [guia de servidores](SERVIDORES.md).

```bash
tar -xzf LabGuard-Server-Linux-x86_64.tar.gz
cd LabGuardServer
./LabGuardServer --self-test --output /tmp/labguard-server-check.json
sudo bash server/install-server.sh
```

O instalador registra o serviço, que pode iniciar em observação local com alterações indisponíveis. Antes de habilitar o controle real, configure o backend administrativo suportado pela edição de servidor conforme seu guia, guarde os tokens e revise as permissões. A demonstração precisa ser selecionada explicitamente. O painel web escuta somente em `127.0.0.1` por padrão.

O servidor administrativo não transforma a máquina em roteador automaticamente. Sua implantação é independente do uso do desktop com conexão direta.

## Verificar e remover

Compare o SHA-256 do download com `SHA256SUMS.txt` da mesma versão:

```bash
sha256sum LabGuard-Linux-amd64.deb
```

Para remover o desktop `.deb`:

```bash
sudo apt remove labguard
```

A remoção do aplicativo não desfaz políticas aplicadas em equipamentos externos. O portátil pode ser removido apagando sua pasta após fechar o programa. Para remover o serviço, siga [SERVIDORES.md](SERVIDORES.md).

## Executar pelo código-fonte ou compilar

Para executar pelo código-fonte, instale Python 3.12 e Tk, crie um ambiente virtual e instale as dependências:

```bash
sudo apt install python3-venv python3-tk
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python main.py
```

Essa opção também começa em observação local e não exige implantar um gateway adicional. Para gerar os pacotes em Linux x86_64:

```bash
python -m pip install -r requirements-build.txt
bash scripts/build_linux.sh 2.0.0
```

O GitHub Actions compila no Ubuntu 22.04, testa o `.deb`, abre uma janela real em demonstração no Xvfb e valida o servidor em systemd com demonstração. Os pacotes Windows são gerados em Windows. A publicação aguarda a conclusão das duas plataformas.

Referências: [PyInstaller](https://pyinstaller.org/en/stable/usage.html), [recursos empacotados](https://pyinstaller.org/en/stable/runtime-information.html) e [campos do pacote Debian](https://www.debian.org/doc/debian-policy/ch-controlfields.html).

## Identificação local e comando ip

A observação usa o comando `ip`, do pacote `iproute2`. O instalador `.deb` declara essa dependência. Na versão portátil, no servidor Linux ou ao executar o código-fonte, confirme que `ip -4 address show up` e `ip -4 route show default` estão disponíveis. Se o comando estiver ausente, a TI deve instalar `iproute2` pelo gerenciador da distribuição; o LabGuard não instala ferramentas automaticamente.

No desktop, abra **Início → Não identificou? Ver passo a passo**. No servidor, o diagnóstico corresponde ao host do serviço, que pode estar em outra rede em relação ao navegador. Consulte o [passo a passo](https://perabru.github.io/LabGuard/manual2/index.html#erro-de-identificacao).
