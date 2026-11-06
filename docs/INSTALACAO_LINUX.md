# LabGuard para Linux

## Escolher o pacote

| Pacote | Uso |
|---|---|
| `LabGuard-Linux-amd64.deb` | Painel gráfico para Ubuntu 22.04 ou posterior e Debian 12 ou posterior, em x86_64/amd64 |
| `LabGuard-Linux-x86_64.tar.gz` | Painel gráfico portátil para Linux x86_64 com glibc 2.35 ou posterior e ambiente gráfico X11/XWayland |
| `LabGuard-Server-Linux-x86_64.tar.gz` | Serviço administrativo sem interface Tk, com painel web local e instalação systemd |

Os pacotes incluem o runtime Python. A conexão administrativa por SSH usa o cliente OpenSSH do sistema. Não há pacote ARM, 32 bits ou Alpine/musl nesta versão. Distribuições fora da matriz acima precisam de validação própria.

## Instalar o painel gráfico

Baixe o pacote na [página de versões](https://github.com/perabru/LabGuard/releases/latest). No Ubuntu/Debian:

```bash
sudo apt install ./LabGuard-Linux-amd64.deb
labguard
```

O aplicativo também aparece no menu como **LabGuard**. Os arquivos ficam em `/opt/labguard`. A primeira abertura usa dados fictícios de demonstração e não altera a rede.

Para o pacote portátil:

```bash
tar -xzf LabGuard-Linux-x86_64.tar.gz
cd LabGuard
./iniciar.sh
```

Mantenha a pasta `_internal` e os demais arquivos junto ao executável. É necessário um ambiente gráfico ativo; para uma máquina sem desktop, escolha a versão de servidor.

## Versão para servidores Linux

Extraia `LabGuard-Server-Linux-x86_64.tar.gz`. O executável `LabGuardServer` não abre janelas Tk. O pacote inclui `server/install-server.sh`, configuração de serviço e [guia de servidores](SERVIDORES.md).

```bash
tar -xzf LabGuard-Server-Linux-x86_64.tar.gz
cd LabGuardServer
./LabGuardServer --self-test --output /tmp/labguard-server-check.json
sudo bash server/install-server.sh
```

O instalador registra o serviço, mas a operação real exige configurar o gateway administrativo antes de iniciá-lo. Consulte o guia de servidores para editar a conexão, guardar os tokens e iniciar o serviço. O modo de demonstração precisa ser selecionado explicitamente. O painel web escuta somente em `127.0.0.1` por padrão; não o exponha à internet diretamente.

O servidor de administração é separado do gateway que aplica DNS/firewall. Instalar o servidor não converte automaticamente a máquina em roteador. A implantação do gateway Linux continua em [INSTALACAO.md](INSTALACAO.md).

## Verificar integridade e remover

Compare o SHA-256 do arquivo baixado com `SHA256SUMS.txt` da mesma versão:

```bash
sha256sum LabGuard-Linux-amd64.deb
```

Para remover o painel `.deb`:

```bash
sudo apt remove labguard
```

Isso não remove regras do gateway nem altera equipamentos externos. A remoção dos serviços administrativos deve seguir [SERVIDORES.md](SERVIDORES.md), preservando os registros exigidos pelo colégio.

## Compilar

O fluxo do GitHub Actions compila Linux em Ubuntu 22.04 e testa o `.deb`, uma janela real no Xvfb e o servidor como serviço systemd em uma máquina descartável. As versões de Windows são geradas separadamente em Windows. A publicação só ocorre quando as duas plataformas passam nos testes.

```bash
python3 -m pip install -r requirements-build.txt
bash scripts/build_linux.sh 1.4.0
```

Referências: [PyInstaller](https://pyinstaller.org/en/stable/usage.html), [arquivos de dados empacotados](https://pyinstaller.org/en/stable/runtime-information.html) e [campos do pacote Debian](https://www.debian.org/doc/debian-policy/ch-controlfields.html).
