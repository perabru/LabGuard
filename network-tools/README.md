# LabGuard — DNS sem cliente 1.0.0

Ferramenta administrativa para estações Windows que devem usar o filtro DNS do **LabGuard 2.4.4** (também compatível com o 2.4.3), com **IPv6 desabilitado no adaptador escolhido**, conforme a configuração definida pela TI para o laboratório. O script executa uma configuração pontual; não instala cliente, serviço ou tarefa em segundo plano.

**Comece em uma estação piloto.** O modo padrão, `Diagnosticar`, apenas consulta a configuração e faz testes DNS. `Aplicar` e `Restaurar` exigem administrador, um adaptador escolhido e confirmação.

- [Guia prático no site](https://perabru.github.io/LabGuard/tecnico/dns-ipv6.html).
- [Baixar ZIP 1.0.0](https://perabru.github.io/LabGuard/tecnico/ferramentas/LabGuard-DNS-Sem-Cliente-1.0.0.zip).
- [Conferir SHA-256 do ZIP](https://perabru.github.io/LabGuard/tecnico/ferramentas/LabGuard-DNS-Sem-Cliente-1.0.0.sha256).
- [Código do script](LabGuard-DNS-Sem-Cliente.ps1).

## Por que funciona no PC da TI e não no aluno?

Os computadores podem estar usando servidores DNS diferentes. Alterar o DNS IPv4 de uma estação não comprova que ela deixou de receber DNS por anúncios IPv6 do roteador. Outro adaptador, o DNS seguro do navegador, uma VPN ou respostas em cache também podem explicar a diferença.

**IPv6 habilitado não significa, por si só, desvio do filtro.** Consultas A e AAAA são tipos de registro; o transporte da consulta pode ser IPv4 ou IPv6. O LabGuard pode receber pelo seu IPv4 uma consulta AAAA e bloquear o domínio. A tela `DNS_PROBE_FINISHED_NXDOMAIN` mostra uma falha de resolução, mas não identifica quem respondeu. Compare o diagnóstico da estação com a sessão ativa do LabGuard. Veja as [referências](#referências).

## Antes de executar

No aplicativo 2.4.4, o atalho é **Configurar → 2. Usar nos computadores → Guia e ferramenta IPv6**. Ele abre a página de instruções e download. A ferramenta deve ser executada na estação escolhida; o atalho não configura os alunos nem desabilita IPv6 no PC da TI.

1. No PC da TI, mantenha o LabGuard e seu filtro ligados. Confira o **IPv4 real exibido pelo aplicativo**, a rede autorizada e o acesso da estação às portas UDP/TCP 53.
2. O IP do filtro deve permanecer estável. O endereço a informar é o do PC que executa o filtro, não o do modem Vivo nem o da estação do aluno.
3. Se a escola usa Active Directory ou nomes internos, o resolvedor de saída do LabGuard precisa continuar atendendo esses nomes. Confira isso antes de trocar o DNS de uma estação do domínio.
4. Baixe o ZIP, confira sua origem e soma SHA-256 e extraia a pasta inteira. Preserve a ferramenta e o backup mantido por ela no registro da estação para poder restaurar depois.
5. Na estação piloto, abra **Windows PowerShell como administrador**, na pasta que contém `LabGuard-DNS-Sem-Cliente.ps1`. Use uma conta autorizada da TI.

Para conferir o ZIP antes de extrair:

```powershell
Get-FileHash .\LabGuard-DNS-Sem-Cliente-1.0.0.zip -Algorithm SHA256
```

Compare o resultado com o arquivo `.sha256` publicado. A soma verifica integridade; ela não equivale a uma assinatura digital do script.

### Política de execução da escola

Consulte a política efetiva quando o PowerShell impedir a execução:

```powershell
Get-ExecutionPolicy -List
```

Siga o processo da escola para autorizar ou assinar scripts. Após revisar o conteúdo e a origem, a TI pode remover a marca de download **somente deste arquivo**, quando a política institucional permitir:

```powershell
Unblock-File .\LabGuard-DNS-Sem-Cliente.ps1
```

Isso não substitui exigências de assinatura nem políticas de grupo. Não reduza `MachinePolicy`/`UserPolicy` nem configure um bypass global para executar a ferramenta.

## 1. Descobrir o DNS e diagnosticar

Estes comandos mostram os adaptadores ativos e seus servidores DNS:

```powershell
Get-NetAdapter | Where-Object Status -eq 'Up' |
  Format-Table ifIndex, Name, InterfaceDescription, Status -Auto

Get-DnsClientServerAddress |
  Format-Table InterfaceIndex, InterfaceAlias, AddressFamily, ServerAddresses -Auto
```

Escolha a conexão Ethernet ou Wi-Fi usada pela estação no laboratório. Não selecione automaticamente VPNs ou adaptadores virtuais. O número da coluna `ifIndex`/`InterfaceIndex` identifica a interface para os comandos seguintes.

Informe o IPv4 copiado do LabGuard e rode o diagnóstico sem mudar configurações:

```powershell
$Filtro = Read-Host 'IPv4 real mostrado no LabGuard, no PC da TI'
.\LabGuard-DNS-Sem-Cliente.ps1 -Modo Diagnosticar -FiltroIPv4 $Filtro
```

Para acrescentar um domínio que **você já bloqueou** no LabGuard:

```powershell
$Dominio = Read-Host 'Domínio já bloqueado, sem https, caminho ou espaços'
.\LabGuard-DNS-Sem-Cliente.ps1 -Modo Diagnosticar -FiltroIPv4 $Filtro -DominioTeste $Dominio
```

O domínio da imagem relatada foi `www.meutimao.com.br`; ele só serve como teste de bloqueio se estiver coberto por uma regra aplicada. Um site que abre não prova defeito se não há regra para ele.

### Ler a saída do diagnóstico

O resultado aparece em JSON no próprio PowerShell. **`Ok: true` indica que a coleta foi executada; não certifica que toda a navegação está filtrada.** Confira os campos específicos:

| Campo | Interpretação |
|---|---|
| `Paths.Direct` igual a `ok` | O IPv4 informado respondeu com um código de sessão LabGuard válido |
| `Paths.Default` igual a `ok` e `Paths.SameSession` igual a `true` | A consulta padrão recebeu a mesma sessão do teste direto |
| `Adapters` → `State` → `IPv6BindingEnabled` igual a `false` | IPv6 desabilitado naquele adaptador; confira também índice e nome |
| `DomainQueries` | Respostas A/AAAA do domínio opcional pelos caminhos direto e padrão; relacione-as ao registro em Atividade |
| `BrowserPolicies` | Valores encontrados no registro para políticas Chrome/Edge; não são uma leitura completa das preferências de cada navegador |

Política DoH `Nao definida` não significa que o DNS seguro está desligado. Se um adaptador trouxer `Error` ou `State: null`, a leitura dessa configuração ficou incompleta e precisa ser revisada antes da aplicação.

## 2. Aplicar em um adaptador

Faça isso na estação piloto, depois de revisar o diagnóstico e confirmar que o filtro responde diretamente:

```powershell
$Indice = [int](Read-Host 'InterfaceIndex da conexão do laboratório nesta estação')
.\LabGuard-DNS-Sem-Cliente.ps1 -Modo Aplicar -FiltroIPv4 $Filtro -InterfaceIndex $Indice
```

Leia o resumo e confirme no próprio PowerShell. A ferramenta guarda o DNS IPv4 anterior e o estado `Enabled` do vínculo `ms_tcpip6`, define o IPv4 do filtro como DNS da interface e **desabilita o vínculo IPv6 somente nesse adaptador**. Ela usa `Disable-NetAdapterBinding`; não altera manualmente os anúncios do roteador nem a lista DNS IPv6. A alteração pode reiniciar a interface e interromper momentaneamente sua conexão; execute o procedimento com acesso local à estação.

O ajuste é feito no Windows da estação e não depende de existir um menu correspondente no roteador. A ferramenta precisa identificar o estado anterior para restaurá-lo. Se ela recusar a alteração por estado desconhecido, comando indisponível ou falha de verificação, use o diagnóstico para investigar; não complete a operação apagando valores manualmente.

O backup fica no registro protegido da própria estação, em `HKLM:\SOFTWARE\LabGuard\NetworkDNS\{GUID_DO_ADAPTADOR}`, valor `State`, com acesso de Administradores/SYSTEM. Ele guarda a identidade do adaptador, o DNS IPv4 e o estado IPv6 anterior. Não edite nem remova esse estado enquanto a configuração estiver em uso.

A ferramenta tenta restaurar o backup se a aplicação falhar. Confira a mensagem final: uma tentativa de reversão não deve ser tratada como restauração concluída se o Windows informar erro.

**Trate os demais adaptadores separadamente.** Uma interface Wi-Fi, Ethernet, VPN ou outra conexão ainda ativa pode oferecer outro resolvedor. A configuração de uma interface não significa que todos os caminhos de resolução foram corrigidos.

### Procedimento manual para um adaptador chamado Ethernet

O comando utilizado pela TI é válido para uma interface cujo nome real seja **Ethernet**. Confira antes com `Get-NetAdapter` e registre o valor anterior de `Enabled`:

```powershell
Get-NetAdapterBinding -Name "Ethernet" -ComponentID ms_tcpip6 |
  Format-List Name, Enabled
```

Depois, em PowerShell como administrador:

```powershell
Disable-NetAdapterBinding -Name "Ethernet" -ComponentID ms_tcpip6
Get-NetAdapterBinding -Name "Ethernet" -ComponentID ms_tcpip6 |
  Format-List Name, Enabled
ipconfig /flushdns
```

O resultado esperado é **`Enabled : False`**. Se o adaptador tiver outro nome, substitua `Ethernet` pelo nome exato. Feche e reabra o navegador e teste na estação do aluno.

Esses comandos desabilitam IPv6 na interface escolhida, mas não configuram o DNS IPv4 do LabGuard. Para configurar ambos com backup, use a ferramenta acima. Caso a TI precise desfazer a alteração manual e o valor anterior fosse `True`, use `Enable-NetAdapterBinding -Name "Ethernet" -ComponentID ms_tcpip6` e confira o estado novamente.

## 3. Conferir o resultado

Execute novamente `Diagnosticar` com o filtro e o domínio escolhidos. Os testes direto e padrão precisam identificar a sessão ativa do LabGuard. No aplicativo da TI, confira também as consultas recebidas em **Atividade**.

| Resultado observado | Próxima verificação |
|---|---|
| O teste direto não alcança o filtro | IP do PC da TI, filtro ligado, rede autorizada, UDP/TCP 53 e isolamento da rede |
| O direto responde, mas o padrão não identifica o LabGuard | DNS IPv4/IPv6, outros adaptadores, políticas de rede e configuração que reapareceu |
| Os testes DNS passam, mas o navegador abre o site | Regra/domínio exato, DNS seguro, VPN, cache e conexões anteriores |
| `Enabled` ainda aparece como `True` para `ms_tcpip6` no adaptador escolhido | Confira o adaptador, o resultado da aplicação e políticas que possam ter reativado o vínculo |

Confira `Enabled : False` para `ms_tcpip6` no adaptador escolhido. Teste A e AAAA do domínio bloqueado, um domínio permitido e a navegação na conta utilizada pelo aluno. Limpe o cache DNS do Windows com `ipconfig /flushdns` (ou `Clear-DnsClientCache`) e feche/reabra o navegador. O cache do Windows não é todo o estado do navegador.

**Repita a conferência após reiniciar a estação ou reconectar a interface**, antes de aplicar nas demais máquinas. Ao abrir uma nova sessão do PowerShell, informe novamente `$Filtro`, `$Indice` e `$Dominio`; essas variáveis não são salvas entre janelas.

O diagnóstico comprova somente os caminhos efetivamente testados. Um resultado de DNS não certifica todos os navegadores, aplicativos, VPNs ou acessos futuros.

Para demonstrar **abriu → bloqueou → liberou** na lista de sites do LabGuard 2.4.4, use `poki.com` e siga o [roteiro do técnico](https://perabru.github.io/LabGuard/tecnico/#demonstrar). Mantenha **Estado → Todos** para acompanhar o mesmo item; liberar preserva o cadastro.

## 4. DNS seguro no Chrome e no Edge

Um navegador configurado para consultar um provedor DoH próprio pode não usar o DNS do Windows. A TI deve alinhar essa configuração à política da escola. Para navegadores administrados, Chrome e Edge documentam a política **`DnsOverHttpsMode`**, com valor **`off`** para desativar o resolvedor DoH do navegador. Confira a política aplicada em `chrome://policy` ou `edge://policy`.

Use as [instruções oficiais do Chrome](https://chromeenterprise.google/policies/#DnsOverHttpsMode) e do [Microsoft Edge](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-browser-policies/dnsoverhttpsmode). Preserve a configuração anterior caso essa política também seja alterada. O ajuste DNS desta ferramenta não configura automaticamente essas políticas de navegador. A política citada trata de DNS; páginas HTTPS continuam usando HTTPS.

## 5. Restaurar

Antes de parar o filtro ou retirar a estação desse modelo, restaure o DNS anterior:

```powershell
$Indice = [int](Read-Host 'InterfaceIndex da conexão configurada nesta estação')
.\LabGuard-DNS-Sem-Cliente.ps1 -Modo Restaurar -InterfaceIndex $Indice
```

Leia o resumo e confirme. A ferramenta restaura o DNS IPv4 e o estado IPv6 registrados no backup: se `Enabled` já era `False`, a restauração mantém `False`; se era `True`, volta a `True`. Isso também vale se a TI já havia desabilitado IPv6 manualmente antes de usar a ferramenta. Confira a mensagem de conclusão e teste a resolução de nomes depois. A restauração depende do backup daquela estação e interface. Não transplante o backup de outro computador nem remova a chave do registro enquanto a configuração estiver em uso. Se outra política ou administrador mudou o DNS/vínculo depois, a restauração pode recusar a sobreposição e preservar o backup para revisão da TI.

Se a TI mudou políticas de navegador separadamente, restaure-as pelo mesmo procedimento institucional usado para aplicá-las.

## Parâmetros

| Parâmetro | Uso |
|---|---|
| `-Modo Diagnosticar` | Padrão; consulta configuração e realiza testes, sem aplicar DNS |
| `-Modo Aplicar` | Configura a interface escolhida; requer administrador, filtro e interface |
| `-Modo Restaurar` | Restaura o backup da interface escolhida; requer administrador e interface |
| `-FiltroIPv4` | IPv4 real do PC que executa o LabGuard; necessário para aplicar e para os testes direcionados ao filtro |
| `-InterfaceIndex` | Índice da interface; obrigatório ao aplicar/restaurar |
| `-DominioTeste` | Domínio opcional para acrescentar às consultas de diagnóstico |
| `-ConfirmarAlteracao` | Confirmação explícita para execução não interativa de aplicar/restaurar; omita no uso manual para ler e responder à pergunta |

Carregar o arquivo por *dot-source* apenas disponibiliza suas funções; não executa automaticamente o fluxo. Para uso normal, execute pelo caminho `.\LabGuard-DNS-Sem-Cliente.ps1`, como nos exemplos.

## Referências

- [Microsoft: Disable-NetAdapterBinding](https://learn.microsoft.com/en-us/powershell/module/netadapter/disable-netadapterbinding).
- [Microsoft: Get-NetAdapterBinding](https://learn.microsoft.com/en-us/powershell/module/netadapter/get-netadapterbinding).
- [Microsoft: Enable-NetAdapterBinding](https://learn.microsoft.com/en-us/powershell/module/netadapter/enable-netadapterbinding).
- [Microsoft: configuração IPv6 no Windows](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/configure-ipv6-in-windows).
- [Microsoft: Set-DnsClientServerAddress](https://learn.microsoft.com/en-us/powershell/module/dnsclient/set-dnsclientserveraddress).
- [Microsoft: DNS client resolution timeouts](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/dns-client-resolution-timeouts).
- [Microsoft: Clear-DnsClientCache](https://learn.microsoft.com/en-us/powershell/module/dnsclient/clear-dnsclientcache).
- [RFC 3596: registros IPv6 e transporte das consultas DNS](https://www.rfc-editor.org/rfc/rfc3596.html).

A edição principal do aplicativo é **2.4.4**. **1.0.0** é a versão desta ferramenta auxiliar, que também pode ser usada com o filtro da edição 2.4.3.
