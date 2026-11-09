# Vivo + Mercusys não gerenciável: bloquear sites sem MikroTik

No PC da TI, abra **LabGuard → Configurar → 1. Ligar filtro**. O Vivo e o switch continuam transportando o tráfego normalmente. O PC do LabGuard passa a responder às consultas DNS das estações configuradas. Os testes de estação e o ajuste do DNS do Windows são comandados pelo painel da TI.

## 1. Preparar o PC do filtro

1. Abra o LabGuard e aguarde a observação real.
2. Clique **Configurar** no topo ou no primeiro card de Início. Siga **1. Ligar filtro → 2. Usar nos computadores → 3. Testar**.
3. Escolha a conexão e, se necessário, abra **Ajustar IP / DNS** para conferir **IP deste PC** e **Rede autorizada (CIDR)**. São o endereço e a sub-rede da interface do laboratório, não o IP do roteador. O assistente sugere apenas endereços efetivamente observados; dados de demonstração não são usados como configuração.
4. Reserve esse IP no DHCP ou combine uma configuração fixa com a TI, fora de conflitos. Exemplo didático: PC `192.168.15.10`, rede `192.168.15.0/24`. Não copie o exemplo sem conferir sua rede.
5. Confira **DNS de saída**. O padrão `1.1.1.1` recebe as consultas não bloqueadas; pode ser trocado pelo resolvedor IPv4 autorizado pela TI. Não aponte a saída para o próprio filtro.
6. Se desejar, marque **Ligar este filtro ao abrir o LabGuard**. Essa opção é salva somente após a ativação bem-sucedida; com o filtro ativo, use **Salvar início automático** para alterá-la. A falha de inicialização é informada e não muda DNS nem IP do sistema.
7. Marque a autorização e clique **Iniciar filtro DNS**. O programa tenta abrir **UDP e TCP 53** no IP escolhido. A lista aplicada anteriormente a esse IP/rede será carregada; organizar o banco não aplica novas regras por si só.

O serviço não muda DNS, DHCP, firewall ou configurações do Vivo. Se outro processo já usa a porta, não o encerra. No Linux a conta precisa ter permissão de vincular a porta 53; a TI pode usar o servidor como serviço com `CAP_NET_BIND_SERVICE`, mantendo a interface gráfica sem root. No Windows, autorize no firewall somente o IP/rede necessários; as permissões administrativas seguem a política da escola.

## 2. Administrar uma estação pelo PC da TI

Abra **Administrar estações** na etapa **2. Usar nos computadores** ou **3. Testar**. Selecione ou informe o IPv4 da estação do laboratório. Escolha o sistema e o acesso autorizado. Use um IPv4 da rede permitida. Endereços do filtro, gateway, dispositivos protegidos e endereços com identidade conflitante ficam fora da seleção. Para Windows, confira WinRM HTTPS, certificado confiável para o endereço utilizado, acesso pela porta de gerenciamento e conta com permissão adequada. Para Linux, use SSH já preparado com chave, identidade do host conferida, Python 3 e `dig` no alvo.

1. Clique em **Testar estação** antes de alterar o DNS. Os resultados são calculados a partir da estação selecionada. Compare ambos com o código apresentado no painel.
2. No Windows, clique em **Preparar alteração** e revise as configurações do adaptador associado ao IP selecionado. Confira o DNS anterior e o IP do filtro em execução. Confirme **Aplicar DNS** e teste de novo.
3. Para reverter a alteração, selecione o mesmo alvo e confira a restauração antes de confirmar **Restaurar DNS**. Teste a navegação após a recuperação da configuração original.

No Windows, a prévia propõe usar o IPv4 do LabGuard como DNS e remover os servidores DNS IPv6 alternativos apenas daquele adaptador. O protocolo IPv6 permanece habilitado. A alteração guarda os dados anteriores no Registro da estação, vinculados ao alvo, adaptador e filtro. É possível restaurar após reconectar. A aplicação exige um adaptador identificável e uma configuração cuja origem anterior possa ser recomposta. Ao aplicar, o programa verifica o caminho direto, grava a alteração e testa o DNS padrão. Se essa verificação falhar, tenta restaurar. Em caso de perda de acesso durante a operação, reconecte e confira o estado antes de repetir.

### Usar o navegador da TI

No desktop, abra **Painel web → Copiar chave e abrir** e cole a chave no login. Mantenha a janela do painel aberta. No serviço instalado, entre no painel local com o token administrativo. Em **Estações**, informe o acesso WinRM HTTPS ao Windows piloto e use **Testar DNS**, **Preparar alteração**, **Aplicar DNS** e **Restaurar DNS**. Se o WinRM ainda precisar ser preparado, o Windows da TI pode usar **Preparar nesta estação** quando já houver WMI/DCOM autorizado com Kerberos no domínio. Informe o IPv4 e o FQDN canônico da estação e a conta de domínio. A TI também pode usar **Preparar acesso remoto** e distribuir o script pela GPO ou pelo MDM. Os certificados e os passos de implantação estão no capítulo 11 do [manual completo](https://perabru.github.io/LabGuard/manual2/index.html).

Em Linux, a conexão SSH oferece os testes. Quando a estação não tiver um canal de administração disponível, a TI pode configurar DNS no DHCP/LAN do Vivo caso o modelo permita, ou usar a política de domínio/GPO ou outra gestão institucional já autorizada. Anote as configurações anteriores antes de alterar a política e restrinja o primeiro teste a uma estação ou a um escopo piloto.

## 3. Interpretar os dois testes

Se o teste local funcionou e a conexão com a estação Windows falhou, abra **Administrar estações → Verificar porta** no PC da TI. O resultado mostra se a porta de administração está acessível antes de usar conta e senha. Siga o [passo a passo para a estação sem confirmação](ADMINISTRACAO_REMOTA.md#funciona-no-pc-da-ti-e-a-estação-está-sem-confirmação).

**Direto ao filtro** consulta o IPv4 do serviço ativo. **DNS padrão da estação** consulta o resolvedor usado pelo computador do aluno. O teste automático no Windows usa um nome novo sob `labguard-check.test.` para cada consulta. O diagnóstico manual e o teste Linux usam `labguard-check.invalid.`. Compare os dois resultados com o código `LabGuard-...` da sessão atual. Cada reinício do filtro gera um código novo.

Em **Atividade**, localize o nome do teste, a origem e o horário. Se existir um encaminhador DNS, a origem registrada pode ser o próprio encaminhador. O contador geral de consultas e o teste **Verificar neste PC** não identificam qual estação recebeu o código.

### Domínio inexistente (NXDOMAIN), tempo esgotado ou código diferente

- Se o teste direto passar e o padrão retornar **domínio inexistente**, a estação alcança o filtro. Revise o DNS efetivamente usado pelo adaptador. Um endereço `fe80::…` no campo de servidor do CMD é um endereço IPv6 do enlace. Confira os resolvedores recebidos por IPv4 e IPv6, inclusive via DHCP e anúncios do roteador. Mantenha IPv6 habilitado e distribua apenas os resolvedores aprovados para a rede do laboratório.
- Se o teste direto expirar, confira o IP do filtro ativo, a rede autorizada, a permissão UDP/TCP 53 no firewall e o isolamento de VLAN ou Wi-Fi. Um erro de WinRM ou SSH indica falha de administração anterior ao teste DNS.
- Se o teste direto retornar NXDOMAIN ou um texto diferente, confira o destino e o código de sessão no painel. Repita os dois testes. Uma resposta diferente continua exigindo verificação mesmo que outra consulta apareça em Atividade.

Em **3. Testar → Diagnóstico manual**, os botões **Copiar teste direto** e **Copiar teste padrão** ficam disponíveis para suporte opcional. No primeiro comando, o painel inclui o IPv4 real do serviço ativo. No segundo, o comando `nslookup -type=TXT labguard-check.invalid.` consulta o resolvedor padrão. Mantenha o ponto final para consultar o nome completo. Ambos devem retornar o código esperado.

## 4. Aplicar um domínio e conferir

**Proteger laboratório** aplica uma lista inicial de domínios de jogos e adultos após a revisão da TI. Para usar o resolvedor familiar da Cloudflare, escolha a opção correspondente antes de ligar o filtro. O endereço `1.1.1.3` recebe consultas encaminhadas e filtra malware e conteúdo adulto. Avalie a resolução de nomes internos do domínio escolar. No serviço já ativo, aplicar a lista preserva o DNS de saída. As regras de IA são preparadas e aplicadas separadamente pelo Banco de sites.

Com ao menos um domínio aplicado, use **Testar estação** para observar o campo **Domínio aplicado**. A estação consulta aquele domínio pelo resolvedor padrão. Confira o código da sessão, o domínio exato e o horário do registro de bloqueio recebido pelo LabGuard. O resultado se refere ao domínio consultado pela estação naquele momento.

1. Em **Sites**, cadastre, por exemplo, `roblox.com`, categoria Jogos. Essa regra cobre o domínio e seus subdomínios. Outros serviços/CDNs do aplicativo podem exigir entradas adicionais; isso não desinstala o jogo.
2. Para uma lista maior, use **Banco de sites**, revise os registros e clique **Aplicar lista**. O catálogo de IA pode ser preparado nesse banco e aplicado explicitamente.
3. No PC da TI, abra **Atividade**. Busque o domínio cadastrado, a origem e o horário da consulta. A indicação **Bloqueio DNS confirmado** registra o bloqueio da consulta recebida. Se a escola dispõe de uma ferramenta de execução remota, a TI pode gerar uma consulta de teste por esse console.
4. Confira também um domínio permitido. Resposta negativa ou falha no DNS de saída não é exibida como bloqueio confirmado.
5. Cache, conexões já abertas e endereços embutidos nos aplicativos podem continuar funcionando. Se necessário, limpe o cache da estação conforme a política da TI e faça um novo teste.

A atividade mostra solicitações DNS recebidas, não páginas visitadas, conteúdo HTTPS ou todas as máquinas conectadas. Se o roteador encaminha as consultas em nome dos clientes, pode aparecer somente o IP do roteador.

## Se não funcionar

| Sintoma | Verificação |
|---|---|
| Continua somente visualização | Abra Configurar e inicie o filtro, com autorização; selecionar Observação não inicia DNS. |
| Não abre a porta 53 | Confira IP local, outro serviço DNS e permissão do sistema. O programa não encerra serviços nem eleva privilégios sozinho. |
| Código não aparece na consulta com IP explícito | Confira se LabGuard e PC estão ligados, o IP e a rede escolhidos, firewall UDP/TCP 53 e isolamento de Wi-Fi/VLAN. |
| Com IP funciona, sem IP não | Confira DNS do adaptador/DHCP, outros adaptadores, alternativas IPv6 e a renovação da configuração. |
| Código correto, navegador ainda abre um domínio | Confira a regra aplicada, subdomínios/CDNs, cache, DoH, VPN e conexões anteriores. |
| Bloqueio por IP/MAC desabilitado | É esperado: DNS não é um firewall de encaminhamento e o switch não gerenciável não controla portas. |

## Parar e desfazer

Restaure o DNS anterior na estação de teste ou no DHCP antes de parar o serviço. O aplicativo avisa ao fechar, desconectar ou trocar a fonte enquanto o DNS está ativo. Deixar clientes apontando para um PC desligado pode interromper a resolução de nomes. O LabGuard não faz alterações ocultas para restaurar a rede.

## Servidor opcional Windows/Linux

Inicialize o servidor como descrito em `SERVIDORES.md`. No `config.json` privado, use o controlador abaixo, substituindo IP e rede reais:

```json
"controller": {
  "kind": "local_dns",
  "host": "192.168.15.10",
  "port": 53,
  "lab_cidr": "192.168.15.0/24",
  "upstream": "1.1.1.1",
  "manage_rules": true
}
```

O serviço precisa de permissão para UDP/TCP 53. No Linux, a TI pode adicionar um override systemd com `AmbientCapabilities=CAP_NET_BIND_SERVICE` e `CapabilityBoundingSet=CAP_NET_BIND_SERVICE`, preservando o usuário dedicado e revisando as outras capacidades necessárias. As políticas ficam na pasta privada `data/dns-policy` da configuração. A administração web permanece no loopback, com tokens e perfis existentes; não é aberta para a LAN automaticamente. Não execute o DNS desktop e o DNS de servidor no mesmo IP/porta.

Não há promessa de controle universal ou de funcionamento infalível. O modelo do Vivo, o firewall e os clientes reais ainda precisam de homologação no colégio.

## Referências

- [Microsoft, comando nslookup e seleção do servidor DNS](https://learn.microsoft.com/pt-br/windows-server/administration/windows-commands/nslookup).
- [Microsoft, configuração de IPv6 no Windows](https://learn.microsoft.com/pt-br/troubleshoot/windows-server/networking/configure-ipv6-in-windows).
- MERCUSYS MS108G (exemplo de switch sem configuração): https://www.mercusys.com.br/product/switch/ms108g/
- Vivo, acesso ao roteador e lista de clientes: https://vivo.com.br/para-voce/ajuda/duvidas/internet/internet-vivo-wi-fi
- Configuração DNS por cliente e limitações de equipamentos de operadora: https://developers.google.com/speed/public-dns/docs/using?hl=pt-br
