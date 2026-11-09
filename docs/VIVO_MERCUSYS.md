# Vivo + Mercusys não gerenciável: bloquear sites sem MikroTik

**Use LabGuard 2.4 ou posterior → Configurar → 1. Ligar filtro.**

A visualização da versão anterior não era uma conexão de controle com o Vivo. Ela apenas lia interfaces, rota e vizinhos do PC. Não é necessário comprar um MikroTik para usar o novo filtro DNS. O switch simples continua ramificando a rede e não possui uma API de configuração que o LabGuard possa habilitar.

O novo modo executa um servidor DNS no próprio computador. Os cabos e o roteador podem continuar no lugar atual. Para funcionar, os computadores precisam consultar esse servidor DNS; estar na mesma rede, sozinho, não basta.

## 1. Preparar o PC do filtro

1. Abra o LabGuard e aguarde a observação real.
2. Clique **Configurar** no topo ou no primeiro card de Início. Siga **1. Ligar filtro → 2. Usar nos computadores → 3. Testar**.
3. Escolha a conexão e, se necessário, abra **Ajustar IP / DNS** para conferir **IP deste PC** e **Rede autorizada (CIDR)**. São o endereço e a sub-rede da interface do laboratório, não o IP do roteador. O assistente sugere apenas endereços efetivamente observados; dados de demonstração não são usados como configuração.
4. Reserve esse IP no DHCP ou combine uma configuração fixa com a TI, fora de conflitos. Exemplo didático: PC `192.168.15.10`, rede `192.168.15.0/24`. Não copie o exemplo sem conferir sua rede.
5. Confira **DNS de saída**. O padrão `1.1.1.1` recebe as consultas não bloqueadas; pode ser trocado pelo resolvedor IPv4 autorizado pela TI. Não aponte a saída para o próprio filtro.
6. Se desejar, marque **Ligar este filtro ao abrir o LabGuard**. Essa opção é salva somente após a ativação bem-sucedida; com o filtro ativo, use **Salvar início automático** para alterá-la. A falha de inicialização é informada e não muda DNS nem IP do sistema.
7. Marque a autorização e clique **Iniciar filtro DNS**. O programa tenta abrir **UDP e TCP 53** no IP escolhido. A lista aplicada anteriormente a esse IP/rede será carregada; organizar o banco não aplica novas regras por si só.

O serviço não muda DNS, DHCP, firewall ou configurações do Vivo. Se outro processo já usa a porta, não o encerra. No Linux a conta precisa ter permissão de vincular a porta 53; a TI pode usar o servidor como serviço com `CAP_NET_BIND_SERVICE`, mantendo a interface gráfica sem root. No Windows, autorize no firewall somente o IP/rede necessários; as permissões administrativas seguem a política da escola.

## 2. Apontar uma estação de teste para o filtro

Antes da mudança, anote se o DNS da estação era automático e quais servidores estavam configurados.

**Se o Vivo permite escolher DNS no DHCP/LAN:** configure o endereço do PC LabGuard como DNS para as estações do laboratório. A posição e disponibilidade dessa opção dependem do modelo e firmware. A TI deve revisar o escopo antes de aplicar à rede inteira.

**Se o Vivo não permite:** configure o DNS diretamente em uma estação de teste. No Windows, `Win+R → ncpa.cpl → adaptador do laboratório → Propriedades → Protocolo IP Versão 4 → Propriedades`. Preserve a configuração IP existente e altere apenas o DNS preferencial para o IP do LabGuard. Em um ambiente de domínio, a TI pode distribuir a opção por política ou administração remota já autorizada, sem instalar um cliente LabGuard.

Não coloque um DNS público como alternativo: o sistema pode escolhê-lo e contornar os bloqueios. Para redundância, use outro resolvedor que aplique a mesma política. IPv6, DNS seguro do navegador, VPN e redes Wi-Fi isoladas também precisam de avaliação; não são desativados pelo programa.

## 3. Confirmar por código, em outro computador

Depois de iniciar, abra **3. Testar**, clique **Verificar neste PC** para conferir UDP/TCP locais e anote o código `LabGuard-...` exibido.

Execute, substituindo o IP pelo valor real:

```text
nslookup -type=TXT labguard-check.invalid 192.168.15.10
```

Deve retornar o mesmo código do painel. Isso confirma que a estação alcançou este filtro em uma consulta explícita, sem depender de um site externo.

Depois de configurar o DNS da estação, teste também **sem informar servidor**:

```text
nslookup -type=TXT labguard-check.invalid
```

O código deve continuar igual. Se o primeiro teste funciona e o segundo não, o DNS padrão da estação ainda não está usando este filtro. Cada teste valida aquele caminho naquele momento; não garante cobertura de todo o laboratório nem bloqueia DNS criptografado do navegador.

## 4. Aplicar um domínio e conferir

1. Em **Sites**, cadastre, por exemplo, `roblox.com`, categoria Jogos. Essa regra cobre o domínio e seus subdomínios. Outros serviços/CDNs do aplicativo podem exigir entradas adicionais; isso não desinstala o jogo.
2. Para uma lista maior, use **Banco de sites**, revise os registros e clique **Aplicar lista**. O catálogo de IA pode ser preparado nesse banco e aplicado explicitamente.
3. Na estação de teste, consulte `nslookup roblox.com` usando o DNS configurado. Uma consulta recebida e bloqueada fica em **Atividade** com **Bloqueio DNS confirmado**.
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

- MERCUSYS MS108G (exemplo de switch sem configuração): https://www.mercusys.com.br/product/switch/ms108g/
- Vivo, acesso ao roteador e lista de clientes: https://vivo.com.br/para-voce/ajuda/duvidas/internet/internet-vivo-wi-fi
- Configuração DNS por cliente e limitações de equipamentos de operadora: https://developers.google.com/speed/public-dns/docs/using?hl=pt-br
