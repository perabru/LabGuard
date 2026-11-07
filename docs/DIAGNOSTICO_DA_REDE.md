# Erro de identificação: passo a passo - LabGuard 2.2.0

Use este guia quando o IP do roteador não aparecer, houver poucas máquinas ou uma conexão administrativa falhar. A Observação consulta os dados disponíveis no computador e pode ser usada sem uma API do roteador. O alcance depende do sistema, da rede e das fontes acessíveis; não há identificação garantida de todos os equipamentos.

Confirme onde o programa está sendo executado. Em uma máquina virtual, contêiner ou servidor, a consulta descreve a rede desse ambiente, que pode ser diferente da rede do computador ou navegador utilizado para acessá-lo.

## 1. Abrir a ajuda do programa

Em Observação, comece por **Identificar minha rede**. Confira a fonte e o estado no cartão **O que foi identificado**, seguido de **Próximo passo**. As contagens representam amostras, não um censo físico. Uma leitura confirmada ainda tem cobertura parcial.

Se a leitura estiver indisponível, a coleta não confirmou informações; isso não comprova ausência de rede. Se aparecerem **Dados desatualizados**, os registros anteriores continuam visíveis para consulta, mas não foram confirmados como atuais. Horário ausente, inválido ou futuro não é recente. Dados de **Demonstração** são fictícios e ficam separados das consultas reais.

1. Em **Início**, clique **Não identificou? Ver passo a passo**. Depois de uma falha, use também o botão de ajuda apresentado junto ao erro.
2. No assistente **Ajuda para identificar a rede**, leia o caso indicado e avance por **Voltar / Avançar**.
3. Em Observação, MikroTik direto ou Demonstração, use **Atualizar consulta** depois de conferir os passos. Esse botão relê a fonte atual; não troca credenciais, perfil ou autorização e não altera firewall, DNS ou rotas.
4. Se a dúvida continuar, siga o caso correspondente abaixo e anote somente as informações necessárias ao suporte.

No gateway SSH legado, esse botão fica desabilitado: a consulta avançada pode reconciliar políticas já configuradas. Siga o fluxo do legado ou escolha **Observar esta rede** em Início para consultar a rede local. O assistente não troca o modo automaticamente.

## 2. Conferir a conexão e o IP no Windows

O programa prefere os recursos de rede do PowerShell. Quando a fonte principal falha, tenta consultas **CIM locais** para configuração e rotas, e o cache ARP quando os vizinhos não puderam ser lidos. Isso não consulta computadores remotos, não baixa ferramentas e não solicita elevação. As fontes alternativas podem fornecer menos campos ou endereços. PowerShell indisponível ou uma política institucional ainda pode impedir a coleta.

Abra o Terminal, PowerShell ou Prompt de Comando na sua conta habitual. Estes comandos apenas exibem informações; não é necessário iniciar como administrador para a consulta normal:

```text
ipconfig /all
route print -4
arp -a
```

| Consulta | O que procurar |
|---|---|
| `ipconfig /all` | Adaptador do laboratório, IPv4, máscara, gateway padrão e DNS; ignore adaptadores desconectados |
| `route print -4` | Rota de destino `0.0.0.0`, seu gateway e interface; várias rotas exigem confirmar qual atende ao laboratório |
| `arp -a` | IPs/MACs já conhecidos por cada interface; a lista pode estar vazia ou desatualizada |

Compare o adaptador e o endereço com **Início**. Se aparecerem Wi-Fi, Ethernet, VPN ou adaptadores virtuais, confirme com a TI qual conexão deve ser usada. Não apague rotas nem desative interfaces por tentativa.

## 3. Conferir a conexão e o IP no Linux

Abra um terminal na conta habitual e execute somente as consultas:

```text
ip -4 addr
ip -4 route
ip -4 neigh
```

| Consulta | O que procurar |
|---|---|
| `ip -4 addr` | Interface do laboratório e endereço `inet` com prefixo de rede |
| `ip -4 route` | Linha `default via`, IP de saída e interface `dev`; compare também as demais rotas |
| `ip -4 neigh` | Vizinhos IPv4 conhecidos, campo `lladdr` e estado; `STALE` não comprova presença atual |

O programa usa **iproute2** como fonte preferencial. Se `ip` não existir ou uma consulta falhar, tenta fontes alternativas somente para os dados indisponíveis: interfaces e tabelas locais de rotas e ARP do Linux. A alternativa pode mostrar menos interfaces ou endereços adicionais. Ela não eleva privilégios, não instala ferramentas e não envia sondagens à rede.

Uma tabela válida e vazia continua sendo um resultado válido: não dispara uma busca para forçar o aparecimento de máquinas. Se precisar dos comandos manuais acima e `ip` não existir, peça à TI a instalação de **iproute2** pelo gerenciador da distribuição. O pacote Debian do LabGuard declara essa dependência.

Não é necessário usar `sudo` para essas consultas normais. Se uma política institucional impedir a leitura, peça à TI que confira a permissão específica.

## 4. IP ou gateway ausente

1. Confira se o computador está conectado ao cabo ou SSID correto. Em uma rede só local, pode não existir rota padrão, e isso não significa que todas as interfaces estejam sem conexão.
2. Use as consultas do seu sistema. O gateway da rota padrão é uma referência do caminho de saída; não presuma que seja o equipamento cuja etiqueta você está olhando.
3. Se houver várias rotas, confirme com a TI o adaptador do laboratório. Não adivinhe o roteador escolhendo um IP parecido com o seu.
4. Se o IP da estação for fixo, ele pode não aparecer em uma concessão DHCP. Compare a configuração local e, quando disponível, o ARP do roteador. Não mude a estação para DHCP apenas para fazê-la aparecer.
5. Em Observação, clique **Atualizar consulta** no assistente e confira o resultado.

A Observação desta versão usa **IPv4 privado** das faixas `10.0.0.0/8`, `172.16.0.0/12` e `192.168.0.0/16`. Redes apenas IPv6 ou com outro endereçamento podem ficar fora da lista. O programa não modifica a rede para contornar esse limite.

## 5. Sem MAC ou com poucos dispositivos

1. Confira se o campo vazio é o **MAC do próprio computador**. Ele pode ficar vazio quando a fonte não o fornece; essa ausência, sozinha, não é falha de identificação.
2. Compare a tabela do LabGuard com `arp -a` no Windows ou `ip -4 neigh` no Linux. A coleta local lê cache, sem varrer todas as máquinas.
3. Considere VLANs, roteadores intermediários, NAT, pontos de acesso e isolamento entre clientes Wi-Fi. Essas configurações podem impedir que o computador veja os MACs dos demais clientes.
4. Uma entrada antiga ou `STALE` também pode permanecer depois que a máquina saiu da rede. Não trate o cache como lista de presença. Ausência de MAC, ARP ou concessão DHCP tampouco comprova que uma estação esteja desligada; IP fixo pode não gerar concessão.
5. Para inventário mais amplo, consulte o equipamento ou controlador compatível com uma conta autorizada. A disponibilidade desse acesso depende do modelo; não é requisito para continuar em Observação.

Se o mesmo IP aparecer associado a MACs diferentes, confirme a identidade com a TI antes de agir. Um mesmo MAC em vários IPs pode refletir endereços adicionais ou registros antigos. Contar IPs ou MACs não equivale a contar computadores físicos ou pessoas.

## 6. Marca, modelo ou modem Vivo desconhecido

1. Identifique o IP de saída pelas consultas locais e confirme com a TI qual equipamento exerce o papel de roteador.
2. Confira **marca e modelo exatos na etiqueta**. Uma etiqueta de ponto de acesso ou switch pode não corresponder ao gateway da rede.
3. Quando autorizado, consulte a página de informações do painel local já utilizado para esse equipamento e anote o firmware. Não use endereços, credenciais ou procedimentos de outro modelo.
4. Se o equipamento for fornecido pela Vivo, Embratel ou outra operadora, anote também o fabricante/modelo real. O nome da operadora não define uma API universal.
5. Sem integração documentada, mantenha **Observar esta rede**. Não selecione MikroTik por tentativa e não instale um perfil aleatório para obter bloqueios.

O LabGuard não deduz o modelo pelo MAC. O fabricante associado a um prefixo MAC, quando conhecido, também não comprova modelo, firmware nem capacidade de administração.

## 7. Falha de certificado HTTPS

1. Confira o IP literal digitado e a porta HTTPS autorizada. O adaptador direto MikroTik desta versão não aceita nomes DNS no endereço.
2. Peça à TI que confira o certificado do serviço `www-ssl`: validade, cadeia confiável e **SAN de tipo IP** correspondente ao endereço utilizado.
3. Se houver CA institucional, selecione o arquivo correto no campo de CA. Confira também a data/hora do computador.
4. Tente conectar novamente em consulta, sem autorizar alterações.

Não desative TLS, validação de certificado ou firewall para passar dessa etapa. Uma CA correta estabelece confiança; não é uma opção para ignorar um certificado incorreto.

## 8. Autenticação recusada: HTTP 401 ou 403

1. Confira usuário, conta autorizada, IP e porta do equipamento correto. Digite a senha somente no campo de sessão.
2. Solicite à TI a verificação das permissões REST e das restrições de origem da conta ou do serviço. Comece com leitura.
3. Uma resposta **401** pode envolver autenticação ou restrições de acesso. **403** pode envolver autorização, política ou serviço. Não conclua automaticamente que a senha está errada.
4. Depois da conferência, reconecte em consulta e valide a identificação antes de autorizar regras.

Não tente senhas padrão, não envie credenciais em relatórios e não amplie permissões por tentativa.

## 9. API indisponível ou equipamento incompatível

1. Confirme modelo e firmware pelo equipamento, não pela marca da conexão ou pelo MAC.
2. O adaptador **Controlar MikroTik via HTTPS** exige RouterOS 7 com REST HTTPS já preparado. Um painel web acessível não comprova que essa API esteja disponível.
3. Uma consulta parcial pode deixar funções específicas indisponíveis. Para domínios, esta implementação exige RouterOS 7.18 ou posterior e os requisitos DNS/DHCP descritos no manual.
4. Para outra família de equipamento, use somente o perfil compatível documentado em **Outros equipamentos**. Se não existir, continue em Observação e encaminhe modelo/firmware à TI.

Conseguir consultar o equipamento não libera automaticamente bloqueios. FastTrack, offload, IPv6, WAN e permissões também podem limitar ações.

## 10. Tempo esgotado ou sem resposta

1. Confira conexão, IP literal e porta já autorizada. Se houver várias interfaces ou redes de gestão, confirme o caminho correto com a TI.
2. Verifique se o equipamento está ligado e se o painel administrativo normalmente utilizado está acessível pelo caminho autorizado.
3. Peça à TI que confira a disponibilidade do serviço e a política de acesso da rede. Não desligue o firewall nem abra portas gerais para testar.
4. Atualize a consulta ou reconecte uma vez depois da conferência. Tentativas repetidas ou prazos maiores não corrigem endereço errado, equipamento incompatível ou acesso negado.

## 11. Informações para suporte

Anote versão do LabGuard, Windows/distribuição Linux, modo escolhido, tipo de conexão, caso indicado pelo assistente e modelo/firmware confirmados. Inclua o horário e se a falha ocorre na Observação ou ao conectar uma API. Compartilhe IPs somente com os responsáveis autorizados quando necessários.

**Não inclua senha do roteador, senha Wi-Fi, tokens, chaves privadas ou a saída completa dos comandos sem revisão.** A etiqueta e o painel do equipamento podem exibir segredos; transcreva somente os campos necessários.

## 12. Atualização ou conexão ao abrir não funcionou

### Atualização do aplicativo

1. Confira se você já instalou a **2.2 ou posterior**. A primeira migração de uma versão antiga é manual, pois ela não tinha o atualizador.
2. Abra **Detalhes e recursos → Atualizações do programa** e leia o estado. A aplicação automática exige o Windows instalado por usuário; portátil, Linux, `.deb` e servidor continuam com procedimento manual ou da TI. Fonte, desenvolvimento e Demonstração não instalam atualizações automaticamente.
3. Confira a conexão com a publicação oficial e use **Verificar atualização**, quando disponível. Se houver falha de rede, download ou validação, continue com a versão em uso. Não desative TLS ou firewall para liberar o download.
4. Uma atualização preparada é aplicada somente ao encerramento voluntário e sem operação/download em curso. Não force o encerramento de processos para antecipar essa etapa.
5. Se a instalação falhar, peça à TI que confira a versão e a instalação antes de voltar ao uso. Não presuma que todo erro tenha recuperação automática.

### Acesso lembrado ao MikroTik

1. Confira se a conexão manual funcionou depois de escolher **Lembrar este acesso**. As opções não são salvas após uma tentativa com falha.
2. No Windows, confirme **Salvar senha no cofre do Windows** e **Conectar ao abrir (somente consulta)**. Se o cofre não estiver disponível, continue em Observação e conecte manualmente; não copie a senha para o JSON.
3. Mudou o IP, a conta ou o certificado? Abra **Acesso ao equipamento**, corrija e reconecte manualmente. O início automático faz uma única tentativa, não corrige requisitos do equipamento.
4. Para retirar o acesso lembrado, use **Esquecer acesso salvo** e confira a confirmação. A sessão atual continua ativa. Se a remoção da senha no cofre não for confirmada, peça à TI que confira o cofre antes de considerar a credencial removida.

A abertura automática nunca restaura autorização de alterar regras nem aplica listas de sites. Se a consulta falhar, a Observação continua disponível. Para suporte, informe também o tipo de pacote e o estado apresentado, preservando os segredos.

## Referências de consulta

- [Microsoft: ipconfig](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/ipconfig).
- [Microsoft: route](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/route_ws2008).
- [Microsoft: arp](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/arp).
- [Linux: tabela de vizinhos](https://man7.org/linux/man-pages/man8/ip-neighbour.8.html).
- [MikroTik: REST API](https://manual.mikrotik.com/docs/developer-guides/rest-api/).
- [Manual 2.2.0: recuperação](MANUAL_DO_USUARIO_V2.html#erro-de-identificacao).
- [Manual 2.2.0: atualizações e início](MANUAL_DO_USUARIO_V2.html#atualizacoes-e-inicio).
