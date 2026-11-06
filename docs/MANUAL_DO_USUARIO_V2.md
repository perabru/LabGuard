# LabGuard 2.0.1 - Manual do usuário

Começar na rede existente, conectar um controlador e conferir cada resultado.

Edição 2.0.1 | 6 de novembro de 2026

Este manual acompanha a interface simplificada 2.0.1 e sua ajuda de identificação da rede. A disponibilidade dos instaladores depende da publicação correspondente na página de versões. Um pacote 1.4 não contém automaticamente as funções descritas aqui.

## 1. Primeiro uso em cinco passos

O LabGuard começa em **Observação**, com informações reais que o sistema local consegue consultar. Esse primeiro contato não pede senha do roteador e não altera o caminho da rede.

1. Baixe o pacote correto na [página de versões](https://github.com/perabru/LabGuard/releases), conferindo versão e arquivo de verificação da mesma publicação.
2. Abra o programa. Pelo código-fonte, use Python 3.10 ou superior com Tcl/Tk e execute `python3 main.py`. No Windows, use também o inicializador do projeto. No Debian/Ubuntu, o Tk está no pacote `python3-tk`.
3. Na tela **Início**, mantenha **Observar esta rede**. Não precisa instalar gateway Linux nem trocar cabos para consultar os dados locais.
4. Abra **Dispositivos** e confira os endereços disponíveis. A lista reúne evidências do sistema; não garante descobrir todas as máquinas ligadas ao switch.
5. Abra **Sites → Banco de sites** para organizar a política desejada. Cadastrar um domínio não modifica o firewall. A aplicação exige um controlador compatível conectado.

Para aprender sem usar dados reais, escolha **Abrir demonstração** em Início. O modo fictício fica identificado e não altera a rede.

### Antes de uma aula

Confira o modo ativo e a última atualização. Comece com uma estação de teste. Aplique regras somente depois de confirmar que a conexão corresponde ao equipamento certo e que a capacidade desejada está disponível.

## 2. Escolher o modo certo

| Modo | O que oferece | O que precisa |
|---|---|---|
| Observar esta rede | Configuração local, rota padrão e vizinhos conhecidos | Computador conectado |
| Abrir demonstração | Dados fictícios para aprender | Nenhuma credencial |
| Controlar MikroTik via HTTPS | Consulta e ações pela API | RouterOS 7 compatível, HTTPS e permissões |
| Outros equipamentos | Consulta ou controle específico | Modelo, protocolo e acesso compatíveis |
| Gateway SSH existente | Agente Linux legado | Gateway LabGuard já instalado |

### Observação é o padrão

A tabela de vizinhos depende do tráfego conhecido pelo computador. Uma máquina silenciosa, em outra VLAN ou atrás de NAT pode não aparecer. Um endereço pode continuar listado depois de o equipamento ser desligado. Isso não é inventário físico completo.

Nesse modo, suspender internet, aplicar domínios e ativar filtro de IA ficam indisponíveis. Cadastros e relatórios locais continuam úteis.

### Vivo e outras marcas

A marca ou operadora não define uma API universal. Um modem Vivo identificado na rota pode ser observado; isso não significa que seu firewall seja administrável pelo programa. Perfis de switches Cisco e TP-Link podem oferecer portas e MACs, com alcance diferente de um filtro de sites. Confira o modelo e as capacidades em **Outros equipamentos**.

## 3. Conhecer as quatro telas

| Tela | Para que serve |
|---|---|
| Início | Escolher o modo, conectar o controlador e conferir o estado |
| Dispositivos | Consultar IP/MAC, selecionar uma máquina e acessar ações |
| Sites | Administrar domínios, perfil de IA e banco de sites |
| Atividade | Consultar a amostra DNS, ações e conexões disponibilizadas |

Em Início, o formulário de MikroTik pede **Endereço**, **Porta**, **Usuário**, **Senha da sessão** e **Certificado CA opcional**. **Autorizar alterações neste roteador** começa desmarcado.

As opções avançadas incluem lista de interfaces WAN, rede do laboratório e IPs/MACs protegidos. Preencha com a TI antes de autorizar alterações. Esses valores delimitam as regras.

**Mapa e relatórios** e **Outros equipamentos** abrem ferramentas adicionais, mantendo a navegação principal simples.

### Ação indisponível

O botão pode depender do modo, permissões, atualização recente ou requisito do roteador. Leia a indicação apresentada. Conseguir consultar o equipamento não comprova autorização para escrever no firewall.

Ao trocar de modo, atualize antes de agir. Uma falha real deve ser apresentada como falha; demonstração não substitui o estado do laboratório.

## 4. Conectar um MikroTik existente

A integração usa a API REST HTTPS do **RouterOS 7**. Ela administra o roteador compatível que já está no caminho da rede, sem instalar um novo gateway.

1. Peça à TI que confira a versão, o serviço `www-ssl`, o certificado e as permissões REST. Comece com uma conta de consulta.
2. Em **Início**, selecione **Controlar MikroTik via HTTPS**.
3. Informe o IP literal do roteador, porta HTTPS, usuário e senha da sessão. Se necessário, selecione a CA institucional. Este adaptador não aceita nomes DNS no campo de endereço.
4. Mantenha **Autorizar alterações neste roteador** desmarcado e clique **Conectar**.
5. Confira a identificação, a rede e as capacidades antes de autorizar qualquer alteração.

### Certificado e alcance

O certificado deve incluir o IP utilizado em um campo SAN de tipo IP e encadear para uma autoridade confiável. Informar uma CA não desliga a validação TLS. Corrija falhas no certificado do equipamento.

Na seção avançada, a lista de interfaces WAN começa em `WAN`; ela deve corresponder à lista real do roteador. Informe a rede do laboratório quando a identificação por DHCP for insuficiente ou houver múltiplas redes. Resolva ambiguidades antes de aplicar regras.

Cadastre os endereços administrativos como protegidos. Não coloque senha no endereço, no nome do equipamento ou em relatórios. No painel, ela pertence à sessão.

## 5. Habilitar controle corretamente

Marcar **Autorizar alterações neste roteador** expressa a intenção do operador. O programa ainda verifica se a ação é compatível com a configuração encontrada.

Para filtro de domínios, este adaptador exige RouterOS **7.18 ou posterior**, DNS remoto já preparado e DHCP anunciando somente o DNS do próprio roteador. Ele não configura esses requisitos automaticamente.

| Requisito | Por que importa |
|---|---|
| HTTPS e usuário autorizado | Consulta e escrita exigem permissões adequadas |
| Rede do laboratório definida | Evita alcançar outra sub-rede |
| Lista WAN correta | Delimita a saída administrada |
| DNS preparado | Os clientes precisam resolver pelo DNS controlado |
| Tipo NXDOMAIN compatível | O firmware precisa aceitar o bloqueio DNS usado |
| FastTrack verificado | Fluxos acelerados podem contornar regras tradicionais |
| Offload de roteamento verificado | Encaminhamento em hardware pode contornar o filtro |
| IPv6 verificado | Um caminho IPv6 pode contornar corte somente IPv4 |

O programa não desativa FastTrack, IPv6 nem configurações gerais automaticamente para liberar um botão. Se um requisito impedir a operação, a TI precisa avaliar e preparar uma configuração compatível.

### DNS do laboratório

O roteador precisa aceitar consultas dos clientes autorizados, e estes precisam usar seu DNS. Isso envolve as opções do RouterOS e o DNS entregue à rede. Não exponha o resolvedor à internet. Acesso à API não muda automaticamente o DNS usado pelos clientes.

O filtro age em novas resoluções. Cache, DNS sobre HTTPS e VPNs exigem políticas adicionais. O corte de internet também depende da ausência de saída alternativa por outra rede.

## 6. Dispositivos: consultar e controlar

Abra **Dispositivos** e selecione a máquina pela combinação de nome disponível, IP, MAC e evidência apresentada. Confirme o alvo físico quando houver dúvida.

### Consultar primeiro

Uma concessão DHCP informa um endereço concedido, não garante presença atual. ARP e vizinhos também são evidências limitadas. MAC privado, troca de interface, NAT e equipamentos intermediários podem afetar a identificação.

### Bloquear e desbloquear IP

1. Conecte um controlador compatível e atualize o inventário.
2. No MikroTik direto, selecione a máquina e use **Bloquear IP**, quando disponível. No gateway legado e na demonstração, os botões continuam **Suspender internet** e **Restaurar internet**.
3. Confira alvo e alcance na confirmação.
4. Após a resposta, atualize e teste uma conexão na própria estação.

**Desbloquear IP** retira somente a regra daquele IP. Um bloqueio independente por MAC permanece até ser retirado na ação de MAC. A operação não corrige falha de cabo, Wi-Fi, DNS externo ou regra de outro sistema.

### IP, MAC e proteção

Uma regra por IP segue o endereço; ela não promete suspender todas as identidades da máquina. IP e MAC são escopos independentes, também acessíveis no mapa quando suportados. IPs/MACs protegidos não devem receber bloqueio pelo painel.

Desativar uma porta de switch em **Outros equipamentos** é outra operação: pode desconectar várias máquinas quando há switch ou ponto de acesso conectado àquela porta.

## 7. Sites, jogos e serviços de IA

Use domínios como `exemplo.com`, sem protocolo, caminho, porta ou curinga. Confira o alcance por subdomínios apresentado pelo controlador. Um domínio amplo compartilhado pode afetar ferramentas pedagógicas.

### Banco de sites

O **Banco de sites** mantém o cadastro local em SQLite, com categorias, busca, notas, importação e exportação. Pode ser editado sem conexão administrativa. **Cadastrar ou ativar um item no banco não aplica uma regra na rede.**

A lista preparada inicialmente em Observação é aproveitada na primeira conexão MikroTik, enquanto ainda não estiver vinculada a outro destino. Ao desconectar ou reiniciar o painel, o último banco real continua disponível. Outro destino usa um banco separado; a demonstração tem seu próprio banco. Confira sempre a conexão antes de aplicar.

Para sincronizar, conecte uma fonte com filtragem de domínios disponível, revise a seleção e use **Aplicar lista**. Confira o resultado. Em falha parcial, itens já aplicados podem permanecer ativos; leia o resumo antes de repetir.

Na tela Sites, **Bloquear domínio** aplica uma regra diretamente ao controlador conectado, quando permitido. **Adicionar catálogo de IA ao banco** apenas prepara cadastros locais; não ativa o filtro na rede.

### Perfil de IA

O perfil usa um catálogo de domínios conhecidos. Ative somente em controlador compatível e confira o alcance informado. Desativar a política preserva os domínios manuais; um domínio manual pode continuar bloqueado.

No MikroTik direto desta versão, use **Adicionar catálogo de IA ao banco**, revise a seleção e aplique a lista. O botão **Perfil global de IA** separado exige uma fonte que confirme essa capacidade, como o gateway legado; ele não é habilitado por este adaptador MikroTik.

O catálogo não identifica toda IA. Modelos offline, funções no mesmo domínio de um serviço permitido e novos serviços fora da lista não são detectados por DNS. VPNs e DNS criptografado também podem contornar o método.

### Testar um domínio

Use uma estação e um domínio de teste. Consulte pelo DNS controlado e confira a resposta depois de limpar o cache local. Retire a regra e confirme a liberação. A tela de cadastro não comprova aplicação no firewall.

## 8. Atividade: interpretar os registros

**Atividade** separa **Consultas DNS**, **Ações** e **Conexões**. Cada fonte fornece dados diferentes. Uma tela vazia ou indisponível não deve ser interpretada como histórico completo.

| Informação | O que representa |
|---|---|
| Consulta DNS | Solicitação de um domínio, inclusive por aplicativo automático |
| Ação | Operação enviada e resultado informado pelo controlador |
| Conexão IP/porta | Comunicação observada, sem URL nem conteúdo HTTPS |
| DNS indisponível | A fonte não fornece consultas atribuídas aos clientes |

### Observação não intercepta a rede

Esse modo não captura páginas das outras máquinas, não instala proxy e não revela os sites de todos os alunos. A tabela local ajuda no inventário; não substitui registros do roteador ou de um resolvedor preparado.

### Cache não é histórico por aluno

Um cache DNS pode reunir nomes de muitos dispositivos, sem atribuição individual. Um nome só deve ser associado a um cliente quando uma fonte realmente entregar essa relação.

O adaptador MikroTik direto desta versão não fornece histórico DNS por cliente nem lista de conexões. Esses campos ficam indisponíveis; vazios não significam ausência de acesso.

Uma consulta não prova visita ou leitura de conteúdo. Anúncios, pré-carregamento e tarefas automáticas também geram consultas. Confirme o contexto antes de agir.

Ao exportar, mantenha o arquivo sob acesso dos responsáveis e adote a retenção definida pelo colégio. Exporte apenas a amostra necessária.

## 9. Programas e avisos nas estações

**Programas e avisos**, em Dispositivos, usa administração autenticada do próprio computador. Esse recurso é independente da marca do roteador.

| Estação | Preparação necessária |
|---|---|
| Windows | WinRM HTTPS, certificado válido e conta autorizada |
| Linux | OpenSSH, Python remoto, chave e host verificado |

A TI precisa preparar os serviços antes. O programa não habilita WinRM/SSH remotamente, não descobre senhas e não instala um agente permanente nas estações.

### Consultar e avisar

O inventário é pontual e reconhece nomes do catálogo. Launcher aberto não comprova uma partida. A consulta não oferece leitura de páginas, senhas, arquivos pessoais ou captura contínua da tela.

No Windows, sessões e permissões adequadas podem permitir mensagem do sistema. No Linux, o aviso usa terminais conectados; popup gráfico não é garantido. Uma resposta de envio não confirma que o aluno leu.

### Remover uma instalação suportada

A remoção exige consulta recente, pacote reconhecido, prévia e confirmação explícita. Nem todo jogo tem remoção remota. Dados locais podem ser afetados pelo gerenciador do sistema. Falha de rede durante a execução pode deixar o resultado incerto: consulte a estação antes de repetir.

Consulte [Administração remota](ADMINISTRACAO_REMOTA.md) para catálogo e permissões. As operações limitadas não exigem liberar execução arbitrária ou um shell root.

## 10. Mapa, relatórios e outros equipamentos

### Mapa e relatórios

O atalho usa a amostra da fonte conectada. O desenho é lógico: ligações inferidas não comprovam porta física, cabo, switch ou associação Wi-Fi. MAC privado não equivale a identidade permanente de pessoa.

Os formatos incluem SVG, HTML, CSV e PDF conforme o pacote e suas dependências. Exporte após atualizar; confira horário, modo e origem dos dados. Relatório de demonstração continua fictício.

### Perfis de equipamentos

Perfis podem consultar portas, MACs, concessões ou saída limitada. Um adaptador de inventário não passa a controlar firewall por ter sido instalado.

Quando houver controle de porta, autorize somente portas de acesso conhecidas. Desativar uma porta com switch ou ponto de acesso abaixo dela pode atingir vários dispositivos. Reativação administrativa não confirma cabo conectado nem cliente funcionando.

Perfis locais ou baixados continuam limitados pelo formato e protocolo suportados. Importar um perfil não troca firmware, habilita API ausente nem garante todos os modelos da marca. Revise origem, hash e documentação do equipamento.

Para modem Vivo sem API compatível documentada, mantenha Observação e use administração das estações quando já preparada. Credenciais ou procedimentos de outro modelo não substituem uma integração suportada.

## 11. Servidor administrativo e legado

### Servidor 2.0

O servidor roda sem Tk e oferece painel web local em `http://127.0.0.1:8765/`. O padrão é observação/controlador, sem exigir gateway Linux no caminho do tráfego.

A CLI mantém `init` e `run` com diretório de configuração. O arquivo de configuração seleciona `controller.kind`: `observation` para consulta local ou `routeros` para API compatível. A senha fica somente no arquivo privado de segredos, no campo `controller_password`; não deve ser inserida no JSON público de configuração.

Pelo código-fonte, inicialize e execute em um diretório privado:

```bash
python3 server_main.py init --directory ./labguard-servidor
python3 server_main.py run --directory ./labguard-servidor
```

O padrão de `manage_rules` é `false`. Configurar o controlador não autoriza alterações. Tokens de consulta e administração permanecem separados. Preserve as permissões privadas definidas pelo instalador.

O HTTP é local. Para acesso remoto, use canal administrativo autenticado preparado pela TI; não publique a porta 8765 diretamente na internet.

Consulte [Servidores](SERVIDORES.md) para instalação como serviço e configuração completa.

### Gateway existente é opcional

Quem usa o agente SSH anterior pode manter o modo avançado. Ele tem requisitos próprios de duas interfaces, DNS/DHCP, regras e chave SSH preparada.

Esses requisitos do legado não se aplicam ao início em Observação nem à consulta por API. O [manual 1.4](MANUAL_DO_USUARIO.md) e o [PDF 1.4](Manual_LabGuard_1.4.pdf) permanecem como referência desse caminho.

## 12. Erro de identificação: passo a passo {#erro-de-identificacao}

### Abrir o assistente

1. Em **Início**, clique **Não identificou? Ver passo a passo**. Após uma falha, há também um botão de ajuda junto ao erro.
2. No assistente **Ajuda para identificar a rede**, confira o caso sugerido ou escolha outro. Uma sugestão não confirma a causa.
3. Use **Voltar / Avançar** para ler as etapas. Os comandos são executados manualmente; a ajuda não os executa.
4. Em Observação ou MikroTik direto, clique **Atualizar consulta**. A leitura usa a conexão atual; não troca credenciais, perfil, firewall, DNS ou rotas. Para corrigir IP, certificado ou conta, volte a Início e reconecte.

No gateway SSH legado, o botão fica desabilitado: uma consulta avançada pode reconciliar políticas existentes. Siga o fluxo do legado ou escolha Observação em Início; a ajuda não troca o modo automaticamente.

### Conferir IP e rota

Abra um terminal na conta habitual. As consultas normais não exigem administrador ou `sudo`.

| Windows | Linux | Confira |
|---|---|---|
| `ipconfig /all` | `ip -4 addr` | Interface conectada e IPv4 do laboratório |
| `route print -4` | `ip -4 route` | Rota padrão, gateway e interface de saída |
| `arp -a` | `ip -4 neigh` | IPs/MACs já conhecidos no cache local |

Se faltar `ip` no Linux portátil ou pelo código-fonte, peça à TI a instalação de **iproute2** pelo gerenciador da distribuição. O pacote Debian declara essa dependência.

Confira o cabo ou SSID e compare a interface com o planejamento da TI. VPNs e várias conexões podem criar mais de uma rota. Uma rede só local pode não ter gateway padrão. Não altere DHCP ou rotas por tentativa: uma estação com IP fixo pode não aparecer nas concessões DHCP.

### Poucas máquinas ou MAC vazio

A Observação lê um **cache parcial**, não faz varredura completa. Cache vazio pode ser normal; entrada antiga ou `STALE` não comprova presença. O MAC do próprio computador fica vazio por desenho da coleta e isso não é falha.

VLANs, roteadores, NAT, pontos de acesso e isolamento Wi-Fi podem ocultar vizinhos e seus MACs. A coleta automática cobre IPv4 privado `10.x`, `172.16-31.x` e `192.168.x`; redes somente IPv6 ou outros endereços podem ficar fora da lista. Continue em Observação sem exigir um MikroTik.

## 13. Modelo desconhecido e falha na API

### Confirmar o equipamento

1. Encontre o gateway na rota e confirme com a TI qual equipamento exerce esse papel. Ele pode ser diferente do ponto de acesso.
2. Leia fabricante e modelo na etiqueta ou no inventário autorizado. No painel local já usado pela escola, confira também o firmware.
3. Vivo ou Embratel são operadoras, não uma API universal. Não deduza o modelo pelo MAC e não selecione MikroTik por tentativa.
4. Sem perfil compatível confirmado, mantenha **Observar esta rede**. A consulta local funciona sem credenciais administrativas.

### Resolver a conexão administrativa

| Caso | Passo a passo |
|---|---|
| HTTPS ou certificado | Confira IP literal, porta e data/hora. No MikroTik direto, o certificado precisa de SAN de tipo IP correspondente e cadeia confiável. Use a CA institucional correta e reconecte em consulta. Nomes DNS não são aceitos nesse adaptador |
| HTTP 401 ou 403 | Confira conta e equipamento. Peça à TI que verifique permissões REST e restrições de origem. 401/403 podem envolver autenticação, autorização ou política; não conclua automaticamente que a senha está errada |
| API indisponível | Confirme perfil, modelo e firmware. MikroTik direto exige RouterOS 7 com REST HTTPS já preparado; um painel web acessível não comprova uma API compatível. Domínios exigem 7.18 ou posterior e os requisitos do capítulo 5 |
| Tempo esgotado | Confira conexão, IP e porta autorizados. Aguarde a consulta atual. Peça à TI que confira disponibilidade e restrições de gestão; depois tente uma leitura. Não repita uma alteração de resultado incerto antes de conferir o estado |

Não desative TLS, validação de certificado ou firewall para prosseguir. O assistente não habilita serviços de gestão nem libera capacidades de bloqueio.

Para suporte, informe versão, sistema, modo, categoria da falha, etapa realizada e modelo/firmware confirmados. Revise IPs e capturas antes de compartilhar. **Nunca inclua senha, token, chave privada ou saída bruta com credenciais.**

O [guia completo de diagnóstico](DIAGNOSTICO_DA_REDE.md) detalha os comandos e cada caso do assistente.

## 14. Teste de aceitação e suporte

| Situação | Próximo passo |
|---|---|
| Identificação incompleta ou API com falha | Use o assistente dos capítulos 12 e 13; a hipótese não confirma a causa |
| Bloqueio indisponível | Leia modo, capacidade, permissões e requisitos |
| Conecta mas não corta | Confira autorização, WAN, FastTrack, IPv6 e saída alternativa |
| Site ainda abre | Verifique DNS do cliente, cache, DoH/VPN e domínio |
| Aviso não aparece | Confira WinRM/SSH, sessão e permissões |

### Teste com uma única máquina

1. Abra em Observação e confirme que não pode aplicar bloqueios.
2. Conecte em consulta e confira identidade e redes antes de autorizar alterações.
3. Aplique e retire um domínio de teste; bloqueie e desbloqueie um IP quando o controlador permitir. Confira separadamente qualquer regra por MAC.
4. Teste a proteção administrativa e confira que um requisito ausente mantém a ação indisponível.
5. Atualize, teste após reinício e registre o resultado real. Teste simulado ou compilação não substitui homologação no equipamento.

### Referências e suporte

- [MikroTik: REST API e HTTPS](https://manual.mikrotik.com/docs/developer-guides/rest-api/).
- [MikroTik: DNS](https://help.mikrotik.com/docs/spaces/ROS/pages/37748767/DNS).
- [MikroTik: conexões e FastTrack](https://help.mikrotik.com/docs/spaces/ROS/pages/130220087/Connection+tracking).
- [Microsoft: configuração do WinRM](https://learn.microsoft.com/en-us/windows/win32/winrm/installation-and-configuration-for-windows-remote-management).

Para suporte, informe versão, sistema, modo, modelo/firmware e categoria da falha. Não inclua senhas, tokens ou chaves privadas.
