# Alcance e operação

> **LabGuard 2.0:** este guia descreve o gateway Linux opcional. Para começar em observação local ou administrar um roteador compatível sem reposicionar o PC, use [Comece aqui](COMECE_AQUI.md) e o [manual 2.0](MANUAL_DO_USUARIO_V2.html).

## O que cada informação significa

| Informação | Interpretação correta |
|---|---|
| Concessão DHCP ativa | O servidor concedeu um IP e o prazo ainda não terminou; a máquina pode ter sido desligada |
| Vizinho alcançável/observado | O Linux tem uma entrada recente na tabela de vizinhos; isso não é inventário físico completo |
| Consulta DNS | Um dispositivo solicitou um domínio; pode ser navegação, aplicativo ou atividade automática |
| Bloqueio DNS confirmado | O log associou uma resposta local de bloqueio à consulta |
| Conexão por IP | Estado disponibilizado pelo rastreamento de conexões; não inclui URL nem conteúdo |

O painel apresenta uma janela recente de eventos, não uma captura completa de toda a rede. Cache DNS nos clientes pode fazer uma conexão aparecer sem uma nova consulta. Conexões que passam por outro gateway não aparecem.

## Bloquear jogos e cadastrar sites

Cadastre o domínio, como `poki.com`, sem `https://`, caminho, porta ou curingas. O bloqueio abrange também seus subdomínios. As regras de domínio são globais para a rede do laboratório; esta versão não cria listas diferentes por aluno.

Para organizar a lista, use a categoria “Jogos” ou outra descrição. A categoria é um rótulo: a ferramenta não classifica automaticamente todos os jogos da internet. É necessário cadastrar os domínios conhecidos e complementar a lista conforme o uso observado.

Adicionar ou remover um domínio reinicia brevemente o DNS/DHCP dedicado para aplicar a configuração. As concessões já existentes são mantidas no arquivo de leases. A consulta seguinte passa pela lista atualizada; conteúdo em cache e conexões já abertas podem continuar. Para interromper imediatamente o tráfego encaminhado de uma máquina, use o corte de internet dessa máquina.

## Bloqueio de serviços de IA

A política de IA usa o catálogo `gateway/ai_services.json`, instalado ao lado do agente em `/opt/labguard/ai_services.json`. No gateway ela começa desativada; o responsável precisa ativá-la no painel. A ativação acrescenta os domínios do catálogo ao filtro DNS de todo o laboratório. A desativação retira essa política sem apagar domínios adicionados manualmente, inclusive um domínio que também faça parte do catálogo.

O bloqueio é global: inclui a máquina do professor quando ela usa o mesmo DNS. A proteção do IP administrativo impede o corte completo de internet, mas não cria exceção às regras de domínio.

Este controle abrange os domínios cadastrados e seus subdomínios. IA offline, recursos incorporados no mesmo domínio de um site permitido, caminhos específicos dentro de um site e serviços ainda não cadastrados exigem outras políticas. DNS não distingue um recurso de IA do restante de um serviço hospedado no mesmo domínio; bloquear esse domínio pode afetar funções adicionais. DNS criptografado, VPNs e cache têm as mesmas limitações descritas adiante.

Novos serviços podem ser incluídos na lista manual pelo painel. O catálogo embarcado é atualizado com uma nova versão do pacote; a atualização não elimina a lista manual mantida no estado do gateway.

## Integrações de roteadores

Marca ou operadora não define uma API única. Os adaptadores diretos apresentam suas capacidades e precisam de modelo, firmware, acesso de administração e configuração compatíveis. Uma integração de inventário não implica que o equipamento permita instalar regras de domínio ou cortar internet por máquina. Consulte [INTEGRACOES.md](INTEGRACOES.md) para escolher o caminho disponível no equipamento do colégio.

## Cortar internet de uma máquina

O agente valida se o endereço pertence à sub-rede, se foi observado e se está protegido. A regra limita o encaminhamento LAN–WAN; serviços no próprio gateway e comunicação local no mesmo switch não são o alvo desse corte. Por isso, o painel pode continuar disponível mesmo quando a internet da máquina está cortada.

O MAC observado complementa o bloqueio por IP. O temporizador do gateway atualiza os IPs associados a cada cinco segundos, sem depender do painel aberto. Uma mudança de concessão pode levar até a próxima execução bem-sucedida para se refletir no conjunto de endereços do firewall. Alterações deliberadas de MAC/IP, novas interfaces ou uma segunda rede exigem controles de acesso adicionais. Cadastre IPs administrativos em `protected_ips`, use contas de aluno sem privilégios administrativos e evite acesso físico à porta WAN.

## DNS criptografado, VPNs e IPv6

O gateway redireciona DNS convencional TCP/UDP na porta 53 e bloqueia o encaminhamento da porta 853 usada por DNS criptografado. DNS sobre HTTPS usa a mesma porta de sites HTTPS e pode contornar a lista DNS. Uma VPN também pode esconder os domínios consultados.

A gestão dos navegadores deve desabilitar DNS seguro fora da política do colégio e impedir que os alunos alterem essas opções. Se a escola precisa de resistência a evasão por VPN/DoH, é necessário complementar este pacote com políticas de endpoints e um firewall apropriado. A primeira versão não faz interceptação TLS, inspeção de conteúdo, descoberta de todas as VPNs ou bloqueio automático de todo site de jogos.

IPv6 é bloqueado no encaminhamento do laboratório nesta versão. Não reative IPv6 de saída sem implementar e validar regras equivalentes. Também mantenha flowtables/offload desabilitados no gateway.

## Registros e acesso

O painel opera com a chave SSH de administração. Mantenha a chave privada acessível somente aos responsáveis. Arquivos exportados podem conter IPs e domínios ligados à atividade do laboratório; limite o acesso aos responsáveis autorizados e adote o prazo de retenção do colégio.

O arquivo DNS tem rotação diária, até sete versões, com limite de tamanho para antecipar a rotação quando o serviço logrotate executar. Isso não é um limite rígido instantâneo do tamanho do arquivo. O estado do agente mantém regras e uma janela de auditoria. A interface de demonstração é inteiramente fictícia e está identificada no próprio painel.

## Referências técnicas

- [Manual oficial do dnsmasq](https://thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html): DNS/DHCP, log de consultas, domínio local, reinício e sinais.
- [Hooks do nftables](https://wiki.nftables.org/wiki-nftables/index.php/Netfilter_hooks): caminho de encaminhamento e prioridades.
- [Flowtables do nftables](https://wiki.nftables.org/wiki-nftables/index.php/Flowtable): desvio do caminho clássico de encaminhamento.
- [Encaminhamento IP no Linux](https://docs.kernel.org/networking/ip-sysctl.html): configuração `ip_forward`.
- [Manual oficial do OpenSSH](https://man.openbsd.org/sshd.8): verificação de host e restrições de chave em `authorized_keys`.
