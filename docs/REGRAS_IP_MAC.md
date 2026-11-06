# Bloqueios independentes de IP e MAC

O gateway aceita `set_address_block` com os parâmetros exatos `kind`, `address` e `blocked`. `kind` é `ip` ou `mac`; `blocked` precisa ser um booleano JSON. A chamada segue o protocolo existente `version=1`. O aplicativo recebe uma amostra completa após aplicar e persistir a alteração.

```json
{"version":1,"action":"set_address_block","params":{"kind":"ip","address":"192.168.50.101","blocked":true}}
```

Para MAC, use seis pares separados por dois-pontos. A entrada é normalizada para minúsculas. Endereços multicast, broadcast e zero são recusados. Um novo bloqueio exige um endereço observado nas concessões DHCP ou nos vizinhos da interface LAN. IPs precisam pertencer à sub-rede configurada e não podem ser os endereços de rede/broadcast. IPs protegidos e MACs observados em máquinas protegidas não podem receber um novo bloqueio. Regras já salvas podem ser removidas quando o cliente estiver offline.

Os escopos são independentes:

| Escopo | Comportamento |
| --- | --- |
| `device` | Operação existente `set_device_block`: mantém a política da máquina pelo MAC observado, com fallback IP quando não há MAC |
| `ip` | IP fixo: continua valendo para esse endereço se o DHCP o atribuir a outro cliente |
| `mac` | MAC: acompanha esse MAC quando aparece em outro IP visível na LAN |

Remover um escopo conserva os outros. Uma máquina só aparece liberada quando nenhum escopo efetivo permanece. Uma regra de domínio ou perfil de IA também pode continuar impedindo um site depois da liberação de internet por endereço.

As regras novas são persistidas na lista opcional `address_blocks` do estado versão 1, com `kind`, `address`, `created_at` e `name`. Estados existentes continuam aceitos; o dicionário legado `blocked` é preservado. A lista aparece no nível principal da amostra, inclusive para regras sem cliente online. O estado usa até 10.000 regras diretas e recusa duplicatas ou dados salvos inválidos.

Cada registro em `devices` inclui:

| Campo | Significado |
| --- | --- |
| `observed` | Há dado de concessão/vizinhança; `false` identifica somente um endereço de regra salva sem presença confirmada |
| `blocked_ip` | Uma regra direta de IP impede esse cliente |
| `blocked_mac` | Uma regra direta de MAC impede esse cliente |
| `blocked_by` | Escopos efetivos, na ordem `device`, `ip`, `mac` |
| `blocked` | Verdadeiro quando `blocked_by` não está vazio |

As exceções administrativas protegidas continuam anteriores aos cortes no firewall. Para esses IPs, os indicadores efetivos permanecem liberados. O conjunto `blocked_v4` reúne IPs fixos e IPs atuais de máquinas bloqueadas; o conjunto `blocked_mac` reúne MACs diretos e legados. A reconciliação existente acompanha mudanças DHCP. Os cortes usam somente a tabela LabGuard e são aplicados antes da aceitação de sessões estabelecidas. Flowtable/offload que possa desviar desse caminho impede afirmar que o corte foi aplicado. Falhas restauram as regras e o estado anteriores; a auditoria registra alterações e recusas sem copiar parâmetros extras.

## Wi-Fi

Os mesmos controles abrangem clientes Wi-Fi quando o ponto de acesso funciona como bridge e encaminha seus clientes pelo gateway LabGuard, preservando a visibilidade dos IPs e MACs. Nesse cenário, o tráfego chega pela LAN configurada, como o de uma máquina cabeada. O mapa usa dados observados; não identifica automaticamente SSIDs, antenas, portas físicas nem relações entre cabos.

Um roteador/AP fazendo NAT pode esconder os IPs e MACs individuais: o gateway pode enxergar apenas o próprio AP/roteador. Não bloqueie esse endereço esperando atingir um único aluno; isso pode afetar todos os clientes atrás dele. Coloque o AP no modo bridge com a equipe de rede antes de administrar clientes individualmente.

Uma VLAN Wi-Fi separada precisa ter roteamento, interface e visibilidade configurados para passar pelo gateway. A instalação atual gerencia a LAN/CIDR configurada e não descobre nem configura VLANs automaticamente. Outro roteador entre o cliente e o gateway pode substituir o MAC visível mesmo sem NAT; o controle individual por MAC exige visibilidade de camada 2.

Bloquear a internet não desconecta o rádio Wi-Fi nem desassocia o cliente do AP. IPs e MACs podem mudar ou ser alterados pelo dispositivo; esses controles não substituem autenticação e segmentação da rede escolar.

Referências técnicas primárias: [manual nftables](https://netfilter.org/projects/nftables/manpage.html), [bridge e roteamento na documentação nftables](https://wiki.nftables.org/wiki-nftables/index.php/Bridge_filtering).
