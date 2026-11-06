# Mapa da rede e controle por endereço

No painel principal, abra **Mapa da rede**. A janela usa o inventário já obtido pelo painel; não inicia varreduras, não captura conteúdo de navegação e não faz conexões próprias com equipamentos.

A aba **Mapa lógico** desenha o gateway, a rede LAN/Wi-Fi e os equipamentos encontrados nas evidências disponíveis. As linhas tracejadas representam relações lógicas inferidas no segmento. Elas não identificam cabos físicos, portas de switches, pontos de acesso ou topologia física confirmada.

Os cartões exibem nome, IP, MAC, evidência e bloqueio. Concessão DHCP ativa ou expirada, entrada de vizinhança e último registro são evidências distintas; nenhuma delas confirma que uma máquina está conectada neste instante. Um registro com `observed=False` aparece em cinza, como regra salva sem observação recente. Regras salvas cujo endereço não aparece no inventário continuam disponíveis para desbloqueio.

A janela atualiza a leitura do snapshot local a cada segundo. Sem mudança nos dados ou no filtro, não redesenha o mapa. A atualização de rede continua sob responsabilidade do painel principal. Se a fonte falhar ou o painel indicar dados desatualizados, os últimos dados permanecem visíveis e as ações reais ficam suspensas.

## Selecionar e controlar

Clique em um cartão ou em uma linha da aba **Inventário completo**. A lateral exibe os detalhes e quatro ações independentes:

| Ação | Regra afetada |
|---|---|
| Bloquear IP | Endereço IPv4 selecionado |
| Desbloquear IP | Somente a regra do IPv4 selecionado |
| Bloquear MAC | Endereço MAC selecionado |
| Desbloquear MAC | Somente a regra do MAC selecionado |

Os bloqueios ativos por endereço vêm de `address_blocks`. Se ambos os endereços estiverem bloqueados, liberar apenas o IP mantém o bloqueio do MAC, e vice-versa. O controle usa o gateway do laboratório e afeta o tráfego encaminhado por ele. Não desliga o computador nem o rádio Wi-Fi.

Equipamentos protegidos não podem ser bloqueados ou desbloqueados por essa janela. Sessão bloqueada, operação em andamento, endereço ausente/inválido e inventário desatualizado também impedem ações. Novos bloqueios exigem um equipamento observado; regras salvas sem evidência recente permitem apenas remoção. O painel principal verifica novamente as condições, solicita a confirmação aplicável e envia a operação fora da interface gráfica.

A busca aceita nome, IP, MAC e estado. O mapa desenha até 200 cartões do filtro para manter a interface utilizável; a tabela mostra todos os registros do filtro. A lateral de ações tem rolagem própria para manter os controles acessíveis em telas menores. O filtro não limita as exportações.

## Wi-Fi

Máquinas de uma rede Wi-Fi em ponte com a LAN podem aparecer no mesmo inventário quando seu tráfego passa pelo gateway monitorado. O mapa mostra `connection_type`, SSID e AP apenas quando esses campos forem fornecidos pela fonte. Sem essa evidência, informa que cabo/Wi-Fi, SSID e AP não foram identificados. Não deduz uma conexão sem fio a partir do MAC.

Bloquear IP ou MAC corta o encaminhamento da internet pelo gateway conforme suas regras. A ação não expulsa a estação do ponto de acesso e não altera senha, associação ou sinal Wi-Fi. Redes de convidados, VLANs ou pontos de acesso que utilizam outra saída precisam estar no caminho do gateway ou receber uma integração específica.

## Exportações

- **Salvar mapa SVG:** grava um desenho vetorial com até 200 nós do inventário para abrir em navegador ou editor compatível.
- **Relatório HTML:** grava um relatório para consulta local e impressão, com desenho de até 200 nós e inventário de até 10.000 registros.
- **CSV:** exporta até 10.000 registros do inventário em dados tabulares.
- **PDF:** grava o relatório para compartilhar ou imprimir. O desenho resume até 12 nós; a tabela inclui até 10.000 registros do inventário.

As exportações usam o snapshot disponível, independentemente da busca. Os desenhos SVG/HTML incluem até 200 nós; o desenho PDF inclui até 12 nós. O inventário tabular inclui até 10.000 registros; HTML/PDF também apresentam até 10.000 regras diretas e os dez domínios mais solicitados da amostra de até 1.000 consultas DNS recentes. As quantidades recebidas e exportadas aparecem nos relatórios. Regras salvas podem ser apresentadas em uma seção própria; um cartão sintético criado apenas para facilitar a remoção de uma regra não cria uma máquina descoberta no relatório. Preserve a indicação de demonstração e a data de coleta ao compartilhar. Os dados podem conter identificadores de equipamentos e registros de uso; compartilhe apenas com os responsáveis autorizados.

No modo **DEMONSTRAÇÃO**, todos os equipamentos e eventos são fictícios e nenhuma regra é aplicada à rede real. A faixa amarela permanece visível no mapa.
