# Identidade visual do LabGuard

A interface usa roxo como identidade principal, azul para ações de controle e amarelo para destaque. O fundo lavanda e os cartões brancos mantêm as informações fáceis de localizar.

| Uso | Cor |
|---|---|
| Marca e navegação | `#6C42D9` e `#29184F` |
| Ação principal | `#3478F6` |
| Destaque | `#F4C84A` |
| Fundo | `#F5F3FC` |
| Cartões | `#FFFFFF` |
| Texto | `#21183F` |

Os botões têm cantos arredondados, profundidade discreta, estados de foco/hover e acionamento por teclado. Os cartões organizam contadores, atalhos e formulários, preservando os recursos de administração. O modo demonstração permanece destacado em amarelo.

## Painel operacional da versão 1.4

O dashboard prioriza a leitura da operação: quatro indicadores compactos, confirmação dos serviços do gateway, domínios mais solicitados, atividade por máquina, solicitações DNS recentes e últimas ações administrativas. Os rankings são calculados exclusivamente a partir da amostra recebida; não representam visitas, todo o histórico de navegação nem contagens de pessoas.

O horário da leitura e o modo da sessão ficam visíveis. Uma consulta recente ao gateway é necessária para alterar a rede: leituras com mais de vinte segundos, erros de conexão e serviços necessários indisponíveis desabilitam as ações correspondentes. O painel mantém os dados anteriores para consulta, mas sinaliza quando eles não estão confirmados. A proteção é repetida nos métodos de ação; não depende apenas da aparência dos botões.

Os cartões de domínios e máquinas permitem abrir o histórico DNS filtrado com clique duplo. Tabelas e a área do painel possuem rolagem, preservando o acesso ao conteúdo em telas de 1024 × 700.

## Referências já usadas nos projetos do usuário

- [Botão de cssbuttons-io](https://uiverse.io/cssbuttons-io/nice-walrus-6).
- [Card interativo de ElSombrero2](https://uiverse.io/ElSombrero2/tricky-robin-67).
- [Card de alexmaracinaru](https://uiverse.io/alexmaracinaru/white-octopus-62).

São referências visuais para uma adaptação original em Tk. O aplicativo não incorpora um navegador nem depende de HTML/CSS para desenhar seus controles. Os componentes nativos estão em `labguard/ui.py`.
