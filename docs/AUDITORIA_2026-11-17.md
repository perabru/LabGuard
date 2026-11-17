# Auditoria do LabGuard — 17 de novembro de 2026

Escopo: conversa compartilhada LabGuard; site, manuais, Cliente Automático, Central, filtro TI, desinstalador e edições de rede/servidor.

## Correções

| Problema confirmado | Correção | Verificação |
|---|---|---|
| Falha de atualização podia deixar política e tarefas anteriores desativadas | Validação das duas tarefas antes da interrupção e recuperação da configuração/agendamentos/monitor | Teste Windows provoca falha na cópia do EXE e confere a recuperação |
| Desinstalador desconhecia os diários do catálogo completo 2.5 | Restauração de Chrome, Edge e Firefox, preservação de regras externas e retomada após falha | 11 testes do desinstalador e verificação nativa |
| Central podia mostrar online com proteção ainda não confirmada | Exige estados e revisões coerentes; telemetria inválida não grava eventos parcialmente | 29 testes gerenciados |
| Outra aplicação na porta da Central podia travar a conferência | Respostas JSON de tipo inesperado são tratadas como Central indisponível | Testes Central/TI e HTTP local |
| TI empacotava uma Central antiga de outro release | Compila a Central da mesma revisão e incorpora seu SHA-256 | Build TI e teste de convivência DNS/Central |
| Atualizador de rede poderia substituir a extensão TI | Canal TI abre os próprios pacotes; atualização pelo instalador TI, sem alterar a preferência original | 8 testes da edição TI |
| Serviço Linux não tinha permissão de porta 53 | Capacidade mínima CAP_NET_BIND_SERVICE com usuário dedicado | Regressão de empacotamento e systemd-analyze verify |
| Publicação do site reintroduzia downloads antigos | Página estática e preparador que apenas valida links, âncoras e versões | Validação do site e sintaxe JavaScript |

## Verificações locais

- 531 testes do núcleo aprovados.
- 66 testes do cliente executados: 63 aprovados e 3 reservados ao Windows.
- 29 testes gerenciados, 21 da Central, 8 da TI e 11 do desinstalador aprovados.
- DNS real em loopback com UDP/TCP, código de diagnóstico e encerramento dos listeners aprovados.
- Autotestes do painel, servidor e configuração do gateway aprovados.
- Manual unificado HTML/Markdown e PDF de 7 páginas revisado; guia do Automático com 3 páginas.

## Testes nativos e revisão visual

- [Rede Windows/Linux](https://github.com/perabru/LabGuard/actions/runs/44109529904): testes, diagnóstico de estação, instalação/abertura nativa, serviços e atualização Windows aprovados; publicação ignorada no PR.
- [Cliente, TI, desinstalador e site](https://github.com/perabru/LabGuard/actions/runs/44109531481): os quatro jobs aprovados, com pacotes e relatórios preservados como artefatos. O Cliente inclui falha provocada na atualização e recuperação do monitor/política; TI inclui atualização mantendo os dados e DNS funcionando após parar a Central.
- Prévia local conferida no navegador: início, downloads, manual, tema claro/escuro, suspensão/restauração da demonstração, ausência de imagens quebradas e largura de tela reduzida sem rolagem horizontal. Corrigida sobreposição dos rótulos de destino dos downloads.
- Gate de publicação: quatro testes offline aprovados; o Pages aguarda a disponibilidade dos assets referenciados antes de alterar o site.

As compilações verificadas usam a revisão 3b9f61d3266994f73bdaad553fc414c32fb20358. O ajuste visual e o gate posteriores não alteram código dos executáveis. Nenhum release ou site de produção foi publicado por estes testes.

## Requisitos e limites mantidos

Cliente local sem vínculo obrigatório, início com Windows, limpeza nominal a cada 5 minutos, monitor nominal de 2 segundos, catálogo de 839 domínios, Sites rápidos e YouTube, Central HTTPS opcional e preservação do vínculo. TI mantém bancos, mapas, relatórios, diagnóstico e DNS independente da Central. O domínio Joguester permanece pendente até cadastro do endereço real.

Não foram acessados nem modificados computadores reais do laboratório. Os testes usam loopback, dados fictícios e runners descartáveis. O funcionamento em cada estação depende de privilégios, políticas do Windows/navegadores e configuração de rede. A limpeza de jogos reconhecidos pode apagar saves e mundos; retirar o LabGuard não recupera dados já removidos. Capturas não são enviadas pela Central.
