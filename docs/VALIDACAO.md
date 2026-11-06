# Validação da versão 2.0.1

Preparada em 6 de novembro de 2026. O assistente de identificação, os guias e o empacotamento Linux foram atualizados; os novos pacotes nativos aguardam o fluxo Windows/Linux. A validação e os links do lançamento serão registrados aqui após a compilação.

## Alteração desta versão

O desktop inclui **Não identificou? Ver passo a passo**, com orientação por sintoma e sistema. A consulta de diagnóstico não altera regras, rede, arquivos de configuração ou capacidades. O assistente não usa demonstração para substituir uma leitura falhada e não exibe segredos a partir das mensagens de erro. O painel de servidor oferece um guia equivalente. O pacote Debian passa a declarar a dependência `iproute2`; a versão portátil continua dependendo das ferramentas locais.

O manual inclui verificações de IP/gateway, inventário parcial, MAC ausente, modelo desconhecido e acesso HTTPS/API. Uma informação ausente nem sempre representa erro: o cache local é limitado, o MAC do próprio PC pode ficar vazio e a descoberta cobre IPv4 privada.

## Evidência anterior: 2.0.0

Publicada em 6 de novembro de 2026. O [fluxo completo no GitHub Actions](https://github.com/perabru/LabGuard/actions/runs/42291112160) passou para o commit `0aed0142ccaafe7ee903ef30f93e6e1becb4c013`. A [versão 2.0.0](https://github.com/perabru/LabGuard/releases/tag/v2.0.0) contém os seis pacotes desktop/servidor, quatro autotestes JSON e somas SHA-256.

A suíte completa de **277 testes** passou localmente e no Linux CI; os **233 testes compatíveis com Windows** também passaram. As etapas nativas validaram instalação, abertura da interface e serviços nas plataformas correspondentes. O site e o manual 2.0 passaram no [fluxo de publicação do Pages](https://github.com/perabru/LabGuard/actions/runs/42291112037).

## Escopo verificado

A versão 2.0 inicia em Observação local e usa quatro telas: Início, Dispositivos, Sites e Atividade. A observação consulta somente tabelas e configuração do próprio sistema; não faz varredura ativa nem aplica regras. A ausência de vizinhos ou de ferramentas locais produz um diagnóstico parcial, sem dispositivos inventados.

Os testes do controlador verificam isolamento da demonstração, capacidades, saúde, encerramento e autorização de escrita. O banco local preserva a intenção ao conectar o primeiro RouterOS, mantém bancos separados por destino e exige aplicação explícita. Relatórios identificam modo, fonte, horário e limites do inventário.

O adaptador RouterOS é testado com respostas REST simuladas, incluindo TLS obrigatório, ausência de redirecionamentos e proxy, limites de resposta, regras próprias, pares de bloqueio IP, proteção administrativa, alterações concorrentes, falhas parciais e confirmação posterior. Regras externas são preservadas. Essas verificações não equivalem a homologação em um roteador físico.

O servidor conserva autenticação, perfis de consulta/administração, validação de Host/Origin e arquivos privados. Seu controlador padrão também é Observação. O segredo do RouterOS fica separado da configuração pública. Os testes HTTP locais não utilizam equipamentos do colégio.

## Pacotes nativos

| Pacote | Verificação executada no fluxo 2.0.0 |
|---|---|
| Windows instalador e portátil | Compilação x64, instalação silenciosa, autoteste e abertura da janela em demonstração |
| Linux Debian e portátil | Compilação x86_64, instalação Debian, autoteste e janela real no Xvfb |
| Servidor Windows | Autoteste, serviço SCM, PowerShell 5.1, caminhos com espaços e permissões privadas |
| Servidor Linux | Autoteste, serviço systemd e resposta de saúde em demonstração isolada |

Os pacotes foram compilados no Windows x64 e Ubuntu 22.04 x86_64. A janela foi aberta em demonstração explícita; o modo de início padrão é Observação, confirmado também pelo autoteste do executável. O manual de 13 páginas foi renderizado e revisado; a versão HTML e o site foram conferidos em navegador.

Uma resposta HTTP 200 em `/healthz` confirma apenas o processo ativo. Demonstração e compilação não confirmam regras de rede, WinRM, SSH ou certificados do colégio. A [versão 1.4.0](https://github.com/perabru/LabGuard/releases/tag/v1.4.0) permanece disponível para o fluxo legado; seus pacotes não devem ser confundidos com 2.0.

## Homologação no colégio

Nenhum equipamento ou computador do colégio foi acessado ou alterado. Para bloquear na rede existente, o equipamento já responsável pelo tráfego precisa oferecer uma integração compatível. Estar na mesma LAN ou Wi-Fi, por si só, não concede controle sobre os outros dispositivos. O modelo e a API do modem Vivo ainda precisam ser identificados.

No RouterOS, confirme HTTPS e permissões, gateway DHCP, rede do laboratório, lista WAN, DNS entregue aos clientes, IPv6, FastTrack e offload. O programa não muda essas configurações gerais para liberar ações. O filtro DNS exige RouterOS 7.18 ou superior e DNS compatível; IP/MAC são escopos independentes. Não há histórico DNS por cliente nem inventário de processos por esse adaptador.

Comece por uma estação de teste. Confirme fisicamente IP/MAC e proteção administrativa. Aplique e remova um domínio controlado, teste corte e restauração por IP e confira as regras diretamente no equipamento. Cache, VPN, DoH, IPv6 e caminhos alternativos exigem avaliação no ambiente. MAC privado ou oculto por NAT reduz a identificação; o mapa é lógico, não comprova cabos ou associação Wi-Fi.

A administração de programas exige WinRM HTTPS ou SSH previamente preparado. Remoções e avisos continuam limitados ao catálogo e às permissões da estação. Nenhum jogo real foi removido durante os testes. Consulte o [manual 2.0](MANUAL_DO_USUARIO_V2.html), o [roteador direto](ROTEADOR_DIRETO.md), [servidores](SERVIDORES.md) e [administração remota](ADMINISTRACAO_REMOTA.md).
