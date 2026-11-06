# Proteções do gateway

Esta versão reforça o agente Linux que aplica as regras. As proteções abaixo passam a valer depois de atualizar a instalação do gateway. Instalar somente o novo painel Windows não atualiza o servidor Linux.

## Acesso administrativo

A conexão continua usando SSH com chave e verificação da identidade do servidor. A chave da conta `labguard` está vinculada a um comando forçado, sem terminal ou encaminhamento de portas. O sudo autoriza somente o wrapper instalado, sem argumentos; o wrapper limpa o ambiente e inicia o Python em modo isolado.

Antes de executar uma operação privilegiada, o agente verifica proprietário e permissões de seus arquivos, catálogo, configuração e diretórios administrativos. Arquivos ou ancestrais substituíveis por outro usuário, links simbólicos e configuração/estado com leitura fora do administrador são recusados. A configuração e o estado devem usar permissão `0600`.

O administrador Linux ainda controla o sistema. Essas verificações não tornam os registros imutáveis e não impedem um administrador root de alterar o programa ou os dados.

## Limites de recursos e validação

O agente aceita um objeto JSON por linha ou encerramento da entrada, limitado a 8 KiB e dez segundos para recebimento. Uma conexão que não envia a solicitação completa não mantém um processo privilegiado esperando indefinidamente. O bloqueio de concorrência espera até oito segundos; depois disso, o painel recebe uma indicação de gateway ocupado.

Configuração, estado, catálogo, arquivo de concessões e amostras de log têm leituras limitadas. Arquivos de dados precisam ser regulares: o agente não segue links simbólicos nem abre FIFOs ou dispositivos. Isso é especialmente relevante para os dados escritos pelo serviço DNS/DHCP, que usa uma conta sem privilégios.

Domínios, sub-redes, interfaces, endereços protegidos, tipos booleanos, versão e parâmetros aceitos continuam sendo validados. Solicitações não oferecem comandos livres de shell. Uma falha de validação não aplica regras de rede.

## Auditoria e confirmação do resultado

Além das alterações aplicadas, a auditoria registra operações administrativas recusadas ou que falharam. Ela guarda a operação e um alvo validado; os parâmetros brutos recebidos não são gravados. O arquivo permanece sob controle do administrador e conserva uma janela de até mil eventos, dos quais até 250 são apresentados no painel.

Se uma alteração já foi aplicada e salva, mas a coleta de diagnóstico posterior falha, a resposta informa explicitamente que a alteração foi salva. Nesse caso, os serviços são apresentados como indisponíveis para verificação, e não há amostra de atividade inventada. Atualize o painel antes de outra alteração.

A restauração após falha na aplicação de DNS/firewall continua disponível. Se a restauração também falhar, o erro informa essa condição para o responsável verificar o gateway localmente.

## Serviços isolados

As unidades systemd usam diretórios de escrita delimitados, sistema de arquivos protegido, isolamento de arquivos temporários, bloqueio de acesso a diretórios pessoais e proibição de obter novos privilégios por execução. Os serviços de aplicação e reconciliação também têm prazo máximo de inicialização.

O DNS/DHCP só pode gravar em seu diretório de concessões e nos logs do LabGuard. O agente de aplicação mantém acesso de escrita à sua configuração, estado e logs. As permissões necessárias a DNS, DHCP e nftables são preservadas.

Essas unidades devem ser verificadas na distribuição Linux de destino. Os testes de desenvolvimento simulam os comandos de rede; não substituem uma instalação de teste com duas interfaces.

## Atualização e alcance

Faça a atualização pelo procedimento de instalação existente, no console administrativo do gateway, com a configuração e a chave pública corretas. O instalador conserva o estado e cria backup da configuração anterior quando já existe uma instalação. Comece novamente por uma máquina de teste antes de conectar a turma.

O programa não altera a porta do SSH, não desativa contas administrativas e não substitui regras de entrada de outros firewalls. A rede de gerenciamento e as permissões dos responsáveis continuam sob a política do colégio. Modelos locais de IA, VPNs e DNS sobre HTTPS continuam tendo os limites documentados em [ALCANCE.md](ALCANCE.md).

## Referências técnicas

- [OpenSSH — daemon, autenticação e opções de chaves](https://man.openbsd.org/sshd.8).
- [Python — espera de entrada e saída com select](https://docs.python.org/3/library/select.html).
- [systemd — isolamento e permissões de execução](https://freedesktop.org/software/systemd/man/latest/systemd.exec.html).
