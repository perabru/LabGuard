# Integrações diretas com roteadores e switches

> **LabGuard 2.0:** os perfis desta central são independentes da nova conexão direta RouterOS em **Início → Conectar roteador**. O perfil antigo RouterOS desta central continua sendo consulta. As regras diretas da nova conexão dependem das capacidades e dos requisitos confirmados pelo equipamento; veja o [manual 2.0](MANUAL_DO_USUARIO_V2.html).

A central **Roteadores e switches** é separada da conexão com o gateway Linux. Ela acessa somente o equipamento que o administrador indicar, usando os recursos declarados pelo perfil. A existência de uma marca na lista não significa compatibilidade com todos os seus modelos.

## Perfis fornecidos e alcance

| Família | Acesso | Recursos desta versão |
|---|---|---|
| Cisco IOS / IOS XE | SSH com chave, conta administrativa já autorizada | Inventário e ativação/desativação de portas de acesso explicitamente autorizadas |
| TP-Link JetStream gerenciável com CLI compatível | SSH com chave, acesso administrativo já configurado | Inventário e ativação/desativação de portas de acesso explicitamente autorizadas |
| MikroTik RouterOS 7 | API REST sobre HTTPS | Inventário; as capacidades exibidas pelo perfil delimitam o suporte |
| OpenWrt com ubus acessível por SSH | SSH com chave | Inventário; as capacidades exibidas pelo perfil delimitam o suporte |
| Embratel | Depende do equipamento fornecido | Cadastre o fabricante e modelo reais. A operadora não possui uma API universal para todos os roteadores e switches |
| Outro fabricante | Perfil declarativo revisado pelo responsável técnico | Somente os recursos expressamente definidos e validados no perfil |

Os perfis são baseados nas interfaces de administração documentadas. Os testes incluídos usam respostas simuladas; nenhum modelo físico foi validado neste ambiente. Revise o modelo, firmware, sintaxe e privilégios antes de operar uma porta de produção. TP-Link doméstico, controlador Omada e switch JetStream não são interfaces intercambiáveis.

## Preparar uma conexão

1. Habilite a interface de administração suportada no equipamento, conforme seu manual. Use uma conta autorizada e a rede de gerenciamento do colégio.
2. Para SSH, configure a chave pública da conta. Confira a impressão digital do servidor pelo console ou canal administrativo confiável e registre-a em `known_hosts`. A central não aceita automaticamente identidades desconhecidas ou alteradas.
3. No painel, informe o perfil, endereço, porta, usuário e caminho da chave. Para RouterOS HTTPS, informe a senha da sessão e, quando necessário, o arquivo da autoridade certificadora. Não desative a verificação do certificado.
4. Informe apenas as **portas de acesso autorizadas**, separadas por vírgulas. Por exemplo, portas ligadas a computadores de teste. Não autorize uplinks, trunks, portas agregadas nem a porta usada para gerenciar o equipamento.
5. Clique em **Conectar e consultar**. Confira o inventário e as capacidades apresentadas. A consulta não deve mudar a configuração.

As credenciais ficam na memória da sessão e não são gravadas nos perfis. O cliente OpenSSH do sistema é necessário para perfis SSH. No Windows, habilite **Cliente OpenSSH** em Recursos opcionais; no Linux, instale `openssh-client`. Chaves protegidas por senha devem estar carregadas no `ssh-agent`. Não há download automático nem execução silenciosa de instaladores de sistema.

As consultas precisam retornar sem paginação. O adaptador Cisco solicita `terminal length 0`; para TP-Link, desabilite a paginação conforme o manual do firmware e da sessão utilizada. Se a resposta contiver indicação de continuação, o adaptador recusa usar um inventário parcial para liberar o controle de portas.

## Desativar uma porta

Selecione uma linha de **Porta**, confira a identificação física e use **Desativar porta**. A central exige confirmação e o adaptador recusa portas fora da lista autorizada. **A ação corta toda a conectividade dessa porta**, inclusive serviços locais, e pode afetar mais de uma máquina se houver um switch, telefone ou ponto de acesso conectado nela.

Use **Ativar porta** para reativar administrativamente. Essa ação não garante que o cabo esteja conectado ou que o cliente esteja ligado. Se a resposta do equipamento não confirmar o estado, confira localmente antes de repetir.

O programa não salva automaticamente a configuração do switch na memória de inicialização. Avalie a política de persistência no equipamento antes de reiniciar. Não use essa função como substituta do bloqueio de internet por máquina do gateway.

## Sites e serviços de IA

O controle de portas é diferente do filtro de domínios. Um switch de camada 2 geralmente não oferece a mesma capacidade do gateway. Os perfis desta versão mostram suas capacidades reais; quando `bloqueio de domínios` não estiver disponível, o bloqueio de jogos e serviços de IA continua sendo feito pelo gateway Linux do LabGuard.

O perfil de IA bloqueia os domínios cadastrados e seus subdomínios. Ele não identifica todo uso de IA, não lê conteúdo HTTPS e não bloqueia modelos locais sem rede. Recursos de IA integrados a serviços maiores, VPNs e DNS criptografado exigem políticas complementares. Evite bloquear um domínio compartilhado amplo sem avaliar o impacto nos recursos pedagógicos.

## Adicionar fabricantes e baixar perfis

Na aba **Adicionar adaptadores**, use **Instalar perfil JSON / ZIP local** para importar um perfil declarativo revisado. Um ZIP deve conter o arquivo `profile.json` exigido pelo formato do adaptador. O importador valida o formato e os limites; ele não executa arquivos Python, scripts, instaladores ou comandos de instalação de pacotes.

Para baixar um perfil, preencha uma URL HTTPS e o **SHA-256 esperado**, obtido de uma fonte confiável, e use **Baixar, verificar e instalar perfil**. O hash detecta alteração nos bytes; ele não prova a confiabilidade de quem publicou o perfil. Não existe um catálogo público universal embutido que garanta suporte a qualquer marca. Nunca instale perfis recebidos de alunos ou de fontes não verificadas.

Um perfil declarativo não torna duas CLIs incompatíveis equivalentes. Caso o equipamento exija outra API, protocolo ou privilégio, será necessário implementar e revisar um adaptador correspondente. Não há tentativa de descobrir senhas, habilitar serviços remotamente, substituir o firmware ou reconfigurar a rede inteira.

Perfis de consulta genérica podem apresentar o retorno no botão **Ver saída de consulta**, em vez de tabelas estruturadas. O conteúdo é somente leitura e limitado em tamanho. O arquivo [perfil_novo_fabricante.json](../examples/perfil_novo_fabricante.json) mostra o formato aceito; substitua seus campos de exemplo e confirme o comando no manual do equipamento antes de importar. A origem de exemplo deve ser substituída pelo endereço HTTPS real da documentação do fabricante. Um ZIP deve conter somente `profile.json`, sem pastas ou arquivos adicionais.

## Teste recomendado

Comece com uma porta de acesso de teste e acesso local de recuperação ao equipamento. Consulte o inventário; confirme a máquina física; desative e reative a porta; confira o estado administrativo e operacional. Só depois autorize outras portas. Mantenha o laboratório isolado e os equipamentos de gerenciamento protegidos.

## Documentação técnica dos fabricantes

- [Cisco Catalyst 9300 — características de interfaces, IOS XE 17.9](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-9/configuration_guide/int_hw/b_179_int_and_hw_9300_cg/configuring_interface_characteristics.html).
- [TP-Link — gerenciamento de interfaces físicas e tabela de modelos aplicáveis](https://www.tp-link.com/us/configuration-guides/managing_physical_interface/).
- [MikroTik — API REST do RouterOS](https://manual.mikrotik.com/docs/developer-guides/rest-api/).
- [OpenWrt — ubus](https://openwrt.org/docs/techref/ubus).
