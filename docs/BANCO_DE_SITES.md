# Banco de sites proibidos

O LabGuard mantém um banco SQLite local com os domínios cadastrados pela escola. Cadastrar, editar, desativar, importar ou excluir um item salva a política desejada. **A rede só é alterada pela ação explícita de aplicar/sincronizar com o gateway.** O modo de demonstração simula essa aplicação.

Cada registro contém domínio normalizado, categoria, estado ativo, observações de até 500 caracteres, datas e revisão. As categorias são Jogos, Inteligência artificial (também aceita `IA`), Adultos e Outros. As categorias são rótulos administrativos; não fazem classificação automática de conteúdo. Domínios internacionais são armazenados em IDNA. URLs, caminhos, portas, IPs e curingas são recusados; o bloqueio do domínio inclui seus subdomínios conforme o gateway.

## Cadastro e aplicação

1. Adicione um domínio ou importe uma lista de até 1.000 itens. Duplicatas são normalizadas e ignoradas. Registros existentes conservam categoria, observações e estado, inclusive quando estão desativados.
2. Revise os itens ativos e escolha aplicar no gateway. Uma amostra atual, de até 45 segundos, com DNS saudável é obrigatória.
3. Confira o resultado: aplicações confirmadas, regras externas preservadas, pendências e resultados incertos. Uma edição durante a aplicação continua pendente para a próxima passagem.

O banco suporta até 50.000 registros, incluindo exclusões lógicas. Cada lote executa no máximo 100 alterações de rede, com limite menor configurável pela interface. As operações existentes do gateway reiniciam a configuração DNS por domínio; lotes grandes podem levar vários minutos. A aplicação pode ser interrompida entre domínios, sem cancelar a operação que já está em andamento. O lote não é uma transação única de rede: sucessos anteriores permanecem aplicados quando uma operação posterior falha.

Desativar ou excluir um cadastro só remove uma regra que este banco criou e confirmou. Regras que já existiam no gateway são preservadas. O perfil de IA permanece independente: retirar uma regra manual criada pelo banco pode deixar o mesmo domínio bloqueado pelo perfil de IA. A interface deve explicar a preservação desse bloqueio.

## Propriedade e falhas

Na primeira sincronização, o banco fica vinculado a modo, endereço e porta do transporte, nome do gateway e CIDR do laboratório. Uma mudança nessa identidade impede aplicar o mesmo banco ao novo destino. Utilize um banco separado por gateway. Essa vinculação evita confusão de equipamentos; a autenticação do equipamento continua sendo responsabilidade do transporte SSH e de sua chave de host.

Para regras criadas pelo banco, uma impressão dos metadados do gateway (domínio, categoria, criação e origem manual) precisa continuar igual antes da remoção. Uma regra substituída por outro administrador perde a propriedade local. O gateway não expõe identificadores exclusivos de proprietário: os metadados são uma proteção conservadora, e o administrador deve evitar gerenciar simultaneamente a mesma regra por ferramentas diferentes.

A intenção é persistida antes da chamada de rede. Uma perda de conexão ou falha de gravação após a chamada produz resultado **incerto**, sem afirmar que a regra foi aplicada. A amostra anterior não é retornada como confirmação. Ao reencontrar um domínio após inclusão incerta, o banco o trata como externo e não o remove automaticamente. O administrador deve atualizar o painel e revisar o gateway. Isso pode deixar um bloqueio preservado, mas evita remover um bloqueio cuja propriedade não pôde ser comprovada.

## Armazenamento e acesso

O módulo `labguard.banlist` usa somente bibliotecas padrão do Python e não exige cadastro em serviços externos. O aplicativo define o caminho do banco; o servidor usa seu subdiretório privado `data`. O caminho padrão do módulo fica na pasta de configuração do usuário. Não coloque o banco em compartilhamento de rede.

Em Linux, o diretório final precisa pertencer ao usuário do processo e ser privado (`0700`), assim como o arquivo (`0600`). Arquivos que sejam links simbólicos e caminhos com links são recusados. No Windows, o instalador/administrador deve manter as permissões de acesso da pasta de dados. O arquivo não é criptografado e não armazena senhas, tokens de API ou chaves SSH.

As consultas usam parâmetros SQL, as escritas usam transações com sincronização completa e há espera limitada para contenção. Cada conexão é curta; um bloqueio em memória protege as threads e uma concessão persistida impede dois lotes simultâneos no mesmo banco. Revisões opcionais impedem que uma tela desatualizada sobrescreva a edição de outro administrador. A interface e a API devem exigir o papel de administrador para alterações e aplicação.

O modo WAL é utilizado com SQLite 3.51.3 ou superior e nas séries corrigidas 3.50.7+ e 3.44.6+. Em versões anteriores, utiliza-se o journal tradicional `DELETE` para evitar a falha concorrente WAL-reset documentada pelo SQLite em 2026. Não é necessário instalar outra dependência para esse comportamento.

A auditoria conserva até 10.000 eventos de cadastro e sincronização, sem copiar observações ou mensagens brutas de conexão. Não é uma trilha imutável contra quem possui acesso administrativo ao computador. A exclusão é lógica, para manter o histórico e a remoção pendente de regras próprias. A exportação CSV inclui os cadastros não excluídos; células que possam começar uma fórmula de planilha recebem um apóstrofo de proteção.

Para copiar o arquivo como backup, feche as aplicações que o utilizam ou use a API de backup do SQLite. Um arquivo `-wal` existente faz parte do estado do banco e não deve ser removido manualmente.

## Contrato para integrações

`BanlistDatabase(path)` (alias `BanlistStore`) oferece `list_sites`, `upsert`, `delete`, `import_domains`, `export_csv`, `summary`, `audit` e `sync`. Erros previstos usam `BanlistError`. `close()` existe para integração com o ciclo de vida da aplicação; as conexões já são fechadas após cada operação.

`summary()` devolve `total`, `enabled`, `disabled`, `deleted`, `owned_rules`, `pending` e `uncertain`. `sync(transport, limit=100, cancel_event=None)` usa apenas `snapshot`, `add_domain` e `remove_domain` do transporte existente e devolve:

| Campo | Conteúdo |
| --- | --- |
| `applied` | Lista de alterações confirmadas, com `domain` e `action` |
| `operations` | Detalhes das chamadas de alteração e dos resultados incertos |
| `errors` | Falhas sem confirmação; não contém mensagens brutas do transporte |
| `pending` | Quantidade de cadastros com aplicação ainda pendente |
| `preserved` | Quantidade de regras externas preservadas nesta passagem |
| `snapshot` | Última amostra confirmada, ou `None` quando houver incerteza |
| `target` | Identidade à qual o banco está vinculado |
| `cancelled` | Interrupção solicitada entre domínios |

As listas de resultados não tornam uma alteração incerta em sucesso. `expected_revision=0` exige um cadastro novo; um número maior exige a revisão correspondente. A omissão permite atualização explícita sem verificação de revisão.

Referências primárias: [sqlite3 do Python](https://docs.python.org/3/library/sqlite3.html), [WAL e aviso WAL-reset do SQLite](https://sqlite.org/wal.html).
