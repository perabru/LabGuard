# LabGuard 2.2

Painel em Python para conhecer a rede do laboratório e administrar os equipamentos compatíveis que já estão nela. A nova interface reúne **Início, Dispositivos, Sites e Atividade**.

**Começa em Observação real:** consulta o computador, a rota padrão e os vizinhos conhecidos, com leituras locais alternativas quando o método principal falha. O resumo indica origem, recência e limites da amostra. Para começar, não precisa trocar cabos, instalar gateway ou informar credenciais.

[Comece aqui](docs/COMECE_AQUI.md) · [Manual 2.0](https://perabru.github.io/LabGuard/manual2/index.html) · [Manual em PDF](docs/Manual_LabGuard_2.pdf) · [Versões e downloads](https://github.com/perabru/LabGuard/releases) · [Site](https://perabru.github.io/LabGuard/)

## Início e atualizações

Ao abrir, o desktop inicia a observação real em segundo plano. A configuração do equipamento é feita na primeira utilização; o acesso automático opcional ao RouterOS começa em consulta, sem aplicar listas ou restaurar autorização de alterações. No Windows, a senha dessa opção fica no cofre do sistema; o JSON de preferências contém somente configurações permitidas.

A instalação por usuário no Windows pode verificar e preparar versões estáveis oficiais e aplicá-las ao encerrar voluntariamente o programa. A janela não é fechada para forçar a atualização. A conferência usa HTTPS e SHA-256 do repositório fixo `perabru/LabGuard`; esses controles não equivalem a uma assinatura digital independente do autor. A migração das versões antigas exige instalar a 2.2 uma vez, pois elas não possuíam esse mecanismo. Pacotes portáteis, Linux, servidores e instalações administradas podem exigir atualização pela TI; não há elevação automática.

O programa aceita perfis de equipamentos compatíveis. Não existe uma integração universal que administre todos os modelos de rede ou elimine a necessidade de acesso autorizado.

## Como interpretar o inventário

A lista mostra endereços com evidências, sem garantir que representam todas as máquinas físicas ou que continuam conectados. O mesmo computador pode usar vários IPs e MACs; esses dados não identificam uma pessoa. A interface separa leitura parcial, dados indisponíveis, demonstração e coleta antiga. Identidades conflitantes exigem conferência antes de uma ação.

Estar na mesma rede não garante visibilidade de VLANs, clientes isolados, equipamentos silenciosos ou redes atrás de NAT. Para ampliar a amostra, conecte uma fonte administrativa compatível já preparada pela TI. O software não tenta senhas, não intercepta tráfego e não usa dados fictícios como recuperação de falhas.

## Se a identificação falhar

1. Em **Início**, clique **Não identificou? Ver passo a passo**.
2. Confira o sintoma e siga as etapas de leitura para seu sistema.
3. Use **Atualizar consulta**. O assistente não aplica regras nem muda cabos, DNS ou firewall.
4. Para modelo desconhecido ou acesso à API recusado, confira etiqueta, modelo, firmware, certificado e permissões com a TI.

Poucos vizinhos e o MAC vazio do próprio PC podem ser limitações da amostra. Consulte o [passo a passo completo](https://perabru.github.io/LabGuard/manual2/index.html#erro-de-identificacao) ou o [diagnóstico técnico](docs/DIAGNOSTICO_DA_REDE.md). Não compartilhe senhas, tokens ou chaves.

## O que cada modo oferece

| Modo | Uso |
|---|---|
| Observar esta rede | Inventário local limitado à rota e aos vizinhos conhecidos; não aplica bloqueios |
| Controlar MikroTik via HTTPS | API REST RouterOS 7, com ações condicionadas às permissões e configuração compatível |
| Outros equipamentos | Perfis com capacidades específicas por modelo e protocolo |
| Abrir demonstração | Dados fictícios identificados para aprender |
| Gateway SSH existente | Caminho avançado opcional para o agente Linux legado |

O controle do MikroTik começa sem autorização para escrever. Para aplicar sites ou bloquear endereços, o responsável precisa autorizar alterações e atender aos requisitos apresentados: rede, lista WAN, permissões, DNS compatível e verificações de FastTrack/IPv6. A conexão usa IP literal e certificado com SAN de tipo IP. O programa não muda essas configurações gerais automaticamente.

Identificar um modem Vivo, TP-Link ou outro roteador não fornece uma API universal. Observação continua disponível; o controle depende do modelo e firmware reais.

## Recursos

- Dispositivos com IP, MAC e evidência disponível; no MikroTik direto, bloquear/desbloquear IP mantém independente uma regra por MAC.
- Banco SQLite de sites, categorias, importação/exportação e aplicação explícita.
- Perfil de domínios de IA, preservando regras manuais ao desativá-lo.
- Atividade por fonte, com indicação quando não há histórico DNS por cliente.
- Mapa lógico e relatórios SVG, HTML, CSV e PDF, conforme o pacote.
- Programas e avisos por WinRM HTTPS ou SSH já preparados, com operações limitadas por catálogo.
- Servidor administrativo Windows/Linux, painel web local e controlador selecionável.

Observação não intercepta páginas nem mostra os sites de todas as máquinas. Consultas DNS não comprovam visitas e não revelam conteúdo HTTPS. O filtro cobre domínios cadastrados; IA offline, serviços em domínios compartilhados, VPNs e DoH exigem outras políticas.

No MikroTik direto, o catálogo de IA pode ser adicionado ao banco e aplicado como lista de domínios. O perfil global separado exige outra fonte compatível. Esse adaptador não fornece histórico DNS por cliente nem lista de conexões. Os bancos ficam separados por destino, com reaproveitamento da lista inicial na primeira conexão e isolamento da demonstração.

## Executar pelo código-fonte

Use Python 3.10 ou superior com Tcl/Tk:

```bash
python3 main.py
```

No Debian/Ubuntu, instale `python3-tk` se necessário. No Windows, use também `iniciar.bat`. Recursos opcionais dependem das bibliotecas de `requirements.txt`; instale-as no ambiente usado para executar o projeto.

A versão **2.2.0**, com início e atualizações automáticos nos cenários compatíveis, está em validação dos pacotes nativos. A [versão 2.1.0](https://github.com/perabru/LabGuard/releases/tag/v2.1.0) permanece como base anterior verificada; acompanhe os novos [pacotes](https://github.com/perabru/LabGuard/releases) e a [validação](docs/VALIDACAO.md).

## Documentação e legado

[Manual 2.0 em Markdown](docs/MANUAL_DO_USUARIO_V2.md) · [Administração remota](docs/ADMINISTRACAO_REMOTA.md) · [Integrações](docs/INTEGRACOES.md) · [Validação](docs/VALIDACAO.md)

O [manual 1.4](docs/MANUAL_DO_USUARIO.md) e o [PDF 1.4](docs/Manual_LabGuard_1.4.pdf) foram preservados para o modo avançado legado. Duas interfaces e gateway Linux pertencem a esse modo; não são requisito do novo início em Observação.

## Testes

```bash
python3 -m unittest discover -s tests -v
```

Os testes automatizados não substituem homologação no equipamento do colégio. Comece por uma máquina de teste e confirme o resultado na estação antes de usar com a turma.
