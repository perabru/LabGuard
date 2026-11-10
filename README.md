# LabGuard 2.4.3

**Edição de rede, administrada pelo técnico, sem instalar o LabGuard nos computadores dos alunos.** O painel 2.4.3 e seu filtro DNS rodam no PC da TI. As estações usam o IP desse computador como DNS, distribuído pelo DHCP/LAN do roteador quando disponível ou configurado no Windows. O Vivo e o switch Mercusys simples continuam no lugar.

## Baixar a versão de rede

- **[LabGuard-Setup.exe 2.4.3 — instalar no PC do técnico](https://github.com/perabru/LabGuard/releases/download/v2.4.3/LabGuard-Setup.exe)**
- [LabGuard-Portable.zip 2.4.3 — pacote portátil](https://github.com/perabru/LabGuard/releases/download/v2.4.3/LabGuard-Portable.zip)
- **[Guia do técnico sem cliente](https://perabru.github.io/LabGuard/tecnico/)**
- [Todos os pacotes 2.4.3 e SHA-256](https://github.com/perabru/LabGuard/releases/tag/v2.4.3)

Esta retomada usa o aplicativo 2.4.3 já publicado. O executável principal permanece igual ao dessa versão; o site e este guia voltam a apresentar o funcionamento pela rede.

## Começar sem cliente nas estações

1. Instale o **LabGuard-Setup.exe** no PC do técnico. Ao abrir, o programa começa em **Observação real**; essa leitura ainda não aplica bloqueios.
2. Reserve o IPv4 desse PC. Em **Configurar → 1. Ligar filtro**, escolha a conexão do laboratório; use **Ajustar IP / DNS** para conferir o **IP deste PC**, a **Rede autorizada (CIDR)** e o resolvedor de saída adequado à escola. Autorize e use **Iniciar filtro DNS**. **Proteger laboratório** permite revisar e aplicar a lista inicial de domínios de jogos e adultos.
3. Permita **UDP e TCP 53** entre a rede do laboratório e o filtro. No DHCP/LAN do Vivo, quando o modelo permitir, distribua o IP do PC da TI como DNS. Outra opção é a configuração de DNS do adaptador Windows. O [guia sem cliente](https://perabru.github.io/LabGuard/tecnico/#dns) detalha os dois caminhos. Preserve o IP, o gateway e os serviços internos da escola.
4. No PC do técnico, abra **Configurar → 3. Testar → Diagnóstico manual**. Copie os testes direto e padrão e execute-os no CMD de uma estação piloto. Os dois precisam retornar o mesmo código `LabGuard-...` da sessão ativa. Esse caminho não exige WinRM, pareamento nem aplicativo instalado no aluno.
5. Em **Sites**, adicione um domínio com **Bloquear domínio**. Para retirar um bloqueio manual, selecione a regra e clique **Remover**. Em **Banco de sites**, salvar ou excluir altera o cadastro; use **Aplicar ao gateway** para refletir a lista no filtro e confira o resultado.

**Mantenha o PC da TI e o LabGuard ligados enquanto as estações usarem esse DNS.** A opção **Ligar este filtro ao abrir o LabGuard** retoma o filtro ao abrir o aplicativo; não instala uma inicialização automática com o Windows. Antes de parar o filtro, restaure o DNS anterior nas estações ou no DHCP.

A filtragem cobre as consultas DNS que chegam ao LabGuard. Um bloqueio em domínio pai, no perfil de IA ou no resolvedor de saída pode continuar valendo após remover uma regra manual. O DNS não desinstala jogos; VPN, DNS seguro do navegador e resolvedores alternativos podem exigir políticas adicionais da escola. Não configure um DNS público alternativo que contorne o filtro.

### Se a edição Cliente já estiver instalada

Para voltar à administração somente pela rede, abra a **cópia baixada de LabGuardCliente.exe como administrador** na estação e use **Estação → Desinstalar cliente**. Exporte antes os cadastros locais que pretende conservar. A desinstalação remove a proteção gerenciada e restaura as alterações correspondentes; **Desvincular** apenas retoma a política local e não remove essa proteção. Não apague pastas manualmente. Jogos já desinstalados não são reinstalados por essa operação. Veja o [passo de migração](https://perabru.github.io/LabGuard/tecnico/#migrar).

## Vivo + switch Mercusys não gerenciável

O filtro usa o IP do PC da TI, não o IP do roteador. Não é necessário reposicionar o computador entre o Vivo e o switch nem configurar o switch simples. O ajuste necessário é fazer as estações consultarem o DNS do LabGuard. O software não configura automaticamente todos os modelos de modem Vivo.

O teste manual pelo CMD permite validar o caminho sem acesso remoto. **Administrar estações** e **Painel web → Estações** continuam como ferramentas opcionais para ambientes que já têm WinRM HTTPS, SSH, WMI, domínio ou MDM preparados. Um erro de WinRM não impede o filtro DNS de atender uma estação que usa seu endereço corretamente.

O painel reúne **Início, Dispositivos, Sites e Atividade**. A observação mostra a rota e os vizinhos disponíveis; o filtro ativo registra as consultas recebidas. Consulte o [guia do técnico](https://perabru.github.io/LabGuard/tecnico/), o [manual de rede 2.4](https://perabru.github.io/LabGuard/manual2/index.html) e a [documentação avançada de Vivo e Mercusys](docs/VIVO_MERCUSYS.md).

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
| Filtro DNS local | Regras de jogos, adultos e IA, diagnóstico de estações gerenciadas e consultas recebidas |
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

A [versão 2.4.3](https://github.com/perabru/LabGuard/releases/tag/v2.4.3) inclui diagnóstico de porta, certificado e autenticação da estação. Os 510 testes locais passaram, assim como a instalação no Windows, a atualização de 2.4.2 para 2.4.3 e os testes de serviço no Linux. [Resultados e limites de validação](docs/VALIDACAO.md).

## Edições alternativas preservadas

A edição **Cliente 1.2.0** e a **Central 1.0.0** continuam disponíveis para quem já usa proteção instalada em cada estação. Elas não fazem parte do fluxo sem cliente descrito acima.

- [Cliente: documentação e desinstalação](client/README.md) · [publicação 1.2.0](https://github.com/perabru/LabGuard/releases/tag/cliente-v1.2.0).
- [Central com clientes: manual e fonte](central/README.md) · [publicação 1.0.0](https://github.com/perabru/LabGuard/releases/tag/central-v1.0.0).

## Documentação e legado

[Manual 2.4 em Markdown](docs/MANUAL_DO_USUARIO_V2.md) · [Administração remota](docs/ADMINISTRACAO_REMOTA.md) · [Integrações](docs/INTEGRACOES.md) · [Validação](docs/VALIDACAO.md)

O [manual 1.4](docs/MANUAL_DO_USUARIO.md) e o [PDF 1.4](docs/Manual_LabGuard_1.4.pdf) foram preservados para o modo avançado legado. Duas interfaces e gateway Linux pertencem a esse modo; não são requisito do novo início em Observação.

## Testes

```bash
python3 -m unittest discover -s tests -v
```

Os testes automatizados não substituem homologação no equipamento do colégio. Comece por uma máquina de teste e confirme o resultado na estação antes de usar com a turma.
