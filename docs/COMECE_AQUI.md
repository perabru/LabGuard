# Comece aqui - LabGuard 2.1.0

O LabGuard 2.1.0 abre em **Observação**, usando a rede existente. Não precisa trocar o roteador, mudar cabos, instalar um novo gateway nem informar senha para começar a consultar o computador e os vizinhos conhecidos da rede.

## Primeiro uso

1. Baixe a versão 2.1.0 do seu sistema na [página de versões](https://github.com/perabru/LabGuard/releases). Os pacotes ficam disponíveis depois da publicação; confira o número do arquivo.
2. Abra o programa. Pelo código-fonte, execute `python3 main.py` com Python 3.10 ou superior e Tcl/Tk instalado.
3. Em **Início**, mantenha **Observação** e use **Identificar minha rede**. Abra **Dispositivos** para conferir os endereços locais, o roteador padrão e os vizinhos conhecidos pelo sistema.
4. Use **Sites → Banco de sites** para organizar os domínios. O cadastro pode ser feito sem controlar o roteador.
5. Para aplicar bloqueios, conecte um controlador compatível. A opção direta é **Controlar MikroTik via HTTPS**, com RouterOS 7 e os requisitos do [manual](MANUAL_DO_USUARIO_V2.md). Identificar um modem Vivo não habilita controle universal de sites.

| Objetivo | Caminho |
|---|---|
| Conhecer a rede sem alterar configuração | Início → Identificar minha rede, em Observação |
| Aprender com dados fictícios | Início → Abrir demonstração |
| Organizar jogos, IA e outros sites | Sites → Banco de sites |
| Bloquear IP ou aplicar domínios | Controlador compatível, permissões e verificações aprovadas |
| Consultar programas e enviar avisos | Dispositivos → Programas e avisos; WinRM HTTPS ou SSH já preparado |
| Exportar a amostra observada | Mapa e relatórios |

No modo Observação, os botões de alteração ficam indisponíveis. Esse é o comportamento esperado. A leitura é parcial: os endereços encontrados não representam o total físico de computadores, e cadastrar sites não comprova aplicação de regras.

Leia o cartão **O que foi identificado**: ele mostra a fonte, o estado da leitura, as contagens e o **Próximo passo**. Uma coleta indisponível não significa que a rede esteja vazia; dados desatualizados precisam de nova consulta. O horário é da coleta e não confirma presença das estações. **Demonstração** usa dados fictícios separados da rede real.

No MikroTik direto, use **Bloquear IP / Desbloquear IP**. Retirar a regra de IP não remove um bloqueio independente por MAC. A conexão exige IP literal e certificado com esse IP em SAN de tipo IP.

Para configurar uma conexão administrativa, abra **Acesso ao equipamento**. Consulte requisitos e capacidades em **Detalhes e recursos**. Esses painéis começam recolhidos para deixar a identificação local à vista.

A lista inicial acompanha a primeira conexão MikroTik compatível, enquanto não estiver vinculada a outro destino. Desconectar ou reiniciar mantém o último banco real; outro destino e a demonstração usam bancos separados. Para IA no MikroTik, adicione o catálogo ao banco e aplique a seleção quando o filtro de domínios estiver disponível.

Leia o [manual em HTML](MANUAL_DO_USUARIO_V2.html) ou [PDF](Manual_LabGuard_2.pdf). A documentação 1.4 permanece como referência do modo avançado com gateway Linux existente.

## Não identificou a rede?

1. Em **Início**, clique **Não identificou? Ver passo a passo**.
2. Siga o assistente **Ajuda para identificar a rede** com **Voltar / Avançar** e escolha o caso apresentado: IP/gateway, poucos dispositivos/MAC, modelo, HTTPS, autenticação, API ou tempo esgotado.
3. Confira os dados locais com os comandos de consulta do [guia de diagnóstico](DIAGNOSTICO_DA_REDE.md). No Windows: `ipconfig /all`, `route print -4`, `arp -a`. No Linux: `ip -4 addr`, `ip -4 route`, `ip -4 neigh`.
4. Em Observação ou MikroTik direto, use **Atualizar consulta** depois da conferência. A ajuda não modifica roteador, firewall, DNS nem rotas. No gateway SSH legado, o botão fica desabilitado porque a consulta avançada pode reconciliar políticas existentes; siga o fluxo avançado ou escolha Observação em Início.

A tabela de vizinhos é parcial e pode estar vazia ou antiga. O MAC do próprio computador pode ficar vazio quando a fonte não o fornece; isso não é falha de identificação. Um IP fixo pode não aparecer no DHCP. Ausência de MAC, ARP ou concessão não comprova que a estação esteja desligada; um registro também não garante presença atual. Confira modelo na etiqueta ou no painel autorizado; o programa não o deduz pelo MAC. Um modem Vivo desconhecido continua podendo ser usado em Observação, sem selecionar MikroTik por tentativa.

No Linux, `iproute2` é a fonte preferencial. Se ela falhar ou faltar, o programa tenta fontes locais alternativas, que podem fornecer menos dados, sem elevar privilégios ou instalar ferramentas. Para os comandos manuais, peça à TI a instalação de `iproute2` pela distribuição quando necessário. Não desative certificado/TLS ou firewall. Nunca inclua senhas em um relatório de suporte.
