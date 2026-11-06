# Comece aqui - LabGuard 2.0.1

O LabGuard 2.0.1 abre em **Observação**, usando a rede existente. Não precisa trocar o roteador, mudar cabos, instalar um novo gateway nem informar senha para começar a consultar o computador e os vizinhos conhecidos da rede.

## Primeiro uso

1. Baixe a versão 2.0.1 do seu sistema na [página de versões](https://github.com/perabru/LabGuard/releases). Os pacotes ficam disponíveis depois da publicação; confira o número do arquivo.
2. Abra o programa. Pelo código-fonte, execute `python3 main.py` com Python 3.10 ou superior e Tcl/Tk instalado.
3. Em **Início**, mantenha **Observar esta rede**. Em **Dispositivos**, confira seu computador, o roteador padrão e os vizinhos conhecidos pelo sistema.
4. Use **Sites → Banco de sites** para organizar os domínios. O cadastro pode ser feito sem controlar o roteador.
5. Para aplicar bloqueios, conecte um controlador compatível. A opção direta é **Controlar MikroTik via HTTPS**, com RouterOS 7 e os requisitos do [manual 2.0](MANUAL_DO_USUARIO_V2.md). Identificar um modem Vivo não habilita controle universal de sites.

| Objetivo | Caminho |
|---|---|
| Conhecer a rede sem alterar configuração | Início → Observar esta rede |
| Aprender com dados fictícios | Início → Abrir demonstração |
| Organizar jogos, IA e outros sites | Sites → Banco de sites |
| Bloquear IP ou aplicar domínios | Controlador compatível, permissões e verificações aprovadas |
| Consultar programas e enviar avisos | Dispositivos → Programas e avisos; WinRM HTTPS ou SSH já preparado |
| Exportar a amostra observada | Mapa e relatórios |

No modo Observação, os botões de alteração ficam indisponíveis. Esse é o comportamento esperado. O cadastro de sites também não comprova que as regras foram aplicadas.

No MikroTik direto, use **Bloquear IP / Desbloquear IP**. Retirar a regra de IP não remove um bloqueio independente por MAC. A conexão exige IP literal e certificado com esse IP em SAN de tipo IP.

A lista inicial acompanha a primeira conexão MikroTik compatível, enquanto não estiver vinculada a outro destino. Desconectar ou reiniciar mantém o último banco real; outro destino e a demonstração usam bancos separados. Para IA no MikroTik, adicione o catálogo ao banco e aplique a seleção quando o filtro de domínios estiver disponível.

Leia o [manual em HTML](MANUAL_DO_USUARIO_V2.html) ou [PDF](Manual_LabGuard_2.pdf). A documentação 1.4 permanece como referência do modo avançado com gateway Linux existente.

## Não identificou a rede?

1. Em **Início**, clique **Não identificou? Ver passo a passo**.
2. Siga o assistente **Ajuda para identificar a rede** com **Voltar / Avançar** e escolha o caso apresentado: IP/gateway, poucos dispositivos/MAC, modelo, HTTPS, autenticação, API ou tempo esgotado.
3. Confira os dados locais com os comandos de consulta do [guia de diagnóstico](DIAGNOSTICO_DA_REDE.md). No Windows: `ipconfig /all`, `route print -4`, `arp -a`. No Linux: `ip -4 addr`, `ip -4 route`, `ip -4 neigh`.
4. Em Observação ou MikroTik direto, use **Atualizar consulta** depois da conferência. A ajuda não modifica roteador, firewall, DNS nem rotas. No gateway SSH legado, o botão fica desabilitado porque a consulta avançada pode reconciliar políticas existentes; siga o fluxo avançado ou escolha Observação em Início.

A tabela de vizinhos é parcial e pode estar vazia ou antiga. MAC vazio do próprio computador não é necessariamente erro. IP fixo pode não aparecer no DHCP. Confira modelo na etiqueta ou no painel autorizado; o programa não o deduz pelo MAC. Um modem Vivo desconhecido continua podendo ser usado em Observação, sem selecionar MikroTik por tentativa.

No Linux portátil ou pelo código-fonte, a consulta depende de `iproute2`; se faltar, peça à TI a instalação pela distribuição. Não desative certificado/TLS ou firewall para identificar a rede. Nunca inclua senhas em um relatório de suporte.
