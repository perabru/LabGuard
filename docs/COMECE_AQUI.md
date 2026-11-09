# Comece aqui - LabGuard 2.4.0

O uso diário tem três ações: **Configurar**, **Gerenciar sites** e **Testar conexão**. A leitura local começa ao abrir. Regras novas só são aplicadas após sua escolha.

## 1. Configurar

1. Instale o pacote do seu sistema na [página de versões](https://github.com/perabru/LabGuard/releases). Abra o LabGuard.
2. Clique **Configurar**. Em **1. Ligar filtro**, escolha a conexão do laboratório. Se necessário, use **Ajustar IP / DNS**. O IP deve ser deste PC, não do roteador.
3. Marque a autorização e clique **Iniciar filtro DNS**. Se desejar, marque **Ligar este filtro ao abrir o LabGuard** antes de iniciar. A escolha é salva após o sucesso; com o filtro ativo, use **Salvar início automático** para mudá-la.
4. Em **2. Usar nos computadores**, copie o IP. Configure-o como DNS no DHCP/LAN do Vivo, se o modelo permitir, ou nas estações. Comece em uma estação e guarde o DNS anterior. Reserve o IP do PC e autorize UDP/TCP 53 no firewall somente para a rede necessária, com a TI.

O switch Mercusys simples não precisa de configuração. O filtro atende apenas os computadores que usam esse DNS e conseguem alcançá-lo, por cabo ou Wi-Fi. No Linux, a porta 53 exige permissão apropriada; a TI pode usar o servidor como serviço, mantendo a interface gráfica sem root.

## 2. Gerenciar sites

Abra **Gerenciar sites**. Digite um domínio, como `roblox.com`, escolha a categoria e confirme o bloqueio. Para várias entradas, use **Banco de sites**: cadastre, importe, revise e aplique explicitamente. Para IA, **Preparar catálogo de IA** adiciona os cadastros ao banco; revise e aplique a lista. O filtro trata domínios e subdomínios, não IA instalada localmente.

## 3. Testar conexão

1. Abra **Testar conexão → 3. Testar** e clique **Verificar neste PC**. O teste confere UDP e TCP do filtro local.
2. Em OUTRO computador, execute `nslookup -type=TXT labguard-check.invalid` e compare com o código exibido. O teste local não verifica as estações.
3. Teste também um domínio permitido e um bloqueado. Abra **Atividade** para conferir as consultas recebidas. Consultas não comprovam visitas.

**Antes de parar:** mantenha o PC e o programa ligados enquanto forem usados como DNS. Restaure o DNS anterior nas estações ou no DHCP antes de encerrar o filtro. VPN, DoH e DNS IPv6 alternativo exigem política complementar da TI.

## Mais recursos

| Objetivo | Caminho |
|---|---|
| Ver endereços disponíveis | Dispositivos |
| Desenhar a amostra e exportar relatórios | Mapa e relatórios |
| Configurar roteador/API ou integrações | Início → Opções avançadas → Acesso ao equipamento |
| Conferir capacidades e atualizações | Início → Opções avançadas → Detalhes e recursos |
| Aprender com dados fictícios | Início → Opções avançadas → Abrir demonstração |
| Diagnosticar uma falha | Não identificou? Ver passo a passo |

Internet por IP/MAC, portas de switches e administração de programas continuam disponíveis apenas quando a integração correspondente fornece o recurso. O filtro DNS local não oferece essas ações. Inventário local pode ser parcial; o programa não descobre todos os equipamentos apenas por estar na rede.

No Windows instalado por usuário, atualizações oficiais são preparadas em segundo plano e aplicadas ao fechar voluntariamente. Linux, portátil e servidores ficam sob atualização da TI. A primeira migração da 2.1 ou anterior exige instalação manual do pacote atual.

Leia o [manual completo](MANUAL_DO_USUARIO_V2.html), o [PDF](Manual_LabGuard_2.pdf), o [guia Vivo + Mercusys](VIVO_MERCUSYS.md) ou o [diagnóstico da rede](DIAGNOSTICO_DA_REDE.md).
