# Comece aqui - LabGuard 2.4.2

O uso diário tem três ações: **Configurar**, **Gerenciar sites** e **Testar conexão**. A leitura local começa ao abrir. Regras novas só são aplicadas após sua escolha.

## 1. Configurar

1. Instale o pacote do seu sistema na [página de versões](https://github.com/perabru/LabGuard/releases). Abra o LabGuard.
2. Clique **Configurar**. Em **1. Ligar filtro**, escolha a conexão do laboratório. Se necessário, use **Ajustar IP / DNS**. O IP deve ser deste PC, não do roteador.
3. Marque a autorização e clique **Iniciar filtro DNS**. Se desejar, marque **Ligar este filtro ao abrir o LabGuard** antes de iniciar. A escolha é salva após o sucesso; com o filtro ativo, use **Salvar início automático** para mudá-la.
4. Reserve o IP do filtro e permita UDP/TCP 53 a partir da rede do laboratório. Em **2. Usar nos computadores**, confirme o IP exibido e clique em **Administrar estações** para testar um computador pelo PC da TI. O acesso requer WinRM HTTPS no Windows ou SSH no Linux, já preparados pela escola. Na ausência desse acesso, a TI pode distribuir a política de DNS pelo DHCP/LAN do roteador ou pela gestão de domínio, conforme os recursos disponíveis.

O switch Mercusys simples não precisa de configuração. O filtro atende apenas os computadores que usam esse DNS e conseguem alcançá-lo, por cabo ou Wi-Fi. No Linux, a porta 53 exige permissão apropriada; a TI pode usar o servidor como serviço, mantendo a interface gráfica sem root.

## 2. Gerenciar sites

Para aplicar a lista inicial de jogos e adultos, use **Proteger laboratório** e confira a seleção antes de confirmar. Ao ligar o filtro, a opção de Cloudflare Families usa o DNS de saída `1.1.1.3` para filtragem de conteúdo adulto e malware. Em domínio escolar, preserve um resolvedor adequado aos nomes internos. Para incluir entradas próprias, abra **Gerenciar sites**. Digite um domínio, como `roblox.com`, escolha a categoria e confirme o bloqueio. Para várias entradas, use **Banco de sites**: cadastre, importe, revise e aplique explicitamente. Para IA, **Preparar catálogo de IA** adiciona os cadastros ao banco; revise e aplique a lista. O filtro trata domínios e subdomínios, não IA instalada localmente.

## 3. Testar conexão

1. No PC da TI, abra **Configurar → 2. Usar nos computadores → Administrar estações**. O mesmo botão aparece em **3. Testar**. Selecione o endereço da estação autorizada e a conexão de gerenciamento preparada pela TI.
2. Clique em **Testar estação**. A estação faz duas consultas TXT. **Direto ao filtro** verifica se alcança o IPv4 do LabGuard. **DNS padrão da estação** verifica se a resolução usual retorna o código da sessão. Compare ambos com o código atual do painel.
3. Se o teste direto passar e o padrão falhar em um Windows gerenciado, clique em **Preparar alteração**. Confira o computador, o adaptador e os endereços DNS na prévia antes de confirmar **Aplicar DNS**. Repita **Testar estação**. Use **Restaurar DNS** para desfazer a alteração correspondente.

Para usar o navegador do PC da TI, abra **Painel web → Copiar chave e abrir**, cole a chave no login e abra **Estações → Testar DNS**. O painel também oferece **Preparar alteração**, **Aplicar DNS** e **Restaurar DNS** para a estação Windows. No Windows da TI, **Preparar nesta estação** usa o WMI/DCOM com Kerberos já autorizado no domínio. Informe o IPv4 e o FQDN do alvo e a conta de domínio. Outra opção é distribuir o script de **Preparar acesso remoto** por GPO ou MDM, conforme o capítulo 11 do manual. A estação precisa de certificado apropriado e canal de gestão institucional.

Se houver regras aplicadas, o teste também consulta um domínio bloqueado pelo DNS padrão da estação. Compare o domínio e o horário em **Atividade**. Se aparecer “domínio inexistente” para o nome de diagnóstico, confira qual dos dois testes falhou. Um DNS IPv6 indicado por `fe80::` pode ser o resolvedor escolhido pela estação. Se apenas o teste padrão falhar, revise a política de DNS do adaptador e da rede, mantendo IPv6 habilitado. Em **Atividade**, compare IP, nome consultado e horário com o teste daquela estação. O capítulo 16 detalha também tempo esgotado e código diferente.

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
