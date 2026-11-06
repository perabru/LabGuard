# Diagnóstico local da rede

O modo **Observação local** consulta a configuração do computador que executa o LabGuard. Não exige um PC no caminho do tráfego: o roteador ou controlador já em uso continua responsável pelos bloqueios. O diagnóstico serve para localizar o gateway e preparar uma conexão administrativa compatível.

No Windows, usa uma consulta PowerShell fixa com `Get-NetIPConfiguration` e `Get-NetNeighbor`. No Linux, usa somente `ip -j -4 address show up`, `ip -j -4 route show default`, `ip -j -4 neigh show` e a leitura limitada de `/etc/resolv.conf`. Cada processo possui limite de tempo e saída. Nenhuma ferramenta é instalada automaticamente; sistemas ou comandos indisponíveis retornam um diagnóstico parcial com avisos.

São mostrados os endereços IPv4 privados das interfaces, seus prefixos, o gateway da rota padrão válida, servidores DNS configurados e vizinhos já presentes no cache local. Endereços públicos, interfaces inválidas, vizinhos fora das redes locais informadas, MACs inválidos, multicast e broadcast são descartados. Interfaces públicas, IPv6 e redes que não usam os intervalos privados RFC1918 não são inventariadas nesta versão.

**A tabela local não contém todas as máquinas do laboratório.** Uma entrada antiga (`STALE`) não confirma presença atual; sua atualização não faz ping, scan, resolução reversa de nome ou sondagem de portas. O campo `sampled_at` registra quando o cache foi consultado; `last_seen` fica vazio para vizinhos porque o sistema não informou uma data de presença confiável. O programa não observa o tráfego dos demais computadores nem mostra quais páginas estão abertas. A lista de servidores DNS representa configuração local, sem verificar funcionamento ou coletar histórico de consultas.

O próprio computador e um gateway presente na tabela são protegidos no painel. Todas as capacidades de alteração permanecem desativadas, e o transporte recusa qualquer operação além de `snapshot`. Não existem comandos de ARP poisoning, deautenticação, interceptação, proxy, mudança de DNS, rotas ou firewall neste diagnóstico.

Quando há vários gateways, o programa apresenta a rota válida com menor métrica informada e avisa sobre a ambiguidade. Confirme a interface do laboratório antes de conectar um equipamento. O endereço é uma sugestão para o assistente de conexão: **marca e modelo permanecem desconhecidos**. O MAC não é usado para afirmar que o equipamento é Vivo, TP-Link, Cisco ou outra marca. Confira a etiqueta ou o painel de administração, sem compartilhar senhas em capturas de tela.

Para aplicar regras, conecte explicitamente um roteador/controlador compatível e confirme as capacidades retornadas por ele. Roteadores de operadora podem ter modelos e firmwares distintos e acesso administrativo limitado; saber que o provedor é Vivo não identifica uma API compatível.

Referências primárias: [Microsoft Get-NetIPConfiguration](https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-netipconfiguration), [Microsoft Get-NetNeighbor](https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-netneighbor), [iproute2: ip](https://man7.org/linux/man-pages/man8/ip.8.html), [RFC1918](https://www.rfc-editor.org/rfc/rfc1918).
