# LabGuard TI 2.4.5 — filtro original com recursos adicionais

Esta edição abre o **filtro de rede original**. A nova aba **Clientes e avisos** acrescenta acesso à Central 1.2 sem substituir o DNS, seus bancos ou os controles existentes. O Cliente Automático 2.4 nas estações não precisa ser reinstalado por causa desta atualização da TI.

## Baixar o arquivo correto

**LabGuard-TI-Setup.exe**: instalar/atualizar no PC da TI que já executava o filtro de rede. Instala a interface completa e inclui o instalador da Central 1.2 como componente adicional. Não é o cliente do aluno.

**LabGuard-TI-Portable.zip**: a mesma interface completa em pasta. Extraia tudo e abra LabGuard.exe; não mova apenas esse EXE para fora da pasta. Não cria a instalação tradicional. Para atualizar a instalação existente, prefira o Setup.

**LabGuardTecnico.exe**, incluído como componente: abre o instalador/painel da Central de clientes. Ele, sozinho, não é o filtro DNS. Pode ser aberto pela nova aba. O filtro permanece na janela principal LabGuard.

**LabGuard-Jogos.exe (Automático 2.4)**: continua sendo o cliente de cada estação. Seus bloqueios locais, fechamento de jogos, limpeza, inicialização e comunicação existente não foram substituídos por esta edição da TI.

## Atualizar sem apagar a configuração

1. Use a **mesma conta Windows da TI que configurou o filtro anterior**. O filtro guarda suas configurações por usuário. Não execute o desinstalador e não apague a pasta `.labguard`.
2. Faça uma cópia de segurança de `%USERPROFILE%\.labguard`. Atualize em uma janela de manutenção: fechar o filtro interrompe o DNS que ele serve até o programa ser reaberto.
3. Feche a janela antiga do filtro e abra **LabGuard-TI-Setup.exe**. O instalador usa a mesma identificação e pasta da edição de rede anterior; preserva o banco e as preferências externos à instalação.
4. Abra o atalho **LabGuard**. Se o filtro estava salvo com **iniciar ao abrir**, ele retoma essa opção. Confira **Filtro ligado neste PC** e o IP do DNS. Não há ativação de uma rede/IP inventado em uma primeira instalação.
5. Teste em uma estação que usa o DNS deste PC: um domínio bloqueado e um site permitido da aula. Não desative o antivírus nem o firewall globalmente.

## O que permanece

A interface original continua oferecendo Início/Proteger laboratório, Dispositivos, Sites, Atividade DNS, filtros por categoria, perfil de IA, banco de sites, mapa e relatórios, diagnóstico, administração de estações, integrações, opções avançadas, atualização e restauração da conexão salva. A interface legada permanece acessível pelo argumento `--legacy-ui`.

Os controles continuam respeitando as capacidades da conexão: por exemplo, a simples observação da rede não passa a permitir bloquear IP/MAC em um switch não gerenciável. A operação DNS exige que as estações usem o filtro; não é inspeção universal de todo tráfego.

## O que foi acrescentado

Na aba **Clientes e avisos**:

- **Abrir filtro original** e **Sites e bloqueios DNS**: retornam às funções já existentes.
- **Bloquear lista rápida no DNS**: acrescenta Termo, Friv, Poki, Chess.com e domínios do YouTube ao filtro atual. Mantém regras anteriores e usa a confirmação/persistência originais. Não corta toda a internet. Joguester exige o endereço correto.
- **Abrir Central existente**: abre o painel local; padrão `http://127.0.0.1:8787/`. Se já usa Central 1.2, não precisa recriar senha ou vínculos.
- **Instalar / reparar Central**: abre o componente administrativo incluído, com a autorização normal do Windows. Só configure uma primeira Central quando ainda não houver uma.
- **Conferir conexão**: consulta apenas a disponibilidade da Central local. Falha na Central não redefine nem desliga o filtro DNS.

A Central continua com Sites rápidos/Bloquear tudo, jogos, YouTube, estações vinculadas e avisos. A nova aba é um ponto de acesso: não mescla silenciosamente os bancos e não replica uma alteração entre as duas camadas. **Para liberar um site bloqueado nas duas, libere-o no DNS e na Central.** A política local do cliente também pode continuar em vigor enquanto não sincronizar.

## Conferência diária

Mantenha o PC responsável pelo DNS ligado, o filtro iniciado e a configuração DNS das estações correta. Abra a Central para acompanhar a última comunicação, as revisões aplicadas e os avisos; para notificações do navegador, mantenha a sessão autenticada e autorize as notificações.

**Só aparece a Central, sem filtro?** Abra o atalho LabGuard instalado pelo novo Setup, não apenas LabGuardTecnico.exe.

**Configuração anterior não apareceu?** Confira primeiro a conta Windows; não importe nem apague bancos por tentativa. A pasta original é `%USERPROFILE%\.labguard`.

**Central sem contato, mas filtro ligado?** São serviços independentes. Confira a porta local do painel e, para as estações, o IP/rede e HTTPS 8788. O filtro mantém seu estado.

## Verificação e limites

O processo de publicação compara o código original do filtro com a revisão anterior, executa os testes de regressão e exige testes reais em Windows descartável: atualização sobre a 2.4.4, preservação dos arquivos de preferências/banco, DNS UDP/TCP e execução simultânea com a Central. Também verifica que parar a Central não interrompe o DNS. Os dados usados são fictícios; nenhuma máquina real da escola é alterada.

Consulte `PRESERVACAO_E_TESTES.json`. Esses testes não são uma garantia absoluta em qualquer rede ou versão do Windows. Faça a conferência em uma estação real antes de distribuir ao laboratório inteiro.
