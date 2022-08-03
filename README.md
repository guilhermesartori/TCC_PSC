# Compilação

O sistema utiliza o Maven para gerenciamento de dependências, então é preciso
utilizar comandos do Maven para gerar o arquivo Jar do sistema. Em uma máquina com o
Maven instalado e utilizando o JDK 11, um comando 
```
mvn install -Dmaven.test.skip
```
a partir do diretório raiz do projeto é suficiente para produzir o Jar. Ele será criado no diretório
“target” que será criado a partir do diretório raiz do projeto.

# Configuração

É necessário um arquivo de configuração `settings.json` com o seguinte formato em `/etc/psc/`

```
{
  "databaseConfiguration": {
    "url": "jbdc:mysql://examplehost:9999/database",
    "username": "example",
    "password": "example"
  }
}
```

# Execução

O sistema é executado com o próprio Spring Boot. Para executá-lo, pode-se
primeiramente exportar quaisquer variáveis de ambiente desejadas para alterar as
configurações do servidor, como, por exemplo, as configurações de HTTPS descritas na seção
4.4.2 ou a porta do servidor. Essas informações de configuração estão disponíveis na Spring
Framework Documentation. 

```
java -jar <caminho para o Jar>
```

# Testes

```
mvn test
```
